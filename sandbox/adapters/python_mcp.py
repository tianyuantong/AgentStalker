"""
MCP Python Server Adapter — 适配 MCP Server

Commit 5 修复(为 MCP 审计地基铺路):
- list_tools(): 改用 JSON-RPC 帧从 stdout 读响应(原版 grep 日志文件,极脆弱)
- invoke_tool(): 捕获并返回 server 的真实响应(原版只记请求不记响应,
  无法审计 server 返回了什么 —— 这是 MCP 安全审计的关键盲区)
- _send_rpc(): 新增,跳过 notification 行,只返回匹配 id 的响应
"""
from __future__ import annotations

import json
import os
import subprocess
import time
from pathlib import Path

from . import BaseAdapter, Tool, InvokeResult


class MCPPythonAdapter(BaseAdapter):
    framework_name = "MCP Server (Python)"

    def __init__(self, source_dir, sandbox_endpoint: str = "", agent_profile: dict | None = None):
        super().__init__(source_dir, sandbox_endpoint, agent_profile)
        self._next_rpc_id = 100

    def deploy(self) -> bool:
        """启动 MCP Server

        策略：
        - 启动 MCP Server as subprocess(stdin=PIPE, stdout=PIPE 用于 RPC)
        - 通过 stdio 与 test-runner 通信
        - 拦截所有 tool 响应并记录
        """
        entry = self._find_entry()
        if not entry:
            print("[!] MCP entry not found")
            return False

        env = os.environ.copy()
        env["MCP_LOG_LEVEL"] = "DEBUG"
        env["AGENTSTALKER_MODE"] = "audit"

        try:
            # stdout 必须 PIPE(RPC 响应从此读);日志写到 stderr 的文件重定向
            log_path = Path(self.source_dir.parent) / "output" / "evidence" / "mcp_io.log"
            log_path.parent.mkdir(parents=True, exist_ok=True)
            self.process = subprocess.Popen(
                ["python", str(entry)],
                cwd=entry.parent,
                env=env,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,  # RPC 响应(原版是 open(log_path),导致响应无法读)
                stderr=open(log_path, "w"),
                text=True,
                bufsize=1,
            )
            time.sleep(1)
            # MCP stdio 握手
            return self._handshake()
        except Exception as e:
            print(f"[!] MCP deploy error: {e}")
            return False

    def list_tools(self) -> list[Tool]:
        """通过 MCP tools/list RPC 获取工具列表(完整表,含 description)。

        Commit 5 修复:原版 grep 日志文件找 tools 数组(极脆弱,且依赖日志格式)。
        现版用 JSON-RPC 帧从 stdout 读真实响应。
        """
        try:
            response = self._send_rpc("tools/list", {})
            tools_list = response.get("result", {}).get("tools", [])
            for t in tools_list:
                self.tools.append(Tool(
                    name=t.get("name", "unknown"),
                    description=t.get("description", ""),
                    parameters=t.get("inputSchema", {}),
                    risk_level="medium",
                ))
        except Exception as e:
            print(f"[!] MCP list_tools error: {e}")
        return self.tools

    def invoke_tool(self, tool_name: str, parameters: dict, user_context: dict | None = None) -> InvokeResult:
        """通过 MCP tools/call RPC 调用工具,返回 server 的真实响应。

        Commit 5 修复:原版 output 只含 {"mcp_request": request}(请求),
        完全丢弃了 server 返回的响应 —— 无法审计响应内容(响应注入检测盲区)。
        现版 output 含完整 server 响应(供 MCPMonitor 检测响应注入)。
        """
        start = time.time()
        try:
            response = self._send_rpc("tools/call", {
                "name": tool_name,
                "arguments": parameters,
            })
            duration = int((time.time() - start) * 1000)
            result = InvokeResult(
                success="result" in response,
                output={  # 完整请求 + 响应(供审计)
                    "mcp_request": {"method": "tools/call", "params": {"name": tool_name, "arguments": parameters}},
                    "mcp_response": response,
                },
                error=response.get("error", {}).get("message", ""),
                duration_ms=duration,
            )
            self._record_invocation(tool_name, parameters, result)
            return result
        except Exception as e:
            return InvokeResult(success=False, error=str(e), duration_ms=int((time.time() - start) * 1000))

    def teardown(self) -> bool:
        if getattr(self, "process", None):
            try:
                self.process.terminate()
                self.process.wait(timeout=5)
                return True
            except Exception:
                self.process.kill()
        return True

    # ============ 内部 ============
    def _send_rpc(self, method: str, params: dict) -> dict:
        """发 JSON-RPC 请求并读响应。

        跳过 server 发出的 notification/log 行(无 'id'),只返回与请求 id 匹配的响应。
        这与 sandbox/executors/mcp.py 的 MCPExecutor._send 同样的健壮性。
        """
        if not self.process or not self.process.stdin:
            return {}
        self._next_rpc_id += 1
        req_id = self._next_rpc_id
        request = {"jsonrpc": "2.0", "id": req_id, "method": method, "params": params}
        self.process.stdin.write(json.dumps(request) + "\n")
        self.process.stdin.flush()

        # 最多读 50 行,跳过 notification,直到拿到匹配 id 的响应
        for _ in range(50):
            line = self.process.stdout.readline()
            if not line:
                return {}
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue  # server 在 stdout 打印非 JSON 日志,跳过
            if "id" in msg and msg["id"] == req_id:
                return msg
            # 否则是 notification/log,继续读
        return {}

    def _find_entry(self) -> Path | None:
        """查找 MCP Server 入口"""
        for name in ["server.py", "mcp_server.py", "app.py", "main.py"]:
            for p in self.source_dir.rglob(name):
                if "__pycache__" in str(p) or "test" in str(p):
                    continue
                # 验证是 MCP Server
                try:
                    content = p.read_text(encoding="utf-8", errors="ignore")
                    if "FastMCP" in content or "@server.list_tools" in content or "@app.list_tools" in content:
                        return p
                except Exception:
                    continue
        return None

    def _handshake(self) -> bool:
        """MCP initialize 握手"""
        try:
            response = self._send_rpc("initialize", {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "AgentStalker", "version": "1.0"},
            })
            if not response:
                return False
            # 发 initialized notification(无 id,无响应)
            if self.process and self.process.stdin:
                notif = {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}
                self.process.stdin.write(json.dumps(notif) + "\n")
                self.process.stdin.flush()
            return self.process.poll() is None
        except Exception:
            return False
