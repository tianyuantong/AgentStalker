"""MCP Executor — MCP stdio RPC 执行器

通过 JSON-RPC 与 MCP Server 通信,用于:
- 驱动被测 MCP server(Commit 9 的运行时验证)
- 向 MCP server 的工具注入 payload(replay)

Commit 4 增强内容(为 MCP 运行时验证铺路):
- _send() 支持 Content-Length 帧(旧版只读一行,server 发 notification 会错乱)
- list_tools() 返回完整工具表(name + description),而非仅 name 字符串
- execute() / call_tool() 捕获并返回 server 的真实响应(旧版 execute 丢弃响应详情)
"""
from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path

from .api_executor import ExecutionResult


class MCPExecutor:
    """MCP stdio RPC 执行器

    通过 JSON-RPC 与 MCP Server 通信
    """

    def __init__(self, mcp_command: str = "python -m my_mcp_server", cwd: str | Path = "."):
        # 允许 caller 传 list 或 str;str 按 space split(保持向后兼容)
        if isinstance(mcp_command, str):
            self.mcp_command = mcp_command.split()
        else:
            self.mcp_command = list(mcp_command)
        self.cwd = Path(cwd)
        self.process: subprocess.Popen | None = None
        self._next_id = 100

    def _ensure_process(self):
        if not self.process:
            self.process = subprocess.Popen(
                self.mcp_command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=self.cwd,
                text=True,
                bufsize=1,
            )
            # initialize handshake
            self._send({
                "jsonrpc": "2.0", "id": 0, "method": "initialize",
                "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                           "clientInfo": {"name": "AgentStalker", "version": "1.0"}}
            })
            # initialized notification (no id, no response expected)
            self._notify({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})

    def _next_request_id(self) -> int:
        self._next_id += 1
        return self._next_id

    def _notify(self, request: dict):
        """发 notification(无 id,无响应)。"""
        if not self.process:
            return
        try:
            self.process.stdin.write(json.dumps(request) + "\n")
            self.process.stdin.flush()
        except Exception:
            pass

    def _send(self, request: dict) -> dict:
        """发请求并读响应。

        增强(Commit 4):跳过 server 发出的 notification/log 行(它们没有 'id'
        或 'method' 字段),只返回与请求 'id' 匹配的响应。这修复旧版"只读一行"
        在 server 发 notification 时错乱的问题。
        """
        if not self.process:
            return {}
        self.process.stdin.write(json.dumps(request) + "\n")
        self.process.stdin.flush()

        expected_id = request.get("id")
        # 最多读 50 行,跳过 notification/log,直到拿到匹配 id 的响应
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
                # server 可能在 stdout 打印非 JSON 日志,跳过
                continue
            # notification 没有 'id';只有带 id 的才是响应
            if "id" in msg and (expected_id is None or msg["id"] == expected_id):
                return msg
            # 否则是 notification/log,继续读下一行
        return {}

    def execute(self, test_case: dict) -> ExecutionResult:
        """执行 tools/call(向后兼容旧接口)。返回的 ExecutionResult.output 含完整 server 响应。"""
        start = time.time()
        try:
            self._ensure_process()
            payload = test_case.get("payload", {})
            tool_name = test_case.get("tool", "test_tool")

            response = self.call_tool(tool_name, payload)
            duration = int((time.time() - start) * 1000)
            return ExecutionResult(
                success="result" in response,
                output=response,  # 完整响应(含 result + error),供审计用
                error=response.get("error", {}).get("message", ""),
                duration_ms=duration,
            )
        except Exception as e:
            return ExecutionResult(success=False, error=str(e), duration_ms=int((time.time() - start) * 1000))

    def call_tool(self, name: str, arguments: dict | None = None) -> dict:
        """调用 MCP 工具,返回 server 的完整 JSON-RPC 响应。

        增强(Commit 4):相比旧 execute(),本方法返回原始响应 dict(含 result.content /
        isError 等),供 MCPMonitor 审计响应内容(检测响应注入)。
        """
        self._ensure_process()
        return self._send({
            "jsonrpc": "2.0", "id": self._next_request_id(),
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments or {}},
        })

    def list_tools(self) -> list[dict]:
        """列出 MCP 工具(完整表)。

        增强(Commit 4):返回 list[dict](含 name + description + inputSchema),
        供 MCPMonitor 做工具名冲突检测和描述投毒检测。旧版只返回 list[str]。
        想要旧行为可用 [t["name"] for t in exec.list_tools()]。
        """
        self._ensure_process()
        response = self._send({
            "jsonrpc": "2.0", "id": self._next_request_id(),
            "method": "tools/list", "params": {},
        })
        return response.get("result", {}).get("tools", [])

    def list_tool_names(self) -> list[str]:
        """便捷方法:仅返回工具名(旧行为)。"""
        return [t.get("name") for t in self.list_tools()]

    def teardown(self):
        if self.process:
            try:
                self.process.terminate()
                self.process.wait(timeout=5)
            except Exception:
                self.process.kill()
            finally:
                self.process = None
