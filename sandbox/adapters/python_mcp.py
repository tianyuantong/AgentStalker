"""
MCP Python Server Adapter — 适配 MCP Server
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

    def deploy(self) -> bool:
        """启动 MCP Server

        策略：
        - 启动 MCP Server as subprocess
        - 通过 stdio 或 SSE 与 test-runner 通信
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
            log_path = Path(self.source_dir.parent) / "output" / "evidence" / "mcp_io.log"
            log_path.parent.mkdir(parents=True, exist_ok=True)
            self.process = subprocess.Popen(
                ["python", str(entry)],
                cwd=entry.parent,
                env=env,
                stdin=subprocess.PIPE,
                stdout=open(log_path, "w"),
                stderr=subprocess.STDOUT,
            )
            time.sleep(2)
            # MCP stdio 握手
            return self._handshake()
        except Exception as e:
            print(f"[!] MCP deploy error: {e}")
            return False

    def list_tools(self) -> list[Tool]:
        """通过 MCP list_tools RPC 获取工具列表"""
        try:
            request = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/list",
                "params": {}
            }
            self.process.stdin.write((json.dumps(request) + "\n").encode())
            self.process.stdin.flush()
            time.sleep(1)

            # 读取响应（简化：日志文件中 grep）
            log_path = Path(self.source_dir.parent) / "output" / "evidence" / "mcp_io.log"
            if log_path.exists():
                content = log_path.read_text()
                # 简单解析：找 tools 数组
                import re
                m = re.search(r'"tools"\s*:\s*\[(.*?)\]', content, re.DOTALL)
                if m:
                    tools_text = "[" + m.group(1) + "]"
                    raw_tools = json.loads(tools_text)
                    for t in raw_tools:
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
        """通过 MCP tools/call RPC 调用工具"""
        start = time.time()
        try:
            request = {
                "jsonrpc": "2.0",
                "id": int(time.time()),
                "method": "tools/call",
                "params": {
                    "name": tool_name,
                    "arguments": parameters,
                }
            }
            self.process.stdin.write((json.dumps(request) + "\n").encode())
            self.process.stdin.flush()
            time.sleep(0.5)
            duration = int((time.time() - start) * 1000)
            result = InvokeResult(
                success=True,
                output={"mcp_request": request},
                duration_ms=duration,
            )
            self._record_invocation(tool_name, parameters, result)
            return result
        except Exception as e:
            return InvokeResult(success=False, error=str(e), duration_ms=int((time.time() - start) * 1000))

    def teardown(self) -> bool:
        if hasattr(self, "process") and self.process:
            try:
                self.process.terminate()
                self.process.wait(timeout=5)
                return True
            except Exception:
                self.process.kill()
        return True

    # ============ 内部 ============
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
        """MCP 握手"""
        try:
            request = {
                "jsonrpc": "2.0",
                "id": 0,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "AgentStalker", "version": "1.0"},
                }
            }
            self.process.stdin.write((json.dumps(request) + "\n").encode())
            self.process.stdin.flush()
            time.sleep(1)
            return self.process.poll() is None
        except Exception:
            return False