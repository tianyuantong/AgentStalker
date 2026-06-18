"""
CLI / MCP / Web Executors — 多渠道攻击执行
"""
from __future__ import annotations

import json
import subprocess
import time
import traceback
from pathlib import Path

from .api_executor import ExecutionResult


# ============ CLI Executor ============
class CLIExecutor:
    """命令行 Agent 执行器

    通过 stdin / argv 注入 payload
    """

    def __init__(self, command: str, cwd: str | Path = "."):
        self.command = command
        self.cwd = Path(cwd)

    def execute(self, test_case: dict) -> ExecutionResult:
        start = time.time()
        payload = test_case.get("payload", {})

        # 把 payload 转为 stdin 输入
        stdin_data = json.dumps(payload)

        try:
            result = subprocess.run(
                self.command.split(),
                input=stdin_data,
                capture_output=True,
                text=True,
                timeout=test_case.get("timeout", 30),
                cwd=self.cwd,
            )
            duration = int((time.time() - start) * 1000)
            return ExecutionResult(
                success=result.returncode == 0,
                output={"stdout": result.stdout, "stderr": result.stderr, "returncode": result.returncode},
                error=result.stderr if result.returncode != 0 else "",
                duration_ms=duration,
            )
        except Exception as e:
            return ExecutionResult(
                success=False,
                error=f"{e}\n{traceback.format_exc()}",
                duration_ms=int((time.time() - start) * 1000),
            )


# ============ MCP Executor ============
class MCPExecutor:
    """MCP stdio RPC 执行器

    通过 JSON-RPC 与 MCP Server 通信
    """

    def __init__(self, mcp_command: str = "python -m my_mcp_server", cwd: str | Path = "."):
        self.mcp_command = mcp_command
        self.cwd = Path(cwd)
        self.process: subprocess.Popen | None = None

    def _ensure_process(self):
        if not self.process:
            self.process = subprocess.Popen(
                self.mcp_command.split(),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=self.cwd,
                text=True,
            )
            # initialize handshake
            self._send({
                "jsonrpc": "2.0", "id": 0, "method": "initialize",
                "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                           "clientInfo": {"name": "AgentStalker", "version": "1.0"}}
            })

    def _send(self, request: dict) -> dict:
        self.process.stdin.write(json.dumps(request) + "\n")
        self.process.stdin.flush()
        line = self.process.stdout.readline()
        return json.loads(line) if line else {}

    def execute(self, test_case: dict) -> ExecutionResult:
        start = time.time()
        try:
            self._ensure_process()
            payload = test_case.get("payload", {})
            tool_name = test_case.get("tool", "test_tool")

            response = self._send({
                "jsonrpc": "2.0", "id": int(time.time()),
                "method": "tools/call",
                "params": {"name": tool_name, "arguments": payload},
            })

            duration = int((time.time() - start) * 1000)
            return ExecutionResult(
                success="result" in response,
                output=response,
                error=response.get("error", {}).get("message", ""),
                duration_ms=duration,
            )
        except Exception as e:
            return ExecutionResult(success=False, error=str(e), duration_ms=int((time.time() - start) * 1000))

    def list_tools(self) -> list[str]:
        """列出 MCP 工具"""
        self._ensure_process()
        response = self._send({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
        return [t.get("name") for t in response.get("result", {}).get("tools", [])]

    def teardown(self):
        if self.process:
            try:
                self.process.terminate()
                self.process.wait(timeout=5)
            except Exception:
                self.process.kill()


# ============ Web Executor (Playwright) ============
class WebExecutor:
    """浏览器自动化执行器

    通过 Playwright 模拟用户与 Web Agent 交互
    支持多轮对话、UI 间接注入
    """

    def __init__(self, base_url: str = "http://127.0.0.1:3000"):
        self.base_url = base_url
        self.browser = None
        self.page = None
        self._playwright = None

    def _init(self):
        if not self.page:
            from playwright.sync_api import sync_playwright
            self._playwright = sync_playwright().start()
            self.browser = self._playwright.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-dev-shm-usage"],
            )
            self.page = self.browser.new_page()
            self.page.goto(self.base_url, timeout=30000)

    def execute(self, test_case: dict) -> ExecutionResult:
        start = time.time()
        try:
            self._init()

            if test_case.get("multi_turn"):
                return self._multi_turn(test_case)
            else:
                return self._single(test_case)

        except Exception as e:
            return ExecutionResult(success=False, error=str(e), duration_ms=int((time.time() - start) * 1000))

    def _single(self, test_case: dict) -> ExecutionResult:
        """单轮：发送一条消息，等待响应"""
        start = time.time()
        message = test_case.get("payload", {}).get("message", "")

        # 找到 chat input
        chat_input = self.page.query_selector(
            "input[type=text], input:not([type]), textarea, [contenteditable=true]"
        )
        if not chat_input:
            return ExecutionResult(success=False, error="No chat input found")

        chat_input.fill(message)
        chat_input.press("Enter")

        # 等待响应（agent 消息出现）
        try:
            self.page.wait_for_function(
                "document.querySelectorAll('[class*=\"agent\"], [class*=\"bot\"], [class*=\"response\"]').length > 0",
                timeout=15000,
            )
        except Exception:
            pass

        time.sleep(1)
        duration = int((time.time() - start) * 1000)

        # 提取响应
        response_elements = self.page.query_selector_all(
            '[class*="agent"], [class*="bot"], [class*="response"]'
        )
        response_text = "\n".join(el.inner_text() for el in response_elements[-5:])

        return ExecutionResult(
            success=True,
            output={"agent_response": response_text[:2000], "url": self.page.url},
            duration_ms=duration,
        )

    def _multi_turn(self, test_case: dict) -> ExecutionResult:
        """多轮：顺序发送多轮消息"""
        start = time.time()
        history = []
        for turn in test_case.get("turns", []):
            r = self._single({"payload": {"message": turn.get("message", "")}})
            history.append({"user": turn.get("message", ""), "agent": r.output.get("agent_response", "") if r.output else ""})
            time.sleep(0.5)
        return ExecutionResult(
            success=True,
            output={"history": history},
            duration_ms=int((time.time() - start) * 1000),
        )

    def inject_file_upload(self, selector: str, file_path: Path) -> bool:
        """通过 file input 上传恶意文件"""
        try:
            self._init()
            self.page.set_input_files(selector, str(file_path))
            return True
        except Exception:
            return False

    def teardown(self):
        try:
            if self.browser:
                self.browser.close()
            if self._playwright:
                self._playwright.stop()
        except Exception:
            pass


# ============ Multi-turn Conversation Replay ============
class ConversationReplayExecutor:
    """多轮对话回放器

    加载预先设计的多轮对话剧本，按顺序注入。
    支持中途插入污染数据（间接注入）。
    """

    def __init__(self, base_url: str = "http://127.0.0.1:8000"):
        self.api_executor = APIExecutor(base_url=base_url)
        self.indirect_injectors: dict = {}

    def add_indirect_injector(self, target: str, callback):
        """注册间接注入器

        Args:
            target: 'rag' | 'mcp' | 'memory' | 'web_search'
            callback: 注入函数 (payload) -> bool
        """
        self.indirect_injectors[target] = callback

    def execute(self, test_case: dict) -> ExecutionResult:
        """执行多轮剧本"""
        start = time.time()
        turns = test_case.get("turns", [])

        history = []
        for i, turn in enumerate(turns):
            # 间接注入（如果 turn 配置了）
            for inject in turn.get("inject_before", []):
                target = inject.get("target")
                payload = inject.get("payload", "")
                if target in self.indirect_injectors:
                    self.indirect_injectors[target](payload)

            # 用户消息
            msg = turn.get("message", "")
            r = self.api_executor.execute({
                "method": "POST",
                "endpoint": "/chat",
                "payload": {"message": msg},
            })
            history.append({"turn": i + 1, "user": msg, "agent_response": r.output})

            # 间接注入后置（用于下一轮）
            for inject in turn.get("inject_after", []):
                target = inject.get("target")
                payload = inject.get("payload", "")
                if target in self.indirect_injectors:
                    self.indirect_injectors[target](payload)

            time.sleep(0.5)

        # 最终断言
        exploitable = False
        if test_case.get("final_assertion"):
            # 检查 history
            pass

        return ExecutionResult(
            success=True,
            output={"history": history},
            duration_ms=int((time.time() - start) * 1000),
            side_effects={"exploitable": exploitable},
        )