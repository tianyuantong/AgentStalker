"""Web Executor — Playwright 浏览器自动化执行器

通过 Playwright 模拟用户与 Web Agent 交互,支持多轮对话、UI 间接注入。

历史:原在 _other_executors.py。Commit 4 拆出独立模块。
"""
from __future__ import annotations

import time
from pathlib import Path

from .api_executor import ExecutionResult


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
