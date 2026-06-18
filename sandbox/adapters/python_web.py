"""
Generic Web Adapter — Playwright-based UI Agent 测试
通过浏览器自动化测试 Web 形态的 Agent
"""
from __future__ import annotations

import time
from pathlib import Path

from . import BaseAdapter, Tool, InvokeResult


class WebAdapter(BaseAdapter):
    framework_name = "Generic Web (Playwright)"

    def __init__(self, source_dir: str | Path, sandbox_endpoint: str = "", agent_profile: dict | None = None):
        super().__init__(source_dir, sandbox_endpoint, agent_profile)
        self.browser = None
        self.page = None

    def deploy(self) -> bool:
        """启动 Playwright"""
        try:
            from playwright.sync_api import sync_playwright
            self._playwright = sync_playwright().start()
            self.browser = self._playwright.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-dev-shm-usage"],
            )
            self.page = self.browser.new_page()
            # 设置 trace header
            self.page.set_extra_http_headers({"X-AgentStalker-Trace": "1"})

            # 导航到 Agent
            self.page.goto(self.sandbox_endpoint, timeout=30000)
            return True
        except Exception as e:
            print(f"[!] Web deploy error: {e}")
            return False

    def list_tools(self) -> list[Tool]:
        """通过 DOM 探测工具按钮"""
        if not self.page:
            return []
        try:
            # 启发式：找含 tool/action/button 等关键字的元素
            buttons = self.page.query_selector_all("button, [role=button], .tool, .action")
            for b in buttons:
                text = b.inner_text()[:50]
                self.tools.append(Tool(
                    name=f"ui_{text}",
                    description=f"UI element: {text}",
                    risk_level="medium",
                ))
        except Exception:
            pass
        return self.tools

    def invoke_tool(self, tool_name: str, parameters: dict, user_context: dict | None = None) -> InvokeResult:
        """通过 UI 触发工具"""
        start = time.time()
        try:
            if tool_name.startswith("ui_"):
                # 点击按钮
                button_text = tool_name[len("ui_"):]
                self.page.click(f"button:has-text('{button_text}')", timeout=5000)
            else:
                # 输入到 chat 框
                chat_input = self.page.query_selector("input, textarea, [contenteditable]")
                if chat_input:
                    chat_input.fill(parameters.get("message", ""))
                    chat_input.press("Enter")

            # 等待响应
            self.page.wait_for_load_state("networkidle", timeout=10000)

            duration = int((time.time() - start) * 1000)
            output = {
                "url": self.page.url,
                "title": self.page.title(),
                "body_text": self.page.inner_text("body")[:1000],
            }
            result = InvokeResult(success=True, output=output, duration_ms=duration)
            self._record_invocation(tool_name, parameters, result)
            return result

        except Exception as e:
            return InvokeResult(success=False, error=str(e), duration_ms=int((time.time() - start) * 1000))

    def teardown(self) -> bool:
        try:
            if self.browser:
                self.browser.close()
            if hasattr(self, "_playwright"):
                self._playwright.stop()
            return True
        except Exception:
            return False

    def inject_indirect_via_dom(self, selector: str, payload: str) -> bool:
        """通过 DOM 注入（如 RAG UI 上传恶意文件）"""
        try:
            self.page.fill(selector, payload)
            return True
        except Exception:
            return False