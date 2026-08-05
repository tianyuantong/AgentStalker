"""LangGraph Adapter — 适配 LangGraph Agent 框架

历史:原在 _other_frameworks.py。Commit 5 拆出独立模块,_start_agent/_stop_agent
委托给 BaseAdapter 的共享 _spawn_by_keyword/_stop_process(消除 ~95% 重复代码)。
"""
from __future__ import annotations

import time

from . import BaseAdapter, Tool, InvokeResult


class LangGraphAdapter(BaseAdapter):
    framework_name = "LangGraph"

    def deploy(self) -> bool:
        return self._start_agent()

    def list_tools(self) -> list[Tool]:
        return self.tools

    def invoke_tool(self, tool_name: str, parameters: dict, user_context: dict | None = None) -> InvokeResult:
        # LangGraph 通过 invoke(input) 调用
        import requests
        start = time.time()
        try:
            r = requests.post(
                f"{self.sandbox_endpoint}/invoke",
                json={"input": parameters},
                timeout=30,
            )
            return InvokeResult(
                success=r.status_code < 300,
                output=r.json(),
                duration_ms=int((time.time() - start) * 1000),
            )
        except Exception as e:
            return InvokeResult(success=False, error=str(e))

    def teardown(self) -> bool:
        return self._stop_process()

    def _start_agent(self) -> bool:
        # 委托给共享 spawn(关键字 "langgraph",日志 langgraph.log,glob "*.py")
        return self._spawn_by_keyword(keyword="langgraph", log_name="langgraph.log", glob="*.py")
