"""CrewAI Adapter — 适配 CrewAI Agent 框架

历史:原在 _other_frameworks.py。Commit 5 拆出独立模块,_start_agent/_stop_agent
委托给 BaseAdapter 的共享 _spawn_by_keyword/_stop_process(消除 ~95% 重复代码)。
"""
from __future__ import annotations

import time

from . import BaseAdapter, Tool, InvokeResult


class CrewAIAdapter(BaseAdapter):
    framework_name = "CrewAI"

    def deploy(self) -> bool:
        return self._start_agent()

    def list_tools(self) -> list[Tool]:
        return self.tools

    def invoke_tool(self, tool_name: str, parameters: dict, user_context: dict | None = None) -> InvokeResult:
        # CrewAI 通过 kickoff() 触发 — 注入 input
        import requests
        start = time.time()
        try:
            r = requests.post(
                f"{self.sandbox_endpoint}/kickoff",
                json={"inputs": parameters},
                timeout=60,
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
        # 委托给共享 spawn(关键字 "crewai",日志 crewai.log)
        return self._spawn_by_keyword(keyword="crewai", log_name="crewai.log")
