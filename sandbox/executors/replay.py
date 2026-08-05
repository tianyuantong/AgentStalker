"""Conversation Replay Executor — 多轮对话回放器

加载预先设计的多轮对话剧本,按顺序注入。支持中途插入污染数据(间接注入)。

历史:原在 _other_executors.py。Commit 4 拆出独立模块。
修 C2:原版 __init__ 调用 APIExecutor(base_url=...) 但只 import 了
ExecutionResult(没 import APIExecutor),实例化时 NameError。
"""
from __future__ import annotations

import time

from .api_executor import APIExecutor, ExecutionResult


class ConversationReplayExecutor:
    """多轮对话回放器

    加载预先设计的多轮对话剧本，按顺序注入。
    支持中途插入污染数据（间接注入）。
    """

    def __init__(self, base_url: str = "http://127.0.0.1:8000"):
        # C2 修复:APIExecutor 现在正确 import(原版漏 import 导致 NameError)
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
