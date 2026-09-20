"""Scripted conversation execution. Offline rejudging lives in correlation."""
from __future__ import annotations

import time
import uuid

from .api_executor import APIExecutor, ExecutionResult, ExecutionContext
from sandbox.assertions import response_assertions


class ConversationReplayExecutor:
    def __init__(self, base_url="http://127.0.0.1:8000", **kwargs):
        self.api_executor = APIExecutor(base_url=base_url, **kwargs)
        self.indirect_injectors = {}

    def add_indirect_injector(self, target, callback):
        self.indirect_injectors[target] = callback

    def _inject(self, injections):
        for inject in injections:
            callback = self.indirect_injectors.get(inject["target"])
            if callback is None or callback(inject.get("payload", "")) is not True:
                raise ValueError(f"injection prerequisite failed: {inject['target']}")

    def execute(self, test_case: dict, context: ExecutionContext | None = None) -> ExecutionResult:
        started = time.monotonic()
        ctx = context or ExecutionContext(uuid.uuid4().hex)
        history = []
        turns = test_case.get("turns", [])
        if not turns:
            return ExecutionResult(False, status="not_run", error="empty conversation")
        try:
            for i, turn in enumerate(turns):
                self._inject(turn.get("inject_before", []))
                r = self.api_executor.execute({"payload": {"message": turn.get("message", "")},
                                                "assertions": turn.get("assertions", [])}, context=ctx)
                history.append({"turn": i + 1, "agent_response": r.output, "status": r.status})
                if not r.success or any(a["status"] != "pass" for a in r.assertions):
                    return ExecutionResult(False, output={"history": history}, status=r.status if not r.success else "error",
                                           error=r.error or "turn prerequisite failed", assertions=r.assertions,
                                           conversation_id=ctx.session_id, trace_id=ctx.session_id)
                self._inject(turn.get("inject_after", []))
            checks = test_case.get("final_assertion", test_case.get("assertions", []))
            if isinstance(checks, dict):
                checks = [checks]
            if not isinstance(checks, list):
                raise ValueError("final_assertion must be structured checks, not an expression")
            results = response_assertions(checks, r.output, r.side_effects.get("response_status", 200))
            return ExecutionResult(True, output={"history": history}, status="completed",
                                   assertions=results, conversation_id=ctx.session_id, trace_id=ctx.session_id,
                                   duration_ms=int((time.monotonic() - started) * 1000),
                                   side_effects={"exploitable": False})
        except Exception as exc:
            return ExecutionResult(False, output={"history": history}, status="error", error=str(exc),
                                   conversation_id=ctx.session_id, trace_id=ctx.session_id)

    def teardown(self):
        self.api_executor.teardown()
