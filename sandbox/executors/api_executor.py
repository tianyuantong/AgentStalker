"""HTTP execution state and normal-task checks; safety is judged centrally."""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from sandbox.assertions import response_assertions


@dataclass
class ExecutionContext:
    session_id: str
    conversation_history: list[dict] = field(default_factory=list)
    tool_invocations: list[dict] = field(default_factory=list)
    started_at: float = 0.0


@dataclass
class ExecutionResult:
    success: bool
    output: Any = None
    error: str = ""
    duration_ms: int = 0
    trace_id: str = ""
    conversation_id: str = ""
    side_effects: dict = field(default_factory=dict)
    status: str = "not_run"
    assertions: list[dict] = field(default_factory=list)

    def __post_init__(self):
        # A successful result necessarily ran; failures must say error/timeout/not_run themselves.
        if self.success and self.status == "not_run":
            self.status = "completed"


class APIExecutor:
    def __init__(self, base_url="http://127.0.0.1:8000", auth_token="", *,
                 session_field="session_id", timeout=30):
        self.base_url = base_url.rstrip("/")
        self.auth_token = auth_token
        self.session_field = session_field
        self.timeout = timeout
        self._init_session()

    def _init_session(self):
        import requests
        self.session = requests.Session()
        if self.auth_token:
            self.session.headers["Authorization"] = f"Bearer {self.auth_token}"
        self.session.headers.update({"Content-Type": "application/json", "X-AgentStalker": "1"})

    def execute(self, test_case: dict, context: ExecutionContext | None = None) -> ExecutionResult:
        import requests
        started = time.monotonic()
        ctx = context or ExecutionContext(uuid.uuid4().hex, started_at=time.time())
        try:
            result = (self._execute_multi_turn(test_case, ctx) if test_case.get("multi_turn")
                      else self._execute_single(test_case, ctx))
        except requests.Timeout as exc:
            result = ExecutionResult(False, output={"history": list(ctx.conversation_history)},
                                     error=str(exc), status="timeout")
        except Exception as exc:
            result = ExecutionResult(False, output={"history": list(ctx.conversation_history)},
                                     error=str(exc), status="error")
        result.duration_ms = int((time.monotonic() - started) * 1000)
        result.trace_id = result.conversation_id = ctx.session_id
        return result

    def _execute_single(self, tc, ctx):
        method = tc.get("method", "POST").upper()
        payload = dict(tc.get("payload", {}))
        if self.session_field:
            payload[self.session_field] = ctx.session_id
        self.session.headers["X-Trace-ID"] = ctx.session_id
        kwargs = {"params" if method == "GET" else "json": payload, "timeout": self.timeout}
        r = self.session.request(method, self.base_url + tc.get("endpoint", "/chat"), **kwargs)
        try:
            output = r.json()
        except ValueError:
            output = {"raw": r.text}
        ctx.tool_invocations.append({"method": method, "response_status": r.status_code})
        checks = response_assertions(tc.get("assertions", []), output, r.status_code)
        return ExecutionResult(
            200 <= r.status_code < 300, output=output,
            error="" if 200 <= r.status_code < 300 else f"HTTP {r.status_code}",
            status="completed" if 200 <= r.status_code < 300 else "error",
            side_effects={"response_status": r.status_code, "exploitable": False}, assertions=checks,
        )

    def _execute_multi_turn(self, tc, ctx):
        turns = tc.get("turns", [])
        if not turns:
            return ExecutionResult(False, error="empty conversation", status="not_run")
        last = None
        for i, turn in enumerate(turns):
            last = self._execute_single({"payload": {"message": turn.get("message", "")},
                                         "assertions": turn.get("assertions", [])}, ctx)
            ctx.conversation_history.append({"turn": i + 1, "user": turn.get("message", ""),
                                             "agent": last.output, "status": last.status})
            if not last.success or any(a["status"] != "pass" for a in last.assertions):
                return ExecutionResult(False, output={"history": ctx.conversation_history},
                                       error=last.error or "turn prerequisite failed", status="error",
                                       assertions=last.assertions)
        checks = response_assertions(tc.get("assertions", []), last.output,
                                     last.side_effects["response_status"])
        return ExecutionResult(True, output={"history": ctx.conversation_history, "final": last.output},
                               status="completed", assertions=checks,
                               side_effects={"exploitable": False})

    def _evaluate_assertions(self, assertions, output, response):
        """Compatibility: task checks only. Unknown types never pass."""
        results = response_assertions(assertions, output, response.status_code)
        return bool(results) and all(a["status"] == "pass" for a in results)

    def check_side_effects(self, expected: dict) -> dict:
        """Legacy unscoped probes. Results are observations, never safety verdicts."""
        results = {"collection": {}}
        endpoints = {"external_api_calls": "http://127.0.0.1:8080/__admin/requests"}
        if "email_sent_to" in expected:
            endpoints["emails"] = "http://127.0.0.1:8025/api/v2/messages"
        for name, url in endpoints.items():
            try:
                response = self.session.get(url, timeout=5)
                response.raise_for_status()
                data = response.json()
                values = data.get("items" if name == "emails" else "requests", [])
                if name == "emails":
                    values = [e for e in values if expected["email_sent_to"] in str(e.get("Content", {}).get("Headers", []))]
                results[name] = values
                results["collection"][name] = {"status": "ok", "window_complete": False, "method": "legacy_unscoped"}
            except Exception as exc:
                results[name] = None
                results["collection"][name] = {"status": "error", "window_complete": False,
                                                "method": "legacy_unscoped", "error": str(exc)}
        return results

    def teardown(self):
        if self.session:
            self.session.close()


def main():
    """Preserve the original HTTP CLI without its unsupported 'safe' claim."""
    import argparse
    from dataclasses import asdict
    import json
    from pathlib import Path
    import sys
    from sandbox.contracts import load_json, write_json_new
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--base-url", default="http://127.0.0.1:8000")
    ap.add_argument("--attack-graph", required=True)
    ap.add_argument("--output", default="execution_results.json")
    args = ap.parse_args()
    executor = None
    try:
        if Path(args.output).exists():
            raise FileExistsError(args.output)
        graph = load_json(args.attack_graph)
        cases = graph.get("test_cases", [])
        if not cases:
            raise ValueError("no test_cases")
        executor = APIExecutor(base_url=args.base_url)
        results = []
        for case in cases:
            result = executor.execute(case)
            results.append({**asdict(result), "test_case_id": case.get("id"),
                            "security_verdict": "inconclusive", "exploitable": None})
        write_json_new(args.output, results)
        print(json.dumps({"executed": len(results), "security_verdict": "inconclusive",
                          "reason": "transport and task checks alone do not establish safety"}))
        return 2 if any(r["status"] != "completed" for r in results) else 0
    except (OSError, ValueError, TypeError, KeyError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    finally:
        if executor:
            executor.teardown()


if __name__ == "__main__":
    raise SystemExit(main())
