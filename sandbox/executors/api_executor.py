"""
AgentStalker Executors — 多渠道攻击执行器
========================================
将攻击 payload 通过不同渠道发送给被测 Agent：
- API Executor: HTTP REST 调用
- Web Executor: Playwright 浏览器自动化（多轮对话）
- CLI Executor: 命令行 stdin
- MCP Executor: MCP stdio RPC

支持多轮对话：每轮注入一个 payload，等待响应后继续下一轮
"""
from __future__ import annotations

import json
import time
import traceback
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class ExecutionContext:
    """执行上下文（多轮对话、session）"""
    session_id: str
    conversation_history: list[dict] = field(default_factory=list)
    tool_invocations: list[dict] = field(default_factory=list)
    started_at: float = 0.0


@dataclass
class ExecutionResult:
    """单次执行结果"""
    success: bool
    output: Any = None
    error: str = ""
    duration_ms: int = 0
    trace_id: str = ""
    conversation_id: str = ""
    side_effects: dict = field(default_factory=dict)  # 副效应（DB rows / emails / network calls）


class APIExecutor:
    """HTTP/REST API 执行器

    支持：
    - 单轮注入
    - 多轮对话（保持 session_id）
    - 副效应探测（事后调用其他 API 查询）
    """

    def __init__(self, base_url: str = "http://127.0.0.1:8000", auth_token: str = ""):
        self.base_url = base_url.rstrip("/")
        self.auth_token = auth_token
        self.session = None
        self._init_session()

    def _init_session(self):
        import requests
        self.session = requests.Session()
        if self.auth_token:
            self.session.headers["Authorization"] = f"Bearer {self.auth_token}"
        self.session.headers["Content-Type"] = "application/json"
        self.session.headers["X-AgentStalker"] = "1"

    def execute(self, test_case: dict) -> ExecutionResult:
        """执行单个测试用例

        Args:
            test_case: {
                "id": "TC-001",
                "title": "...",
                "severity": "high",
                "channel": "api",
                "method": "POST",
                "endpoint": "/chat",
                "payload": {"message": "..."},
                "multi_turn": False,
                "assertions": [{"type": "contains", "value": "..."}, ...]
            }
        """
        start = time.time()
        ctx = ExecutionContext(
            session_id=f"ast-{int(time.time() * 1000)}",
            started_at=start,
        )

        try:
            # 单轮 vs 多轮
            if test_case.get("multi_turn"):
                result = self._execute_multi_turn(test_case, ctx)
            else:
                result = self._execute_single(test_case, ctx)

            result.duration_ms = int((time.time() - start) * 1000)
            return result

        except Exception as e:
            return ExecutionResult(
                success=False,
                error=f"{e}\n{traceback.format_exc()}",
                duration_ms=int((time.time() - start) * 1000),
            )

    def _execute_single(self, tc: dict, ctx: ExecutionContext) -> ExecutionResult:
        """单轮注入"""
        method = tc.get("method", "POST").upper()
        endpoint = tc.get("endpoint", "/chat")
        payload = tc.get("payload", {})

        url = self.base_url + endpoint
        self.session.headers["X-Trace-ID"] = ctx.session_id

        if method == "GET":
            r = self.session.get(url, params=payload, timeout=30)
        elif method == "POST":
            r = self.session.post(url, json=payload, timeout=30)
        elif method == "PUT":
            r = self.session.put(url, json=payload, timeout=30)
        elif method == "DELETE":
            r = self.session.delete(url, json=payload, timeout=30)
        else:
            r = self.session.request(method, url, json=payload, timeout=30)

        ctx.tool_invocations.append({
            "method": method,
            "endpoint": endpoint,
            "payload": payload,
            "response_status": r.status_code,
        })

        # 解析响应
        try:
            output = r.json()
        except Exception:
            output = {"raw": r.text}

        # 断言
        exploitable = self._evaluate_assertions(tc.get("assertions", []), output, r)

        return ExecutionResult(
            success=200 <= r.status_code < 300,
            output=output,
            error="" if 200 <= r.status_code < 300 else f"HTTP {r.status_code}",
            trace_id=ctx.session_id,
            conversation_id=ctx.session_id,
            side_effects={"response_status": r.status_code, "exploitable": exploitable},
        )

    def _execute_multi_turn(self, tc: dict, ctx: ExecutionContext) -> ExecutionResult:
        """多轮对话注入"""
        turns = tc.get("turns", [])
        last_output = None

        for i, turn in enumerate(turns):
            payload = {
                "message": turn.get("message", ""),
                "conversation_id": ctx.session_id,
            }
            r = self.session.post(self.base_url + "/chat", json=payload, timeout=30)
            ctx.conversation_history.append({
                "turn": i + 1,
                "user": turn.get("message", ""),
                "agent": r.text,
            })
            try:
                last_output = r.json()
            except Exception:
                last_output = {"raw": r.text}

            # 可选：每轮断言（如果失败则中止）
            turn_assertions = turn.get("assertions", [])
            if turn_assertions and not self._evaluate_assertions(turn_assertions, last_output, r):
                return ExecutionResult(
                    success=True,
                    output={"history": ctx.conversation_history, "final": last_output},
                    trace_id=ctx.session_id,
                    conversation_id=ctx.session_id,
                    side_effects={"stopped_at_turn": i + 1, "exploitable": False},
                )

            time.sleep(0.5)

        # 最终断言
        exploitable = self._evaluate_assertions(tc.get("assertions", []), last_output, r)

        return ExecutionResult(
            success=True,
            output={"history": ctx.conversation_history, "final": last_output},
            trace_id=ctx.session_id,
            conversation_id=ctx.session_id,
            side_effects={"exploitable": exploitable},
        )

    def _evaluate_assertions(self, assertions: list[dict], output: Any, response) -> bool:
        """评估断言：returns True if exploited"""
        if not assertions:
            return False
        output_text = json.dumps(output) if isinstance(output, dict) else str(output)
        for a in assertions:
            atype = a.get("type", "contains")
            if atype == "contains":
                if a.get("value", "") not in output_text:
                    return False
            elif atype == "not_contains":
                if a.get("value", "") in output_text:
                    return False
            elif atype == "status":
                if response.status_code != a.get("value"):
                    return False
            elif atype == "regex":
                import re
                if not re.search(a.get("value", ""), output_text):
                    return False
            elif atype == "json_path":
                # 简单实现
                path = a.get("value", "")
                if path not in output_text:
                    return False
        return True

    def check_side_effects(self, expected: dict) -> dict:
        """事后探测副效应

        Args:
            expected: {
                "email_sent_to": "evil@...",
                "db_query": "SELECT...",
                "file_created": "/tmp/..."
            }
        """
        results = {}

        # 检查 email（MailHog API）
        if "email_sent_to" in expected:
            try:
                r = self.session.get("http://127.0.0.1:8025/api/v2/messages", timeout=5)
                emails = r.json().get("items", [])
                results["emails"] = [
                    e for e in emails
                    if expected["email_sent_to"] in str(e.get("Content", {}).get("Headers", []))
                ]
            except Exception:
                results["emails"] = "MailHog unreachable"

        # 检查 WireMock 收到的请求
        try:
            r = self.session.get("http://127.0.0.1:8080/__admin/requests", timeout=5)
            results["external_api_calls"] = r.json().get("requests", [])
        except Exception:
            results["external_api_calls"] = "WireMock unreachable"

        return results


# ============ CLI 接口 ============
def main():
    import argparse
    import sys
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", default="http://127.0.0.1:8000")
    ap.add_argument("--attack-graph", required=True)
    ap.add_argument("--output", default="execution_results.json")
    args = ap.parse_args()

    attack_graph = json.loads(Path(args.attack_graph).read_text())
    executor = APIExecutor(base_url=args.base_url)
    results = []
    for tc in attack_graph.get("test_cases", []):
        print(f"[*] Executing {tc.get('id')}: {tc.get('title')}")
        r = executor.execute(tc)
        results.append({
            "test_case_id": tc.get("id"),
            "title": tc.get("title"),
            "severity": tc.get("severity"),
            "success": r.success,
            "exploitable": r.side_effects.get("exploitable", False),
            "output_preview": json.dumps(r.output)[:500] if r.output else "",
            "error": r.error,
            "duration_ms": r.duration_ms,
        })
        print(f"    → {'EXPLOITED' if r.side_effects.get('exploitable') else 'safe' if r.success else 'errored'}")

    Path(args.output).write_text(json.dumps(results, indent=2, ensure_ascii=False))
    exploitable_count = sum(1 for r in results if r["exploitable"])
    print(f"\n[+] Total: {len(results)}, Exploitable: {exploitable_count}")


if __name__ == "__main__":
    main()