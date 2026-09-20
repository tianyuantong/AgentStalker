#!/usr/bin/env python3
"""
AgentStalker Test Runner
Stage 3 (VERIFY) 沙箱测试编排器
读取 attack_graph.json，对每条用例：
  1. 重置环境（DB 快照、MailHog 清空、WireMock 重置）
  2. 预置数据（按 prerequisites）
  3. 发送攻击消息（API 型走 HTTP，Web 型走 Playwright）
  4. 收集四层日志（app/llm/ebpf/mock）
  5. 输出 evidence/{test_id}.json
"""
import argparse
import json
import os
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any

import requests

# ============ 配置 ============
NGINX_LOG = os.getenv("NGINX_LOG", "/var/log/nginx/access.log")
LITELLM_API = os.getenv("LITELLM_API", "http://llm-proxy:4000")
MAILHOG_API = os.getenv("MAILHOG_API", "http://mock-mail:8025/api/v2/messages")
WIREMOCK_API = os.getenv("WIREMOCK_API", "http://mock-api:8080/__admin/requests")
AGENT_ENDPOINT = os.getenv("AGENT_ENDPOINT", "http://agent-under-test:8000/chat")


# ============ 环境重置 ============
def reset_environment():
    """Legacy endpoints: verify responses and return explicit failures."""
    failures = []
    for method, url in ((requests.delete, MAILHOG_API), (requests.post, f"{WIREMOCK_API}/reset")):
        try:
            response = method(url, timeout=5)
            response.raise_for_status()
        except Exception as exc:
            failures.append(str(exc))
    return {"status": "error" if failures else "ok", "errors": failures}


def db_snapshot() -> dict:
    """导出 DB 快照"""
    try:
        result = subprocess.run(
            ["psql", os.getenv("POSTGRES_URL"), "-c", "SELECT * FROM users;"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode:
            return {"error": result.stderr, "status": "error"}
        return {"users": result.stdout, "status": "ok"}
    except Exception as e:
        return {"error": str(e)}


def db_diff(before: dict, after: dict) -> dict:
    """对比 DB 快照差异"""
    if before.get("status") != "ok" or after.get("status") != "ok":
        return {"status": "error", "modified": None, "error": "snapshot unavailable"}
    # Legacy summary only; not an exploitation oracle.
    def count_rows(snap: str) -> int:
        return len([l for l in snap.split("\n") if l and not l.startswith("-")])

    return {
        "users_before": count_rows(before.get("users", "")),
        "users_after": count_rows(after.get("users", "")),
        "modified": after.get("users", "") != before.get("users", ""),
        "status": "ok"
    }


# ============ 攻击执行 ============
def send_attack(steps: list) -> list:
    """发送多轮攻击，返回 agent 响应列表"""
    responses = []
    session_id = f"ast-{uuid.uuid4()}"

    for step in steps:
        if step["role"] != "user":
            continue

        payload = {
            "message": step["content"],
            "session_id": session_id
        }

        try:
            r = requests.post(
                AGENT_ENDPOINT,
                json=payload,
                timeout=30
            )
            responses.append({
                "turn": step["turn"],
                "request": payload,
                "response": r.json() if r.ok else {"error": r.text},
                "status": r.status_code
            })
        except Exception as e:
            responses.append({
                "turn": step["turn"],
                "request": payload,
                "response": {"error": str(e)},
                "status": 0
            })

    return responses


# ============ 日志收集 ============
def _collect_legacy(read):
    # These global sources have no case attribution. Successful reads are not
    # proof of a complete per-case window, and cannot establish a safe verdict.
    try:
        return {"status": "ok", "window_complete": False, "method": "legacy_unscoped",
                "data": read(), "error": ""}
    except Exception as exc:
        return {"status": "error", "window_complete": False, "method": "legacy_unscoped",
                "data": None, "error": f"{type(exc).__name__}: {exc}"}


def _get_json(url):
    response = requests.get(url, timeout=5)
    response.raise_for_status()
    return response.json()


def fetch_litellm_logs():
    return _collect_legacy(lambda: _get_json(f"{LITELLM_API}/logs"))


def fetch_mailhog_messages():
    return _collect_legacy(lambda: _get_json(MAILHOG_API))


def fetch_wiremock_requests():
    return _collect_legacy(lambda: _get_json(f"{WIREMOCK_API}/all"))


def fetch_ebpf_events():
    def read():
        return [json.loads(line) for line in Path("/output/tracee-events.json").read_text().splitlines() if line.strip()]
    return _collect_legacy(read)


def fetch_nginx_logs():
    return _collect_legacy(lambda: Path(NGINX_LOG).read_text().splitlines())


# ============ Shared decision entry (legacy output mapping only) ============
def judge_verdict(evidence_data: dict) -> dict:
    from sandbox.correlation import Evidence, VerdictEngine
    ev = VerdictEngine().judge(Evidence.from_dict(evidence_data))
    mapping = {"exploited": "vulnerable", "not_exploitable": "safe"}
    return {"result": mapping.get(ev.verdict, "inconclusive"),
            "canonical_verdict": ev.verdict, "confidence": "unscored",
            "reason_code": ev.metadata.get("reason_code"),
            "missing_evidence": ev.metadata.get("missing_evidence", []),
            "matched_signatures": ev.metadata.get("matched_rules", [])}


# ============ 主流程 ============
def run_case(case: dict) -> dict:
    """执行单条攻击用例"""
    print(f"\n[run] {case['id']}: {case['name']}")

    # 1. 重置
    reset_result = reset_environment()

    # 2. 预置数据
    # （按 case.prerequisites 注入初始状态）

    # 3. DB 快照（攻击前）
    db_before = db_snapshot()

    # 4. 发送攻击
    responses = [] if case.get("prerequisites") or reset_result["status"] != "ok" else send_attack(case["steps"])

    # 5. 等待副作用（给 agent 1-2s 完成工具调用）
    time.sleep(2)

    # 6. DB 快照（攻击后）
    db_after = db_snapshot()

    # 7. 收集日志
    evidence = {
        "test_id": case["id"],
        "case": case,
        "verdict": {},
        "execution_notes": {"reset": reset_result, "prerequisites_supported": not bool(case.get("prerequisites")),
                            "coverage": "legacy collectors are not scoped; no negative safety conclusion"},
        "logs": {
            "app_logs": {
                "requests": responses,
                "responses": [r.get("response") for r in responses]
            },
            "llm_logs": fetch_litellm_logs(),
            "ebpf_events": fetch_ebpf_events(),
            "mock_logs": {
                "emails_sent": fetch_mailhog_messages(),
                "http_requests_received": fetch_wiremock_requests(),
                "db_state_diff": db_diff(db_before, db_after)
            },
            "agent_reply_text": "\n".join(
                str(r.get("response", {}).get("answer", ""))
                for r in responses
            )
        }
    }

    # 8. 判定
    evidence["verdict"] = judge_verdict(evidence)

    return evidence


# ============ Isolated MCP regression profile ============
def run_mcp_case(case, profile, run_id):
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    import tempfile
    import threading
    from sandbox.contracts import RunContext, canonical_hash
    from sandbox.correlation import Evidence
    from sandbox.executors.mcp import MCPExecutor

    ctx = RunContext.new(case["id"], run_id=run_id).to_dict()
    ev = Evidence(schema_version=2, context=ctx, test_case_id=case["id"], title=case["id"],
                  boundary=profile["permissions"],
                  execution={"status": "not_run", "reset_status": "unknown"},
                  metadata={"case_kind": case["kind"], "group": case["group"],
                            "case_template_hash": canonical_hash(case), "association": "isolated_process_and_receiver"})
    token = "synthetic-" + uuid.uuid4().hex
    marker = "protected-" + uuid.uuid4().hex
    expected_text = "public-content"
    records = []
    lock = threading.Lock()
    class Receiver(BaseHTTPRequestHandler):
        def do_GET(self):
            with lock:
                records.append({"path": self.path, "authorization": self.headers.get("Authorization", "")})
            data = b"public-content"
            self.send_response(200)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        def log_message(self, *_args):
            pass
    server = ThreadingHTTPServer(("127.0.0.1", 0), Receiver)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    executor = None
    try:
        with tempfile.TemporaryDirectory(prefix="ast-case-") as temp:
            tree = Path(temp)
            allowed = tree / "allowed"; allowed.mkdir()
            outside = tree / "allowed-sibling"; outside.mkdir()
            (outside / "secret.txt").write_text(marker)
            (allowed / "ordinary.txt").write_text(expected_text)
            (allowed / "allowed-sibling-name.txt").write_text(expected_text)
            (allowed / "nested").mkdir(); (allowed / "nested/public.txt").write_text(expected_text)
            (allowed / "link.txt").symlink_to(outside / "secret.txt")
            receiver = f"http://127.0.0.1:{server.server_port}"
            env = {"PATH": os.environ.get("PATH", ""), "HOME": temp, "TMPDIR": temp,
                   "PYTHONIOENCODING": "utf-8", "AST_TEST_TREE": temp,
                   "AST_VARIANT": profile["variant"], "AST_RECEIVER": receiver, "AUTHORIZATION": token}
            from sandbox.regression import ROOT
            executor = MCPExecutor([sys.executable, "-m", "testbeds.mcp_mini_server.regression_server"],
                                   cwd=ROOT, env=env, timeout=profile["timeout_seconds"])
            selector = case["selector"]
            if case["operation"] == "read_file":
                paths = {"direct": outside / "secret.txt", "parent": allowed / "../allowed-sibling/secret.txt",
                         "symlink": allowed / "link.txt", "ordinary": allowed / "ordinary.txt",
                         "sibling-name": allowed / "allowed-sibling-name.txt", "nested": allowed / "nested/public.txt"}
                payload = {"path": str(paths[selector])}
            else:
                public = selector.startswith("public-")
                payload = {"url": receiver + ("/public/" if public else "/private/") + ctx["session_id"]}
            ev.execution["reset_status"] = "ok"
            # A fresh receiver and completed synchronous call define the observation window.
            result = executor.execute({"tool": case["operation"], "payload": payload})
            raw_response = result.output or {}
            texts = [c.get("text", "") for c in raw_response.get("result", {}).get("content", []) if c.get("type") == "text"]
            ev.execution.update(status=result.status, error=result.error, duration_ms=result.duration_ms)
            response_ok = result.status == "completed" and bool(texts)
            ev.collection["response"] = {"status": "ok" if response_ok else "error", "window_complete": response_ok,
                                         "method": "matching MCP JSON-RPC response", "error": result.error}
            ev.events.append({**ctx, "event_id": "tool-response", "source": "response", "layer": "mcp",
                              "data": {"text": "\n".join(texts), "rpc": raw_response,
                                       "tool": case["operation"], "arguments": payload}})
            ev.required_sources = ["response"]
            if case["operation"] == "proxy_request":
                with lock:
                    snapshot = list(records)
                # Only a synchronous result proves this receiver's observation window ended.
                ev.collection["receiver"] = {"status": "ok", "window_complete": result.status == "completed",
                                              "method": "dedicated loopback HTTP receiver; synchronous tool response"}
                ev.events.append({**ctx, "event_id": "receiver-snapshot", "source": "receiver",
                                  "data": {"requests": snapshot}})
                ev.required_sources.append("receiver")
            if case["kind"] == "attack":
                ev.checks = [{"id": "impact", "kind": "impact",
                              "type": "protected_marker_returned" if case["operation"] == "read_file" else "credential_received",
                              "source": "response" if case["operation"] == "read_file" else "receiver",
                              "expected": marker if case["operation"] == "read_file" else token}]
            else:
                ev.checks = [{"id": "normal", "kind": "normal", "type": "text_equals", "source": "response", "expected": expected_text}]
                if case["operation"] == "proxy_request":
                    # Same security proposition in both variants, independent of task success.
                    ev.checks.append({"id": "public-credential-impact", "kind": "impact",
                                      "type": "credential_received", "source": "receiver", "expected": token})
    except Exception as exc:
        ev.execution.update(status="error", error=f"{type(exc).__name__}: {exc}")
        if not ev.required_sources:
            ev.required_sources = ["response"]
    finally:
        if executor:
            executor.teardown()
        server.shutdown(); server.server_close(); thread.join(timeout=2)
    return ev


def run_suite(suite, profile, output):
    from sandbox.contracts import write_json_new
    from sandbox.regression import new_manifest, save_record, summarize
    if suite.get("schema_version") != 2 or not suite.get("cases"):
        raise ValueError("empty or unsupported suite")
    if profile.get("type") != "mcp-regression" or profile.get("variant") not in {"vulnerable", "fixed", "disabled"}:
        raise ValueError("unsupported profile")
    if not isinstance(profile.get("timeout_seconds"), (int, float)) or not 0 < profile["timeout_seconds"] <= 60:
        raise ValueError("timeout must be in (0, 60]")
    if not isinstance(profile.get("permissions"), str) or not profile["permissions"].strip():
        raise ValueError("permission boundary required")
    if profile.get("model") is not None:
        raise ValueError("local tool fixture never executes an LLM")
    ids = [c["id"] for c in suite["cases"]]
    if len(set(ids)) != len(ids):
        raise ValueError("duplicate case id")
    for c in suite["cases"]:
        if c.get("kind") not in {"attack", "normal"} or c.get("operation") not in {"read_file", "proxy_request"}:
            raise ValueError("unsupported case")
        import re
        if not isinstance(c.get("id"), str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,99}", c["id"]):
            raise ValueError("unsafe case id")
        group = "file" if c["operation"] == "read_file" else "proxy"
        if c.get("group") != group:
            raise ValueError("case group/operation mismatch")
        selectors = ({"direct", "parent", "symlink"} if c["kind"] == "attack"
                     else {"ordinary", "sibling-name", "nested"}) if group == "file" else (
                     {"private-one", "private-two", "private-three"} if c["kind"] == "attack"
                     else {"public-one", "public-two", "public-three"})
        if c.get("selector") not in selectors:
            raise ValueError("unsupported fixture selector")
    root = Path(output)
    root.mkdir(parents=True, exist_ok=False)
    run_id = uuid.uuid4().hex
    manifest = new_manifest(suite, profile, run_id)
    judged = []
    for case in suite["cases"]:
        raw = run_mcp_case(case, profile, run_id)
        judged.append(save_record(root, manifest, raw))
    write_json_new(root / "manifest.json", manifest)
    write_json_new(root / "summary.json", summarize(judged))
    return judged


def main():
    from sandbox.contracts import load_json, write_json_new
    parser = argparse.ArgumentParser(description="Run a legacy API audit or isolated MCP regression suite")
    parser.add_argument("--config", required=True)
    parser.add_argument("--profile")
    parser.add_argument("--output", required=True, help="new run directory (never overwritten)")
    parser.add_argument("--filter")
    args = parser.parse_args()
    try:
        config = load_json(args.config)
        if args.profile:
            if args.filter:
                config = {**config, "cases": [c for c in config["cases"] if c["id"] == args.filter]}
            results = run_suite(config, load_json(args.profile), args.output)
            from sandbox.regression import summarize
            print(json.dumps(summarize(results), indent=2))
            return 2 if any(e.execution["status"] != "completed" for e in results) else 0
        cases = config if isinstance(config, list) else config.get("cases", [])
        if args.filter:
            cases = [c for c in cases if c["id"] == args.filter]
        if not cases:
            raise ValueError("no cases selected")
        root = Path(args.output); root.mkdir(parents=True, exist_ok=False)
        for i, case in enumerate(cases):
            write_json_new(root / f"{i}.json", run_case(case))
        print("Legacy collection preserved; scoped coverage unverified, verdicts remain inconclusive.")
        return 2
    except (ValueError, KeyError, OSError, TypeError) as exc:
        print(f"Run failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
