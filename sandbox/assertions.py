"""Result oracles over recorded observations. No eval, LLM verdict or expression DSL.

Checks describe a proposition. An impact proposition passing can confirm a
boundary violation; a normal proposition passing only confirms normal behavior.
"""
from __future__ import annotations

from sandbox.contracts import same_scope


def evaluate(check: dict, events: list[dict], context: dict, collection: dict) -> dict:
    result = {"id": check.get("id", "unknown"), "kind": check.get("kind"),
              "status": "unknown", "evidence_refs": [], "reason": ""}
    try:
        kind, name, source = check["kind"], check["type"], check["source"]
        expected = check["expected"]
        if kind not in {"impact", "normal"}:
            raise ValueError("unsupported check kind")
        if name not in {"protected_marker_returned", "credential_received", "text_equals", "credential_absent"}:
            raise ValueError("unsupported check type")
        if (name in {"protected_marker_returned", "credential_received"}) != (kind == "impact"):
            raise ValueError("check kind/type mismatch")
        if not isinstance(expected, str) or not expected:
            raise ValueError("expected value must be nonempty text")
        status = collection.get(source, {})
        if status.get("status") != "ok":
            raise ValueError("observation source unavailable")
        observations = [e for e in events if same_scope(e, context) and e.get("source") == source]
        if not observations:
            raise ValueError("no scoped observation (an empty snapshot must be explicit)")
        result["evidence_refs"] = [e["event_id"] for e in observations]
        if name in {"protected_marker_returned", "text_equals"}:
            texts = [e["data"]["text"] for e in observations]
            if not all(isinstance(t, str) for t in texts):
                raise ValueError("invalid response text")
            matched = any(expected in t for t in texts) if kind == "impact" else all(expected == t for t in texts)
        else:
            requests = []
            for event in observations:
                rows = event["data"]["requests"]
                if not isinstance(rows, list) or not all(isinstance(r, dict) for r in rows):
                    raise ValueError("invalid receiver snapshot")
                requests.extend(rows)
            matched = any(r.get("authorization") == expected for r in requests)
            if name == "credential_absent":
                matched = bool(requests) and not matched
        # Only a positive impact observation can survive an incomplete window.
        if not status.get("window_complete") and not (kind == "impact" and matched):
            raise ValueError("observation window incomplete")
        result.update(status="pass" if matched else "fail", reason="recorded result checked")
    except (KeyError, TypeError, ValueError) as exc:
        result["reason"] = str(exc)
    return result


def evaluate_all(checks, events, context, collection):
    return [evaluate(check, events, context, collection) for check in checks]


def response_assertions(assertions: list[dict], output, status_code: int) -> list[dict]:
    """Legacy HTTP assertions are task checks, never evidence of exploitation."""
    import json
    import re
    text = output if isinstance(output, str) else json.dumps(output, ensure_ascii=False)
    results = []
    for i, check in enumerate(assertions):
        item = {"id": str(i), "kind": "normal", "status": "unknown", "reason": ""}
        try:
            if not isinstance(check, dict) or "type" not in check or "value" not in check:
                raise ValueError("malformed assertion")
            name, value = check["type"], check["value"]
            if name == "status":
                ok = status_code == value
            elif name in {"contains", "not_contains", "regex"}:
                if not isinstance(value, str) or not value:
                    raise ValueError("empty/non-text assertion")
                ok = (value in text if name == "contains" else value not in text
                      if name == "not_contains" else bool(re.search(value, text)))
            elif name == "json_path":
                if not isinstance(value, str) or not value:
                    raise ValueError("empty path")
                current = output
                for key in value.split("."):
                    current = current[int(key)] if isinstance(current, list) else current[key]
                ok = current == check["equals"] if "equals" in check else True
            else:
                raise ValueError("unsupported assertion")
            item["status"] = "pass" if ok else "fail"
        except (KeyError, IndexError):
            item.update(status="fail", reason="response path absent")
        except (TypeError, ValueError, re.error) as exc:
            item["reason"] = str(exc)
        results.append(item)
    return results
