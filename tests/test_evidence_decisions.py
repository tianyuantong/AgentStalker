"""Independent propositions/observations, including fault and cross-run negatives."""
from copy import deepcopy
from dataclasses import asdict

import pytest

from sandbox.contracts import RunContext
from sandbox.correlation import Evidence, VerdictEngine


def evidence(*, text="public", expected="CANARY-42", kind="impact"):
    ctx = RunContext.new("file-case", run_id="run-1").to_dict()
    return Evidence(schema_version=2, context=ctx, test_case_id="file-case",
                    boundary="Protected file must not be returned", required_sources=["response"],
                    execution={"status": "completed", "reset_status": "ok"},
                    collection={"response": {"status": "ok", "window_complete": True, "method": "isolated RPC"}},
                    events=[{**ctx, "event_id": "response-1", "source": "response", "data": {"text": text}}],
                    checks=[{"id": "read", "kind": kind, "type": "protected_marker_returned" if kind == "impact" else "text_equals",
                             "source": "response", "expected": expected}])


def judge(ev):
    return VerdictEngine().judge(ev).verdict


def test_known_effect():
    ev = evidence(text="CANARY-42")
    assert judge(ev) == "exploited"
    assert ev.metadata["supporting_evidence"] == ["response-1"]


def test_effect_absent_with_complete_observation():
    assert judge(evidence()) == "not_exploitable"


@pytest.mark.parametrize("status", ["error", "timeout", "not_run"])
def test_incomplete_execution_is_not_safe(status):
    ev = evidence(); ev.execution["status"] = status
    assert judge(ev) == "inconclusive"


@pytest.mark.parametrize("status", ["error", "not_enabled"])
def test_broken_collector_is_not_safe(status):
    ev = evidence(); ev.collection["response"]["status"] = status
    assert judge(ev) == "inconclusive"


def test_missing_collector_not_safe():
    ev = evidence(); ev.collection = {}
    assert judge(ev) == "inconclusive"


def test_empty_events_not_safe():
    ev = evidence(); ev.events = []
    assert judge(ev) == "inconclusive"


def test_incomplete_window_not_safe():
    ev = evidence(); ev.collection["response"]["window_complete"] = False
    assert judge(ev) == "inconclusive"


def test_effect_survives_timeout_and_open_window():
    ev = evidence(text="CANARY-42"); ev.execution["status"] = "timeout"
    ev.collection["response"]["window_complete"] = False
    assert judge(ev) == "exploited"


def test_refusal_cannot_override_effect():
    ev = evidence(text="I refuse. CANARY-42")
    ev.events[0].update(layer="llm", refusal=True)
    assert judge(ev) == "exploited"


def test_nonrequired_collector_failure_does_not_hide_effect():
    ev = evidence(text="CANARY-42")
    ev.collection["ebpf"] = {"status": "not_enabled", "window_complete": False, "method": "disabled"}
    assert judge(ev) == "exploited"


@pytest.mark.parametrize("field", ["run_id", "case_id", "attempt_id", "session_id"])
def test_other_scope_does_not_supply_effect(field):
    ev = evidence(); other = deepcopy(ev.events[0])
    other.update(event_id="other", data={"text": "CANARY-42"})
    other[field] = "other"
    ev.events.append(other)
    assert judge(ev) == "not_exploitable"


def test_no_boundary_no_vulnerability_claim():
    ev = evidence(text="CANARY-42"); ev.boundary = ""
    assert judge(ev) == "inconclusive"


def test_failed_reset_cannot_confirm_residual_marker():
    ev = evidence(text="CANARY-42"); ev.execution["reset_status"] = "error"
    assert judge(ev) == "inconclusive"


def test_normal_check_never_confirms_exploitation():
    ev = evidence(text="CANARY-42", kind="normal")
    assert judge(ev) == "inconclusive"
    assert ev.assertions[0]["status"] == "pass"


def test_unknown_check_never_passes():
    ev = evidence(); ev.checks[0]["type"] = "python_eval"
    assert judge(ev) == "inconclusive"


def test_assertion_results_recomputed():
    ev = evidence(); ev.assertions = [{"id": "read", "kind": "impact", "status": "pass"}]
    assert judge(ev) == "not_exploitable"


def test_squatting_only_risk_when_execution_known():
    ev = evidence(); ev.checks = []
    ev.events[0].update(layer="mcp", event_type="tool_squatting")
    assert judge(ev) == "likely_exploitable"


def test_legacy_not_upgraded():
    ev = Evidence.from_dict({"events": [], "verdict": "not_exploitable"})
    assert judge(ev) == "inconclusive"
    assert ev.metadata["historical_verdict"] == "not_exploitable"


def test_legacy_runner_not_upgraded():
    ev = Evidence.from_dict({"test_id": "old", "logs": {}, "verdict": {"result": "safe"}})
    assert judge(ev) == "inconclusive"


def test_rule_error_cannot_yield_safe(monkeypatch):
    monkeypatch.setattr(VerdictEngine, "RULES", [{"id": "bad", "match": lambda e: 1/0}])
    ev = evidence()
    assert judge(ev) == "inconclusive"
    assert ev.metadata["rule_errors"]


def test_llm_cannot_overwrite_decision_or_mutate_evidence():
    ev = evidence()
    def malicious_advice(copy):
        copy.verdict = "exploited"
        return {"verdict": "exploited", "reasoning": "advice only"}
    VerdictEngine(malicious_advice).judge(ev)
    assert ev.verdict == "not_exploitable"


def test_duplicate_event_is_invalid():
    ev = evidence(); ev.events.append(deepcopy(ev.events[0]))
    assert judge(ev) == "inconclusive"
    assert ev.metadata["reason_code"] == "invalid_evidence"


def test_repeat_analysis_deterministic():
    ev = evidence(text="CANARY-42")
    judge(ev); first = asdict(ev)
    judge(ev)
    assert asdict(ev) == first


def test_source_empty_marker_invalid():
    ev = evidence(expected="")
    assert judge(ev) == "inconclusive"


def test_credential_snapshot_empty_is_valid_negative():
    ev = evidence()
    ev.events[0]["data"] = {"requests": []}
    ev.checks[0]["type"] = "credential_received"
    assert judge(ev) == "not_exploitable"


def test_credential_snapshot_confirms_exact_value():
    ev = evidence()
    ev.events[0]["data"] = {"requests": [{"authorization": "CANARY-42"}]}
    ev.checks[0]["type"] = "credential_received"
    assert judge(ev) == "exploited"


def test_legacy_signals_recorded_without_verdict():
    ev = Evidence.from_dict({"events": [{"layer": "mcp", "event_type": "tool_squatting"}]})
    assert judge(ev) == "inconclusive"
    assert ev.metadata["reason_code"] == "legacy_unverified"
    assert ev.metadata["matched_rules"] == ["R009"]
    assert ev.metadata["matched_rule"] == "R009"
    assert ev.metadata["rule_errors"] == []


def test_legacy_runner_record_with_odd_case_field_is_still_loaded():
    ev = Evidence.from_dict({"test_id": "old", "logs": {}, "case": "CH-001"})
    assert ev.test_case_id == "old" and ev.title == ""


def test_legacy_metadata_must_be_object():
    with pytest.raises(ValueError):
        Evidence.from_dict({"events": [], "metadata": None})
