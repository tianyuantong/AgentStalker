"""Immutable run bundles, offline rejudging and paired remediation comparison."""
from __future__ import annotations

import argparse
from dataclasses import asdict
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys

from sandbox.contracts import canonical_hash, file_hash, load_json, write_json_new
from sandbox.correlation import Evidence, VerdictEngine


ROOT = Path(__file__).resolve().parent.parent


def source_fingerprint(paths):
    return canonical_hash({str(p.relative_to(ROOT)): file_hash(p) for p in sorted(paths)})


def fingerprints():
    base = ROOT / "sandbox"
    return {
        "analyzer": source_fingerprint([base / "contracts.py", base / "assertions.py",
                                        base / "correlation/__init__.py", base / "regression.py", base / "evidence.schema.json"]),
        "collector": source_fingerprint([base / "test_runner.py", *sorted((base / "executors").glob("*.py"))]),
    }


def revision():
    try:
        commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, stderr=subprocess.DEVNULL, text=True).strip()
        dirty = subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT, text=True).strip()
        return {"commit": commit, "dirty": bool(dirty)}
    except (OSError, subprocess.CalledProcessError):
        return {"commit": "unavailable-installed-package", "dirty": None}


def environment():
    deps = {}
    for name in ("mcp", "requests", "pyyaml", "jinja2", "regex"):
        try:
            deps[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            deps[name] = "not-installed"
    return {"python": platform.python_version(), "system": platform.system(), "dependencies": deps}


def new_manifest(suite, profile, run_id):
    """Profiles declare only variant changes; invariants must match before comparison."""
    fixture = ROOT / "testbeds/mcp_mini_server/regression_server.py"
    return {
        "schema_version": 2, "run_id": run_id, "audit_revision": revision(),
        "comparison": {**fingerprints(), "suite": canonical_hash(suite),
                       "fixture": file_hash(fixture), "environment": environment(),
                       "invariants": {k: v for k, v in profile.items() if k not in {"variant", "remediation"}}},
        "suite": suite,
        "target": {"variant": profile["variant"], "fingerprint": canonical_hash({"fixture": file_hash(fixture), "variant": profile["variant"]})},
        "remediation": profile.get("remediation"),
        "planned_cases": len(suite["cases"]), "records": [],
    }


def save_record(root, manifest, raw: Evidence):
    case_id = raw.test_case_id
    attempt = raw.context["attempt_id"]
    for value in (case_id, attempt):
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,99}", value):
            raise ValueError("unsafe case/attempt path")
    relative = Path(case_id) / attempt
    raw_path = relative / "raw.json"
    judged_path = relative / "evidence.json"
    write_json_new(Path(root) / raw_path, asdict(raw))
    judged = VerdictEngine().judge(Evidence.from_dict(asdict(raw)))
    write_json_new(Path(root) / judged_path, asdict(judged))
    manifest["records"].append({"case_id": case_id, "attempt_id": attempt,
                                "raw": raw_path.as_posix(), "raw_sha256": file_hash(Path(root) / raw_path),
                                "judged": judged_path.as_posix(), "judged_sha256": file_hash(Path(root) / judged_path)})
    return judged


def _artifact(root, name, expected_hash):
    if not isinstance(name, str) or Path(name).is_absolute():
        raise ValueError("invalid artifact path")
    path = (root / name).resolve()
    if not path.is_relative_to(root.resolve()) or not path.is_file():
        raise ValueError("artifact escaped bundle or is missing")
    if file_hash(path) != expected_hash:
        raise ValueError(f"artifact hash mismatch: {name}")
    return path


def read_run(root):
    root = Path(root)
    manifest = load_json(root / "manifest.json")
    if manifest.get("schema_version") != 2 or not isinstance(manifest.get("records"), list):
        raise ValueError("invalid run manifest")
    cases = manifest.get("suite", {}).get("cases", [])
    case_ids = [c["id"] for c in cases]
    if not case_ids or len(set(case_ids)) != len(case_ids):
        raise ValueError("invalid suite inventory")
    if manifest["comparison"]["suite"] != canonical_hash(manifest["suite"]):
        raise ValueError("suite fingerprint mismatch")
    if manifest["planned_cases"] != len(cases) or len(manifest["records"]) != len(cases):
        raise ValueError("incomplete run inventory")
    loaded, seen = [], set()
    case_map = {c["id"]: c for c in cases}
    for record in manifest["records"]:
        case_id = record["case_id"]
        if case_id not in case_map or case_id in seen:
            raise ValueError("duplicate/unplanned case")
        seen.add(case_id)
        path = _artifact(root, record["raw"], record["raw_sha256"])
        _artifact(root, record["judged"], record["judged_sha256"])
        ev = Evidence.from_dict(load_json(path))
        if (ev.context["run_id"] != manifest["run_id"] or ev.test_case_id != case_id
                or ev.context["attempt_id"] != record["attempt_id"]):
            raise ValueError("manifest/evidence identity mismatch")
        if (ev.metadata.get("case_kind") != case_map[case_id]["kind"]
                or ev.metadata.get("group") != case_map[case_id]["group"]):
            raise ValueError("case classification mismatch")
        if ev.metadata.get("case_template_hash") != canonical_hash(case_map[case_id]):
            raise ValueError("case template hash mismatch")
        loaded.append(ev)
    return manifest, loaded


def normal_ok(ev):
    return (ev.execution.get("status") == "completed" and ev.execution.get("reset_status") == "ok"
            and all(ev.collection.get(s, {}).get("status") == "ok"
                    and ev.collection[s].get("window_complete") is True for s in ev.required_sources)
            and any(a["kind"] == "normal" for a in ev.assertions)
            and all(a["status"] == "pass" for a in ev.assertions if a["kind"] == "normal"))


def summarize(evidences):
    attacks = [e for e in evidences if e.metadata.get("case_kind") == "attack"]
    normals = [e for e in evidences if e.metadata.get("case_kind") == "normal"]
    confirmed = sum(e.verdict == "exploited" for e in attacks)
    decidable = sum(e.verdict in {"exploited", "not_exploitable"} for e in attacks)
    return {"planned": len(evidences), "attempted": sum(e.execution.get("status") != "not_run" for e in evidences),
            "execution_failures": sum(e.execution.get("status") != "completed" for e in evidences),
            "attack_cases": len(attacks), "confirmed_effects": confirmed, "decidable_attacks": decidable,
            "inconclusive_attacks": sum(e.verdict == "inconclusive" for e in attacks),
            "risk_only_attacks": sum(e.verdict == "likely_exploitable" for e in attacks),
            "effect_rate": {"numerator": confirmed, "denominator": decidable},
            "normal_passed": sum(normal_ok(e) for e in normals), "normal_total": len(normals),
            "normal_flow_exposures": sum(e.verdict == "exploited" for e in normals)}


# Exit codes: 0 effective, 1 confirmed exposure or functional regression,
# 2 incomplete/incomparable evidence. Missing evidence is never reported as 1.
def _classify_normal(after, before):
    if after.verdict == "exploited":
        return "NORMAL_FLOW_EXPOSURE", 1
    if after.execution.get("status") != "completed" or any(a["status"] == "unknown" for a in after.assertions):
        return "INCONCLUSIVE", 2
    if normal_ok(after) and normal_ok(before):
        return "NORMAL_PASSED", 0
    if not normal_ok(before):
        return "BASELINE_NORMAL_FAILED", 2
    return "FUNCTIONAL_REGRESSION", 1


def _classify_attack(after, before, group_controls):
    if after.verdict == "exploited":
        if before.verdict == "exploited":
            return "STILL_EXPLOITABLE", 1
        return ("SECURITY_REGRESSION" if before.verdict == "not_exploitable" else "CONFIRMED_AFTER"), 1
    if after.verdict != "not_exploitable" or after.execution.get("status") != "completed":
        return "INCONCLUSIVE", 2
    if before.verdict != "exploited":
        return "NO_POSITIVE_BASELINE", 2
    if group_controls is None:
        return "NO_NORMAL_CONTROL", 2  # nothing was planned to prove the tool still works
    if not all(group_controls):
        return "NORMAL_CONTROL_FAILED", 1
    return "REMEDIATION_PASSED", 0


def compare(before_root, after_root):
    before, left = read_run(before_root)
    after, right = read_run(after_root)
    diffs = [key for key in set(before["comparison"]) | set(after["comparison"])
             if before["comparison"].get(key) != after["comparison"].get(key)]
    current = fingerprints()
    if any(before["comparison"].get(k) != v for k, v in current.items()):
        diffs.append("current_analyzer_or_collector")
    if before["target"] != after["target"]:
        declaration = after.get("remediation") or {}
        if (declaration.get("from_variant") != before["target"]["variant"]
                or not declaration.get("description") or declaration.get("to_variant") != after["target"]["variant"]):
            diffs.append("undeclared_target_change")
    if diffs:
        return {"status": "NOT_COMPARABLE", "differences": sorted(diffs), "rows": [], "exit_code": 2}
    engine = VerdictEngine()
    left = [engine.judge(e) for e in left]
    right = [engine.judge(e) for e in right]
    index = {e.test_case_id: e for e in left}
    # At least one matched normal control must exist in each remediation group.
    controls = {}
    for e in right:
        if e.metadata.get("case_kind") == "normal":
            controls.setdefault(e.metadata["group"], []).append(normal_ok(e) and normal_ok(index[e.test_case_id]))
    rows, codes = [], []
    for e in right:
        prior = index[e.test_case_id]
        kind = e.metadata.get("case_kind")
        if kind != prior.metadata.get("case_kind") or e.metadata.get("group") != prior.metadata.get("group"):
            raise ValueError("case grouping drift")
        status, code = (_classify_normal(e, prior) if kind == "normal"
                        else _classify_attack(e, prior, controls.get(e.metadata.get("group"))))
        rows.append({"case_id": e.test_case_id, "kind": kind, "before": prior.verdict,
                     "after": e.verdict, "result": status,
                     "before_reason": prior.metadata.get("reason_code"), "after_reason": e.metadata.get("reason_code"),
                     "before_execution": prior.execution, "after_execution": e.execution,
                     "before_evidence": next(r["judged"] for r in before["records"] if r["case_id"] == e.test_case_id),
                     "after_evidence": next(r["judged"] for r in after["records"] if r["case_id"] == e.test_case_id)})
        codes.append(code)
    return {"status": "COMPARABLE", "differences": [], "rows": rows,
            "before": summarize(left), "after": summarize(right),
            # Paths exactly as given: bundles travel, the author's filesystem does not.
            "before_run": str(before_root), "after_run": str(after_root),
            "verified_evidence_records": len(left) + len(right),
            "positive_baseline_pairs": sum(e.metadata.get("case_kind") == "attack" and e.verdict == "exploited" for e in left),
            "remediation_passed": sum(r["result"] == "REMEDIATION_PASSED" for r in rows),
            "exit_code": 2 if 2 in codes else 1 if 1 in codes else 0}


def rejudge(root, output):
    manifest, evidences = read_run(root)
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    rows = [asdict(VerdictEngine().judge(e)) for e in evidences]
    write_json_new(output / "rejudged.json", rows)
    write_json_new(output / "provenance.json", {"operation": "rejudge_not_rerun",
                   "source_manifest_sha256": file_hash(Path(root) / "manifest.json"),
                   "source_analyzer": manifest["comparison"]["analyzer"], "current": fingerprints(),
                   "audit_revision": revision()})
    return rows


def write_report(output, result):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    write_json_new(output / "comparison.json", result)
    lines = ["# Remediation comparison", "", f"Status: {result['status']}", "",
             "Scope: these cases and attempts only; local tool effects, not model injection resistance.", ""]
    if result.get("differences"):
        lines += ["Incompatible fields: " + ", ".join(result["differences"]), ""]
    lines += ["| Case | Kind | Before | After | Result | Evidence (before / after) |", "|---|---|---|---|---|---|"]
    for row in result["rows"]:
        links = []
        for side in ("before", "after"):
            target = Path(result[f"{side}_run"]) / row[f"{side}_evidence"]
            links.append(f"[{side}](<{os.path.relpath(target, output)}>)")
        lines.append("| " + " | ".join(str(row[k]).replace("|", "\\|") for k in ("case_id", "kind", "before", "after", "result")) + " | " + " / ".join(links) + " |")
    if "before" in result:
        lines += ["", "## Counts (unknown and failed attempts retained)", "", "```json",
                  json.dumps({k: result[k] for k in ("before", "after", "positive_baseline_pairs", "remediation_passed", "verified_evidence_records")}, indent=2), "```"]
    (output / "comparison.md").write_text("\n".join(lines) + "\n")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    commands = ap.add_subparsers(dest="operation", required=True)
    cmp = commands.add_parser("compare")
    cmp.add_argument("before"); cmp.add_argument("after"); cmp.add_argument("--output", required=True)
    again = commands.add_parser("rejudge")
    again.add_argument("run"); again.add_argument("--output", required=True)
    args = ap.parse_args()
    try:
        if args.operation == "rejudge":
            rows = rejudge(args.run, args.output)
            print(f"Rejudged {len(rows)} cases; no target was executed.")
            return 0
        result = compare(args.before, args.after)
        write_report(args.output, result)
        print(json.dumps(result, indent=2))
        return result["exit_code"]
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"Invalid/incomplete evidence: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
