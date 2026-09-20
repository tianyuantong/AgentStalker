# Evidence and remediation design

## Problem and scope

The baseline `7d5748e` has two independent decision paths. The legacy runner treats no matching signatures as safe; the correlation engine treats empty events as not exploitable and MCP name collisions as exploited. Collection failures can look like empty results. Conversation replay has an unimplemented final assertion and can report success after failure.

This change uses one decision core and three new production modules: `contracts.py`, `assertions.py`, `regression.py`. It keeps existing analysis and execution entry points. No business application, new rule DSL, gateway, database or external service is added. The original Chinese design is preserved in [design/plan-2026-09-20.zh.md](design/plan-2026-09-20.zh.md).

## Data and trust boundary

`Evidence` remains the canonical class. Version 2 adds context (run/case/attempt/session), execution and reset status, per-source collection status, required sources, the declared permission boundary, check specifications and recomputed assertion results. Events have a unique ID, source, scoped identity and recorded data. The producer is trusted to report those observations faithfully; artifact hashes provide integrity checking against an unchanged manifest, not authenticity against a malicious author who rewrites both.

A collector status of `ok` differs from an empty snapshot. Each collector states its method and whether the observation window ended. The two fixture checks use a matching synchronous MCP response and a dedicated HTTP receiver. No timestamp-nearness inference is used. Temporary trees and receivers are recreated per case; no secret is supplied in the attack arguments. The SDK child receives a minimal environment with synthetic credentials.

`assertions.py` checks protected marker return, credential receipt, normal response equality and credential absence. Checks return pass/fail/unknown with event references. A normal check passing never confirms exploitation. Unsupported names and malformed values cannot pass. Stored assertion results are recomputed from raw observations.

## Decision order

1. Structurally valid scoped effect evidence plus an explicit boundary and verified initial state confirms impact. Later timeout/refusal or failure of unrelated collectors does not erase it.
2. Without positive confirmation, incomplete execution, missing necessary collection, unknown assertions or rule errors remain inconclusive.
3. Completed and observed impact checks all false mean “not reproduced in this attempt”.
4. Remaining risk signals are unconfirmed findings, not exploitation. Refusal and empty events alone are not sufficient.

Rules R001–R011 are retained as signals, and the legacy runner's five heuristics (dangerous execve, metadata endpoint, external mail, DB change, prompt-leak text) become R012–R016 over events normalized from its global logs. Signals are evaluated for every record, including legacy v1 input, and recorded as `matched_rules`; only v2 records with coverage can turn them into a verdict. The Python definitions are executable; YAML is documentation only and a test keeps the two lists identical. LLM callbacks receive a copy and may add explanatory text but cannot set verdicts. Rule confidence values are uncalibrated heuristics.

## Compatibility

- `Evidence.from_dict()` accepts existing Evidence JSON and the old runner's `logs` format. Historical verdicts are retained in metadata; absent execution/collection coverage is not fabricated.
- Legacy v1 evidence becomes `legacy_unverified`, even if previously called safe/exploited; its risk signals are still listed in `matched_rules`. Existing callers can add proper v2 coverage to regain definitive judgments.
- `test_runner.judge_verdict()` maps the central result to the old output labels; it does not maintain separate rules. Legacy global collectors now report error envelopes, but remain unscoped and cannot establish negative conclusions.
- The runner now requires an explicit new output directory. Existing output is never replaced. The correlation CLI honors `--output` and also refuses overwrite.
- The original `api_executor --attack-graph` CLI and side-effect probe method are retained. They report transport/task observations, not an unsupported safe/exploited verdict.
- API/replay keep public class names. Context can be passed across turns; task assertions are separate from safety, unknown assertion types no longer pass, and errors propagate. Configure `session_field` when a target uses `conversation_id` instead of `session_id`.
- MCP calls have response deadlines and child cleanup. Tool-level errors are execution errors. SDK v1 is bounded as `mcp<2` because the original fixture imports `mcp.server.fastmcp`.
- Nested packages and the evidence schema are included in the built wheel. The standalone `fastmcp` dependency was redundant and is no longer required.

## Paired runs and offline analysis

The manifest stores suite/fixture/config fingerprints, analyzer and collector source hashes, target variant, declared remediation, Python/dependency versions and file digests. Dirty development commits are labeled; source content hashes identify the code actually used, including uncommitted new modules. The supplied profile explicitly has no model; a non-null model label is rejected because this path does not execute an LLM.

`compare` verifies complete inventories, identities and file hashes before comparing. The suite, checker/collector, initial-state definition, permissions, environment and budget must match. The target variant may change only with a declared source and destination variant and explanation. Runtime IDs, temporary paths and random synthetic values differ by design and are not compared as invariant configuration.

Comparison requires a positively reproduced baseline and functioning normal controls in the same group. Disabled tools fail the normal controls (`NORMAL_CONTROL_FAILED`, exit 1); a group that planned no control at all is `NO_NORMAL_CONTROL` (exit 2), incomplete rather than regressed. Both variants' raw records are rejudged by the same current analyzer. Code drift requires explicit new experiments or separately labeled rejudging; the tool will not silently attribute a detector change to a target fix.

`rejudge` verifies the source bundle and writes new analysis/provenance only. It never contacts the target and never edits the original bundle. Its output cannot be passed off as a new execution.

## Fixture and validation limits

The separate regression server preserves the original vulnerable fixture unchanged. Both variants restrict all filesystem access to the generated test tree and HTTP to the loopback receiver. Within that tree, the vulnerable variant exposes the protected sibling directory; fixed mode allows only resolved paths under `allowed/`. The proxy fix strips generic credentials and allows only public test endpoints. No actual OAuth token exchange is claimed.

The 12-case local suite contains 6 attack requests and 6 normal task controls. Three proxy attacks are repeated labeled requests, not three independent vulnerability classes. Public normal requests also carry an impact check, so task completion and credential exposure can both be reported. The API/session tests and fault-injection tests exercise error paths separately. Fixed labeled decision tests establish specific invariants, not broad detector accuracy.

No real LLM, CodeWhale rerun, Docker/eBPF integration, arbitrary third-party target, full OAuth workflow or race-resistant production filesystem boundary is validated by this change. A future live-model run must be separately identified with target/model versions, repeated attempts and its own costs and coverage.
