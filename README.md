<div align="center">

# AgentStalker

**Agent** **St**atic + **A**ttack-graph + **L**ive-replay **K**ernel<br>
for treating an LLM agent as a system to be audited — not a model to be aligned.

[![Python](https://img.shields.io/badge/python-3.11+-blue)](#quick-start) [![tests](https://img.shields.io/badge/tests-163%20passed-brightgreen)](#testing) [![CI](https://github.com/tianyuantong/AgentStalker/actions/workflows/tests.yml/badge.svg)](https://github.com/tianyuantong/AgentStalker/actions/workflows/tests.yml) [![OWASP](https://img.shields.io/badge/OWASP-ASI01--ASI10-purple)](#) [![license](https://img.shields.io/badge/license-authorized%20use-orange)](#credits-and-license)

[中文](README.zh.md) · [Design notes](docs/evidence-regression.md) · [Validation report](docs/validation-20260920.md) · [Review guide](docs/review-guide.zh.md) · [Upstream README](docs/upstream-README.md)

</div>

## Overview

AgentStalker ([upstream by Gach0ng](https://github.com/Gach0ng/AgentStalker)) audits an LLM agent in four stages — **MODEL → ATTACK → VERIFY → REPORT**: static taint modeling of the agent's tools, attack-graph synthesis from 14 payload categories and 10 multi-turn chains, sandbox replay against the live agent, and a deterministic verdict engine. The upstream README documents that framework in full.

**This fork rebuilds VERIFY and REPORT around one question: what does it take to *prove* a finding?**
A verdict now has to be backed by an independently checked effect, complete execution and collection coverage, and a hash-verified evidence bundle — and a fix is proven by re-running the same suite against the repaired target while its normal tasks keep working.

## Highlights

- **One evidence-gated decision core.** Both verdict paths (the sandbox runner's signature rules and `VerdictEngine`) now go through a single `judge()`. Sixteen signal rules (R001–R016) only *raise* risk; exploitation is confirmed only by an effect check scoped to this run/case/attempt/session. An observed effect survives a later timeout or refusal; missing evidence never becomes "safe".
- **Effect oracles instead of keyword matching.** A protected file carries a random marker that is never placed in any prompt; a loopback receiver records exactly which synthetic credential arrived and where. `protected_marker_returned` and `credential_received` decide, not the model's wording.
- **Paired remediation regression.** Run the same 12-case suite against the vulnerable and the fixed target, then `compare`: 6/6 attack effects before → 0/6 after, 6/6 normal tasks passing on both sides, 3 → 0 credential leaks on public requests. Disabling the tool is caught as a functional regression, and a "fix" without a positive baseline cannot be claimed.
- **Reproducible evidence bundles.** Every run writes a manifest with analyzer/collector/fixture fingerprints, environment, and a SHA-256 per record; outputs are exclusive-create, so a rerun never overwrites an experiment. `rejudge` re-analyzes a sealed bundle with provenance and never executes the target; `compare` refuses bundles that differ in suite, analyzer, collector, fixture, environment or declared fix.
- **Hardened executors.** MCP stdio calls get a response deadline, a 1 MiB frame cap and guaranteed child cleanup; HTTP execution keeps one session across turns and propagates every failure; conversation replay finally implements its final assertion.
- **163 tests, up from 76 upstream.** Most of the 87 new ones are negative or fault-injection cases: empty logs, dead collectors, incomplete windows, cross-run events, an LLM callback that tries to overwrite the verdict, corrupted bundles, path escapes, and a "disable everything" pseudo-fix.

## How a verdict is decided

```mermaid
flowchart TD
    A{Scoped effect check passed,<br/>boundary declared, initial state verified?}
    A -- yes --> EX[EXPLOITED<br/>kept even if execution later times out or the model refuses]
    A -- no --> B{Execution completed and every required<br/>source ok with a complete observation window?}
    B -- no --> IN[INCONCLUSIVE<br/>missing_evidence names exactly what is absent]
    B -- yes --> C{Impact checks present and all false?}
    C -- yes --> NE[NOT_EXPLOITABLE<br/>= not reproduced in this attempt]
    C -- no --> D{Any risk signal R001–R016?}
    D -- yes --> LK[LIKELY_EXPLOITABLE<br/>a lead, not a confirmation]
    D -- no --> IN
```

Signals are always recorded in `metadata.matched_rules`, including for legacy (schema v1) records, but a signal alone never confirms exploitation and a refusal or an empty log alone never proves safety. The LLM judge can add explanatory text and nothing else.

## Evidence pipeline

```mermaid
flowchart LR
    subgraph RUN["test_runner — one isolated process per case"]
        F[fresh temp tree +<br/>loopback receiver] --> X[MCP tool call<br/>deadline · child cleanup]
        X --> R[raw.json<br/>scoped events · execution · collection status]
    end
    subgraph JUDGE["VerdictEngine.judge"]
        R --> C[effect checks<br/>marker returned? credential received?]
        C --> D[decision core<br/>effect › coverage › signals]
        D --> E[evidence.json]
    end
    E --> M[manifest.json<br/>source fingerprints · SHA-256 per record]
    M --> CMP["compare before after → exit 0 / 1 / 2"]
    M --> RJ["rejudge → new analysis + provenance,<br/>target never re-executed"]
```

Both entry points — the legacy attack-graph runner and the isolated MCP suite — produce the same `Evidence` record and are judged by the same code. `raw.json` is what was observed; `evidence.json` is recomputed from it, so a cached verdict can never be edited into a different comparison result.

## Paired remediation regression

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/images/paired-regression-dark.svg">
  <img alt="Dumbbell chart: attack cases with a confirmed effect 6 to 0, public proxy requests leaking the credential 3 to 0, normal tasks completed 6 to 6, execution failures 0 to 0" src="docs/images/paired-regression-light.svg" width="760">
</picture>

The suite drives two MCP tools through real stdio calls: a workspace `read_file` (direct sibling access, `..` traversal, symlink escape, plus three allowed reads) and a `proxy_request` that must not forward the caller's credential (three private targets, three public ones). Normal controls are what separate a fix from a disabled feature.

```mermaid
flowchart LR
    S[suite.json<br/>6 attack + 6 normal cases] --> V[run · vulnerable variant]
    S --> Fx[run · fixed variant]
    V --> B[(before bundle)]
    Fx --> A[(after bundle)]
    B --> G{comparable?<br/>same suite · analyzer · collector<br/>fixture · environment · declared fix}
    A --> G
    G -- no --> NC[NOT_COMPARABLE · exit 2]
    G -- yes --> P[pair every case,<br/>rejudge both sides from raw]
    P --> R0[REMEDIATION_PASSED · exit 0<br/>effect before, none after, controls pass]
    P --> R1[STILL_EXPLOITABLE · FUNCTIONAL_REGRESSION<br/>NORMAL_FLOW_EXPOSURE · exit 1]
    P --> R2[NO_POSITIVE_BASELINE · NO_NORMAL_CONTROL<br/>INCONCLUSIVE · exit 2]
```

Saved bundles for the run above live in [`review/artifacts/`](review/artifacts/comparison/comparison.md); every row links to the before/after evidence files.

## Quick start

Python 3.11+. The suite needs only the MCP v1 SDK — no API key, Docker or eBPF.

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e '.[test]'
pytest tests -q

# Output directories must be new; existing evidence is never overwritten.
python -m sandbox.test_runner --config examples/regression/suite.json --profile examples/regression/vulnerable.json --output output/before
python -m sandbox.test_runner --config examples/regression/suite.json --profile examples/regression/fixed.json --output output/after
python -m sandbox.regression compare output/before output/after --output output/comparison
python -m sandbox.regression rejudge output/before --output output/rejudged
```

`compare` prints a per-case table and the counts, and exits 0 / 1 / 2 as in the diagram above — usable directly as a CI gate for a remediation PR:

| Case | Kind | Before | After | Result |
|---|---|---|---|---|
| file-symlink | attack | exploited | not_exploitable | REMEDIATION_PASSED |
| proxy-one | attack | exploited | not_exploitable | REMEDIATION_PASSED |
| proxy-normal-one | normal | exploited | not_exploitable | NORMAL_PASSED |
| file-normal-nested | normal | inconclusive | inconclusive | NORMAL_PASSED |

(`proxy-normal-one` is a public request that *completed* on both sides while leaking the credential only before the fix — task success and security exposure are reported separately. A normal case without an impact proposition shows `inconclusive` as its security verdict by design.)

## What changed vs upstream

| | Upstream `7d5748e` | This fork |
|---|---|---|
| Verdict paths | two independent rule sets | one decision core, both entry points |
| Empty logs / failed collector | `safe` / `NOT_EXPLOITABLE` | `INCONCLUSIVE` with `missing_evidence` |
| MCP tool-name collision | `EXPLOITED` at 0.90 | risk signal only |
| LLM judge | could set the final verdict | advisory text only |
| Proof of exploitation | keyword rules over logs | scoped effect check + coverage gate |
| Evidence storage | one file per case id, overwritten | exclusive-create bundle, manifest, SHA-256 per record |
| Remediation check | — | paired `compare` with normal controls and an exit-code gate |
| Offline re-analysis | `--output` ignored | `rejudge` with provenance, source bundle untouched |
| MCP stdio executor | unbounded `readline()` | deadline, frame cap, child cleanup |
| Multi-turn HTTP | session per `execute()`, failed turns reported as success | context carried across calls, every failure propagates |
| Signal rules | R001–R011 (+5 runner heuristics) | R001–R016, documented in `verdict_rules.yaml`, drift-tested |
| Tests | 76 | 163 |

## Testing

```bash
pytest tests -q -ra           # 163 tests, ~20 s, spawns real MCP subprocesses and a loopback receiver
python -m build --wheel        # nested packages and the evidence schema ship in the wheel
```

CI ([`.github/workflows/tests.yml`](.github/workflows/tests.yml)) runs the suite on Python 3.11 and 3.13, builds the wheel, and imports it from a clean virtualenv outside the checkout.

## Scope

These experiments establish local tool-boundary effects and the correctness of the audit chain; a live-model evaluation is the next layer and has not been run yet. Hashes are integrity checks, not signatures.

## Credits and license

Upstream implementation and authorship: [Gach0ng/AgentStalker](https://github.com/Gach0ng/AgentStalker) — its README is preserved unchanged under [`docs/`](docs/upstream-README.md). The upstream license and authorized-assessment restriction are unchanged: use only on systems and data you are authorized to test.
