# Validation — 2026-09-20

Base: `7d5748e71163eefa473f0a23f460d6f8aa2556ae` (upstream HEAD). The saved bundles under `review/artifacts/` were generated from commit `8684f1f` of this branch with a clean tree (`audit_revision.dirty: false`); every manifest also fingerprints the analyzer, collector and fixture sources that actually ran, so `compare` refuses them once those files change.

## Baseline and tests

| Check | Observed result | Evidence |
|---|---|---|
| Original suite, original unconstrained dependencies | 73 passed, 3 failed | [Baseline output](../review/baseline-tests.txt), [environment](../review/baseline-environment.txt) |
| Final full suite | 163 passed, 0 failed, 0 skipped | [Test output](../review/final-tests.txt), [JUnit](../review/final-tests.xml) |
| Wheel build | Successful | [Build log](../review/build.txt) |
| Fresh wheel installation outside checkout | Imports resolved to site-packages; 4-case paired suite (file and proxy attack plus their normal controls) passed from the installed package; pip check passed | [Install check](../review/install-check.txt) |
| CLI negative gates | Still-vulnerable=1; no positive baseline=2; rejudge overwrite=2 | [Recorded exits](../review/negative-cli-checks.json) |

Baseline failure cause: installing the original `mcp>=1.0` selected SDK 2.2.0, where `mcp.server.fastmcp` is removed. The implementation uses the v1 API and now constrains `mcp<2`. The verified environment used MCP 1.30.0 and Python 3.13.12 on macOS. This is separate from the fixes to evidence semantics. Baseline failures are retained rather than omitted.

A GitHub Actions workflow for Python 3.11/3.13 is included; the recorded checks above were executed locally on Python 3.13.12 / macOS. [Clean installed dependency versions](../review/requirements-verified.txt) are included for reproduction.

## Real local paired experiments

The saved run invokes the MCP SDK server as a subprocess and creates actual temporary files and a real loopback HTTP receiver. All credentials and protected markers are generated synthetic values. No real user files, external target, real model, cloud service or broker is used.

| Measurement | Vulnerable | Fixed |
|---|---:|---:|
| Planned / attempted cases | 12 / 12 | 12 / 12 |
| Execution failures | 0 | 0 |
| Attack cases with confirmed effects | 6 / 6 | 0 / 6 |
| Decidable attack cases | 6 / 6 | 6 / 6 |
| Inconclusive attack cases | 0 | 0 |
| Normal task completion | 6 / 6 | 6 / 6 |
| Credential exposure during normal public proxy requests | 3 | 0 |

Six paired attack cases pass remediation checks with working normal controls. The three proxy attack requests are repeated instances of the same mechanism, not three distinct vulnerability classes. Normal task completion and security exposure are deliberately separate: the vulnerable proxy completes its task while also forwarding a synthetic credential.

- [Paired report with evidence links](../review/artifacts/comparison/comparison.md)
- [Machine-readable comparison](../review/artifacts/comparison/comparison.json)
- [Vulnerable manifest](../review/artifacts/vulnerable/manifest.json)
- [Fixed manifest](../review/artifacts/fixed/manifest.json)
- [Offline rejudging provenance](../review/artifacts/rejudged/provenance.json)
- [Demonstration command transcript](../review/demo-run.txt)

The two manifests contain 24 verified raw records and 24 corresponding judged records. Temporary paths in the raw observations describe the original execution; those temporary trees have been removed. Offline verification uses the saved observations and file hashes, not those paths. For a new execution, fixtures are recreated with new identifiers and synthetic values.

## Cases and limits

File cases exercise direct sibling-directory access, `..` and a symbolic-link escape. Normal controls read ordinary, similarly named and nested allowed files. Proxy cases demonstrate actual synthetic Authorization receipt at an unauthorized endpoint and subsequent absence after repair; public proxy responses remain correct. A separate automated test verifies that disabling all tools fails functional-regression checks.

Additional tests cover scoped event isolation, failed/missing collectors, incomplete windows, refusal-plus-effect, timeout-plus-effect, unknown assertions, legacy records and legacy-runner signals (R012–R016), rule-documentation drift, LLM advisory boundaries, damaged bundles, changed settings, incomplete inventories, repeated outputs, attack groups without a planned control, portable report paths, actual MCP child exit/deadline handling, Windows-safe command splitting, execution status on every executor and multi-turn session continuity.

These results prove the listed local invariants and tool-boundary experiments. They do not measure real-model prompt-injection resistance, general vulnerability detection accuracy, CodeWhale exploitability, full eBPF/Docker integration, arbitrary OAuth behavior or race-resistant filesystem security. The original broad static audit remains a risk-discovery layer. Legacy unscoped collectors remain explicitly inconclusive.
