# Fixture labels and interpretation

These labels come from the declared tool boundaries and the deliberately different fixture implementations. They are not produced by the detector, and they are not input verdicts supplied to `VerdictEngine`.

| Cases | Vulnerable target | Fixed target | Independent evidence |
|---|---|---|---|
| `file-direct`, `file-parent`, `file-symlink` | Protected marker returned | Protected marker not returned | Actual MCP tool response; marker exists only in the sibling protected file before execution |
| `file-normal-ordinary`, `file-normal-sibling-name`, `file-normal-nested` | Normal task passes | Normal task passes | Exact public file content; no security-impact claim is made from the normal assertion alone |
| `proxy-one`, `proxy-two`, `proxy-three` | Synthetic credential reaches private test endpoint | No such credential receipt | Dedicated receiver request snapshot after synchronous tool completion |
| `proxy-normal-one`, `proxy-normal-two`, `proxy-normal-three` | Normal task passes AND credential exposure occurs | Normal task passes, credential exposure absent | Exact response plus receiver Authorization observation |

The three proxy attack cases repeat one mechanism with distinct requests. They are not independent vulnerability categories. The fixed file normals can have an inconclusive security verdict (no impact proposition was requested) while still passing their normal-task check; task success and security conclusions are separate.

Fault tests live in `tests/test_evidence_decisions.py`, `tests/test_execution_states.py` and `tests/test_regression.py`. They are not removed from an attack-success denominator to improve a headline number; execution failures and inconclusive counts are reported separately. Handwritten negative tests for known-safe propositions support specific regression claims, not population-wide false-positive rates.
