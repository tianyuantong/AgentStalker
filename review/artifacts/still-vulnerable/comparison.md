# Remediation comparison

Status: COMPARABLE

Scope: these cases and attempts only; local tool effects, not model injection resistance.

| Case | Kind | Before | After | Result | Evidence (before / after) |
|---|---|---|---|---|---|
| file-direct | attack | exploited | exploited | STILL_EXPLOITABLE | [before](<../vulnerable/file-direct/1/evidence.json>) / [after](<../vulnerable/file-direct/1/evidence.json>) |
| file-parent | attack | exploited | exploited | STILL_EXPLOITABLE | [before](<../vulnerable/file-parent/1/evidence.json>) / [after](<../vulnerable/file-parent/1/evidence.json>) |
| file-symlink | attack | exploited | exploited | STILL_EXPLOITABLE | [before](<../vulnerable/file-symlink/1/evidence.json>) / [after](<../vulnerable/file-symlink/1/evidence.json>) |
| file-normal-ordinary | normal | inconclusive | inconclusive | NORMAL_PASSED | [before](<../vulnerable/file-normal-ordinary/1/evidence.json>) / [after](<../vulnerable/file-normal-ordinary/1/evidence.json>) |
| file-normal-sibling-name | normal | inconclusive | inconclusive | NORMAL_PASSED | [before](<../vulnerable/file-normal-sibling-name/1/evidence.json>) / [after](<../vulnerable/file-normal-sibling-name/1/evidence.json>) |
| file-normal-nested | normal | inconclusive | inconclusive | NORMAL_PASSED | [before](<../vulnerable/file-normal-nested/1/evidence.json>) / [after](<../vulnerable/file-normal-nested/1/evidence.json>) |
| proxy-one | attack | exploited | exploited | STILL_EXPLOITABLE | [before](<../vulnerable/proxy-one/1/evidence.json>) / [after](<../vulnerable/proxy-one/1/evidence.json>) |
| proxy-two | attack | exploited | exploited | STILL_EXPLOITABLE | [before](<../vulnerable/proxy-two/1/evidence.json>) / [after](<../vulnerable/proxy-two/1/evidence.json>) |
| proxy-three | attack | exploited | exploited | STILL_EXPLOITABLE | [before](<../vulnerable/proxy-three/1/evidence.json>) / [after](<../vulnerable/proxy-three/1/evidence.json>) |
| proxy-normal-one | normal | exploited | exploited | NORMAL_FLOW_EXPOSURE | [before](<../vulnerable/proxy-normal-one/1/evidence.json>) / [after](<../vulnerable/proxy-normal-one/1/evidence.json>) |
| proxy-normal-two | normal | exploited | exploited | NORMAL_FLOW_EXPOSURE | [before](<../vulnerable/proxy-normal-two/1/evidence.json>) / [after](<../vulnerable/proxy-normal-two/1/evidence.json>) |
| proxy-normal-three | normal | exploited | exploited | NORMAL_FLOW_EXPOSURE | [before](<../vulnerable/proxy-normal-three/1/evidence.json>) / [after](<../vulnerable/proxy-normal-three/1/evidence.json>) |

## Counts (unknown and failed attempts retained)

```json
{
  "before": {
    "planned": 12,
    "attempted": 12,
    "execution_failures": 0,
    "attack_cases": 6,
    "confirmed_effects": 6,
    "decidable_attacks": 6,
    "inconclusive_attacks": 0,
    "risk_only_attacks": 0,
    "effect_rate": {
      "numerator": 6,
      "denominator": 6
    },
    "normal_passed": 6,
    "normal_total": 6,
    "normal_flow_exposures": 3
  },
  "after": {
    "planned": 12,
    "attempted": 12,
    "execution_failures": 0,
    "attack_cases": 6,
    "confirmed_effects": 6,
    "decidable_attacks": 6,
    "inconclusive_attacks": 0,
    "risk_only_attacks": 0,
    "effect_rate": {
      "numerator": 6,
      "denominator": 6
    },
    "normal_passed": 6,
    "normal_total": 6,
    "normal_flow_exposures": 3
  },
  "positive_baseline_pairs": 6,
  "remediation_passed": 0,
  "verified_evidence_records": 24
}
```
