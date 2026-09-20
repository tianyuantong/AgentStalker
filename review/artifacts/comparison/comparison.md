# Remediation comparison

Status: COMPARABLE

Scope: these cases and attempts only; local tool effects, not model injection resistance.

| Case | Kind | Before | After | Result | Evidence (before / after) |
|---|---|---|---|---|---|
| file-direct | attack | exploited | not_exploitable | REMEDIATION_PASSED | [before](<../vulnerable/file-direct/1/evidence.json>) / [after](<../fixed/file-direct/1/evidence.json>) |
| file-parent | attack | exploited | not_exploitable | REMEDIATION_PASSED | [before](<../vulnerable/file-parent/1/evidence.json>) / [after](<../fixed/file-parent/1/evidence.json>) |
| file-symlink | attack | exploited | not_exploitable | REMEDIATION_PASSED | [before](<../vulnerable/file-symlink/1/evidence.json>) / [after](<../fixed/file-symlink/1/evidence.json>) |
| file-normal-ordinary | normal | inconclusive | inconclusive | NORMAL_PASSED | [before](<../vulnerable/file-normal-ordinary/1/evidence.json>) / [after](<../fixed/file-normal-ordinary/1/evidence.json>) |
| file-normal-sibling-name | normal | inconclusive | inconclusive | NORMAL_PASSED | [before](<../vulnerable/file-normal-sibling-name/1/evidence.json>) / [after](<../fixed/file-normal-sibling-name/1/evidence.json>) |
| file-normal-nested | normal | inconclusive | inconclusive | NORMAL_PASSED | [before](<../vulnerable/file-normal-nested/1/evidence.json>) / [after](<../fixed/file-normal-nested/1/evidence.json>) |
| proxy-one | attack | exploited | not_exploitable | REMEDIATION_PASSED | [before](<../vulnerable/proxy-one/1/evidence.json>) / [after](<../fixed/proxy-one/1/evidence.json>) |
| proxy-two | attack | exploited | not_exploitable | REMEDIATION_PASSED | [before](<../vulnerable/proxy-two/1/evidence.json>) / [after](<../fixed/proxy-two/1/evidence.json>) |
| proxy-three | attack | exploited | not_exploitable | REMEDIATION_PASSED | [before](<../vulnerable/proxy-three/1/evidence.json>) / [after](<../fixed/proxy-three/1/evidence.json>) |
| proxy-normal-one | normal | exploited | not_exploitable | NORMAL_PASSED | [before](<../vulnerable/proxy-normal-one/1/evidence.json>) / [after](<../fixed/proxy-normal-one/1/evidence.json>) |
| proxy-normal-two | normal | exploited | not_exploitable | NORMAL_PASSED | [before](<../vulnerable/proxy-normal-two/1/evidence.json>) / [after](<../fixed/proxy-normal-two/1/evidence.json>) |
| proxy-normal-three | normal | exploited | not_exploitable | NORMAL_PASSED | [before](<../vulnerable/proxy-normal-three/1/evidence.json>) / [after](<../fixed/proxy-normal-three/1/evidence.json>) |

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
    "confirmed_effects": 0,
    "decidable_attacks": 6,
    "inconclusive_attacks": 0,
    "risk_only_attacks": 0,
    "effect_rate": {
      "numerator": 0,
      "denominator": 6
    },
    "normal_passed": 6,
    "normal_total": 6,
    "normal_flow_exposures": 0
  },
  "positive_baseline_pairs": 6,
  "remediation_passed": 6,
  "verified_evidence_records": 24
}
```
