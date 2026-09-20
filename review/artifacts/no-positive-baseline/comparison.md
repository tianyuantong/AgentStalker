# Remediation comparison

Status: COMPARABLE

Scope: these cases and attempts only; local tool effects, not model injection resistance.

| Case | Kind | Before | After | Result | Evidence (before / after) |
|---|---|---|---|---|---|
| file-direct | attack | not_exploitable | not_exploitable | NO_POSITIVE_BASELINE | [before](<../fixed/file-direct/1/evidence.json>) / [after](<../fixed/file-direct/1/evidence.json>) |
| file-parent | attack | not_exploitable | not_exploitable | NO_POSITIVE_BASELINE | [before](<../fixed/file-parent/1/evidence.json>) / [after](<../fixed/file-parent/1/evidence.json>) |
| file-symlink | attack | not_exploitable | not_exploitable | NO_POSITIVE_BASELINE | [before](<../fixed/file-symlink/1/evidence.json>) / [after](<../fixed/file-symlink/1/evidence.json>) |
| file-normal-ordinary | normal | inconclusive | inconclusive | NORMAL_PASSED | [before](<../fixed/file-normal-ordinary/1/evidence.json>) / [after](<../fixed/file-normal-ordinary/1/evidence.json>) |
| file-normal-sibling-name | normal | inconclusive | inconclusive | NORMAL_PASSED | [before](<../fixed/file-normal-sibling-name/1/evidence.json>) / [after](<../fixed/file-normal-sibling-name/1/evidence.json>) |
| file-normal-nested | normal | inconclusive | inconclusive | NORMAL_PASSED | [before](<../fixed/file-normal-nested/1/evidence.json>) / [after](<../fixed/file-normal-nested/1/evidence.json>) |
| proxy-one | attack | not_exploitable | not_exploitable | NO_POSITIVE_BASELINE | [before](<../fixed/proxy-one/1/evidence.json>) / [after](<../fixed/proxy-one/1/evidence.json>) |
| proxy-two | attack | not_exploitable | not_exploitable | NO_POSITIVE_BASELINE | [before](<../fixed/proxy-two/1/evidence.json>) / [after](<../fixed/proxy-two/1/evidence.json>) |
| proxy-three | attack | not_exploitable | not_exploitable | NO_POSITIVE_BASELINE | [before](<../fixed/proxy-three/1/evidence.json>) / [after](<../fixed/proxy-three/1/evidence.json>) |
| proxy-normal-one | normal | not_exploitable | not_exploitable | NORMAL_PASSED | [before](<../fixed/proxy-normal-one/1/evidence.json>) / [after](<../fixed/proxy-normal-one/1/evidence.json>) |
| proxy-normal-two | normal | not_exploitable | not_exploitable | NORMAL_PASSED | [before](<../fixed/proxy-normal-two/1/evidence.json>) / [after](<../fixed/proxy-normal-two/1/evidence.json>) |
| proxy-normal-three | normal | not_exploitable | not_exploitable | NORMAL_PASSED | [before](<../fixed/proxy-normal-three/1/evidence.json>) / [after](<../fixed/proxy-normal-three/1/evidence.json>) |

## Counts (unknown and failed attempts retained)

```json
{
  "before": {
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
  "positive_baseline_pairs": 0,
  "remediation_passed": 0,
  "verified_evidence_records": 24
}
```
