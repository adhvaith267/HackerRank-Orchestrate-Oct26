# Evaluation Report

Generated from `evaluation/sample_metrics.json`, `custom_metrics.json`, and `adversarial_results.json`; no performance numbers are hand-entered.

## Sample-reference comparison

- Sample denominator: 32 case IDs joined by `case_id`.
- Status accuracy: 68.8% (22/32).
- Exact full-case accuracy (status + ordered steps): 9.4% (3/32).
- Step-count accuracy: 28.1% (9/32).
- Step multiset precision / recall: 71.1% / 52.3% (101 overlap; signatures exclude `step_no`, preserving duplicate counts).
- Ordered sequence exact match: 9.4% (3/32).

### Field accuracy (position-aligned, missing steps count as mismatches)

| Field | Accuracy | Matches | Comparisons |
|---|---:|---:|---:|
| `step_no` | 65.0% | 132 | 203 |
| `phase` | 54.7% | 111 | 203 |
| `system_id` | 27.6% | 56 | 203 |
| `resource_id` | 28.6% | 58 | 203 |
| `operation` | 32.0% | 65 | 203 |
| `state` | 36.0% | 73 | 203 |
| `evidence_id` | 55.2% | 112 | 203 |

### Definitions and validity

- Inputs are parsed independently and joined by `case_id`; row position is never used.
- A step multiset signature is `(phase, system_id, resource_id, operation, state, evidence_id)`; `Counter` intersection gives duplicate-aware overlap.
- Sequence exact match compares the ordered signature arrays. Exact full-case additionally requires status equality.
- Reference parser/schema valid: `True`; predicted parser/schema valid: `True`.
- Missing IDs: `[]`; unexpected IDs: `[]`; duplicate reference IDs: `[]`; duplicate predicted IDs: `[]`.
- Hidden grader reference and hidden-test accuracy are not available here and are not estimated.

### Per-case sample results

| Case | Status | Step count | Sequence | Exact case | Gold steps | Pred steps |
|---|---|---|---|---|---:|---:|
| case_01 | FAIL | FAIL | FAIL | FAIL | 1 | 0 |
| case_02 | FAIL | FAIL | FAIL | FAIL | 1 | 0 |
| case_03 | PASS | FAIL | FAIL | FAIL | 3 | 9 |
| case_04 | FAIL | FAIL | FAIL | FAIL | 2 | 0 |
| case_05 | PASS | PASS | PASS | PASS | 3 | 3 |
| case_06 | PASS | FAIL | FAIL | FAIL | 4 | 0 |
| case_07 | PASS | FAIL | FAIL | FAIL | 4 | 3 |
| case_08 | PASS | PASS | FAIL | FAIL | 4 | 4 |
| case_09 | PASS | FAIL | FAIL | FAIL | 5 | 3 |
| case_10 | PASS | FAIL | FAIL | FAIL | 4 | 0 |
| case_11 | PASS | FAIL | FAIL | FAIL | 14 | 16 |
| case_12 | FAIL | FAIL | FAIL | FAIL | 5 | 0 |
| case_13 | PASS | PASS | FAIL | FAIL | 8 | 8 |
| case_14 | PASS | PASS | PASS | PASS | 5 | 5 |
| case_15 | FAIL | FAIL | FAIL | FAIL | 5 | 0 |
| case_16 | PASS | PASS | PASS | PASS | 7 | 7 |
| case_17 | FAIL | FAIL | FAIL | FAIL | 5 | 0 |
| case_18 | PASS | FAIL | FAIL | FAIL | 14 | 3 |
| case_19 | PASS | FAIL | FAIL | FAIL | 8 | 6 |
| case_20 | PASS | FAIL | FAIL | FAIL | 8 | 3 |
| case_21 | PASS | FAIL | FAIL | FAIL | 3 | 2 |
| case_22 | PASS | FAIL | FAIL | FAIL | 8 | 7 |
| case_23 | PASS | FAIL | FAIL | FAIL | 8 | 6 |
| case_24 | PASS | PASS | FAIL | FAIL | 7 | 7 |
| case_25 | PASS | FAIL | FAIL | FAIL | 3 | 1 |
| case_26 | FAIL | FAIL | FAIL | FAIL | 6 | 0 |
| case_27 | FAIL | PASS | FAIL | FAIL | 6 | 6 |
| case_28 | FAIL | PASS | FAIL | FAIL | 6 | 6 |
| case_29 | PASS | FAIL | FAIL | FAIL | 14 | 15 |
| case_30 | PASS | PASS | FAIL | FAIL | 14 | 14 |
| case_31 | FAIL | FAIL | FAIL | FAIL | 3 | 4 |
| case_32 | PASS | FAIL | FAIL | FAIL | 5 | 4 |

## Team-authored cases

Passed 3 of 3 fixture cases.

| Case | Match | Rationale |
|---|---|---|
| custom_A_historical_alias_sync | PASS | Historical email resolution is represented by the stable user_id; a secondary search copy remains and an active sync can recreate it. |
| custom_B_tombstone_redaction | PASS | The account tombstone is retained by policy but still exposes direct identifiers including an email hash. |
| custom_C_not_deletion | PASS | The request is an access request; unrelated deletion-looking evidence cannot authorize deletion. |

## Adversarial/regression checks

Passed 13 of 13 checks.

| Check | Result |
|---|---|
| contradictory evidence does not claim complete | PASS |
| post-audit evidence is excluded by core | PASS |
| active re-import is incomplete | PASS |
| restore risk is incomplete | PASS |
| missing evidence coverage is incomplete | PASS |
| duplicate case IDs are detected | PASS |
| malformed CSV is detected | PASS |
| source-id forgery is rejected | PASS |
| prompt injection-looking evidence is data | PASS |
| PII in logs is redacted deterministically | PASS |
| PII fields require grounded evidence | PASS |
| malformed JSON fallback is deterministic | PASS |
| unknown fields are rejected | PASS |

## Reproduction and limitations

- Command: `python evaluation/harness.py`
- Python version: `3.12.3`.
- Configuration: built-in RunConfig defaults, `llm.mode=off`, provider `ollama-local`, model `qwen2.5:7b`; no random seed is used.
- Full-run command used for output/usage artifacts: `PYTHONPATH=code/ghost-data-audit/src python3 -m ghost_audit.cli run --llm-mode auto`.
- The sample reference is a development reference, not a hidden grader. Synthetic cases test targeted behavior only.
- Remaining limitations: the public sample reference is not a hidden grader; OCR/model-enabled modes require local dependencies and an available Ollama model; no-grounded-resource evidence gaps remain conservative INCOMPLETE without invented steps; activity claims are used for sync-after-delete detection but are not treated as standalone state proof; hidden-test accuracy is unobservable.
