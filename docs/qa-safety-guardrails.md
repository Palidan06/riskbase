# QA and Safety Guardrails

## Validation Test Coverage

RiskBase includes tests for:
- Evidence deduplication behavior.
- Severity-tier validation thresholds.
- Provisional labeling when corroboration is insufficient.
- Score posture band mapping.
- End-to-end assessment result shape.

## Source Conflict Rules

- Do not suppress contradictory evidence.
- Show conflicts through claim-level validation and evidence ledger entries.
- Reduce score influence for unvalidated signals.

## Operator-Facing Safeguards

- Advisory posture language replaces safe/unsafe wording.
- Every run includes an operational notice:
  - decision-support only, not sole authority.
- Audit log records:
  - input parameters
  - queried sources
  - model config version
  - output hash

## Feed Activation Safeguard

- Premium feeds remain disabled until licensing and usage terms are explicitly reviewed and recorded.
