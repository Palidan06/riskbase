# Near-Real-Time Mode

`-NRT` enables a secondary recency scan designed to catch fast-moving developments.

## Windowing

- Default NRT window: **12 hours**.
- Supported design envelope: **6-24 hours** (configured by taxonomy spec).

## Behavior

- Baseline posture uses authoritative and corroborated signals.
- NRT layer adds rapid emerging-signal context.
- NRT findings are kept logically separate in output so users can distinguish:
  - baseline risk posture
  - emerging/provisional movement impacts

## Validation Rules

- NRT evidence is fed into the same severity-tier validation policy.
- If corroboration is incomplete, findings are labeled **Provisional**.
- Provisional findings are scored with dampening to prevent overreaction to noise.

## Operator Guidance

- Treat NRT as recency enhancement, not replacement of baseline advisories.
- Use NRT to trigger additional verification before movement in uncertain cases.
