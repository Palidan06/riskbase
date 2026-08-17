# Report Templates

RiskBase uses two terminal-first report templates.

## Quick Posture Template (default)

Purpose: fast operator decision support in under ~60 seconds when possible.

Sections:
1. Run metadata (run id, generation timestamp)
2. Advisory posture + numeric score
3. Single blunt summary line
4. Two immediate recommendations
5. Prompt for deeper dive

## Detailed Report Template (`-LR`)

Purpose: curated ~5-minute read with explicit validation and evidence.

Sections:
1. Run metadata
2. Advisory posture + score
3. What Changed
4. Near-Real-Time Layer (if enabled)
5. What Matters (action-focused recommendations)
6. Score Explainability (`--explain-score`)
7. Validation Status by Claim
8. Evidence Ledger
9. Operational Notice disclaimer

## Language Policy

- Use advisory posture language, not safe/unsafe claims.
- Keep wording direct, concise, and operationally actionable.
- Preserve caveats for unvalidated/provisional signals.
