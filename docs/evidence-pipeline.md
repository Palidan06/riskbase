# Evidence Pipeline

RiskBase implements a deterministic evidence pipeline with explicit provenance and validation state.

## Stages

1. **Ingestion**
   - Baseline evidence is collected from configured source adapters.
   - NRT evidence is optionally collected when `-NRT` is enabled.

2. **Normalization**
   - Evidence is normalized into a common schema (`EvidenceItem`):
     - source metadata
     - claim key/factor mapping
     - timestamp
     - severity
     - confidence
     - extraction notes

3. **Deduplication**
   - Duplicate events are removed by tuple:
     - `(claim_key, source_id, event_id)`
   - This prevents score inflation from repeated ingest of the same source event.

4. **Corroboration**
   - Evidence is grouped by `claim_key`.
   - Independent corroboration counts distinct `source_id`.
   - Severity-specific thresholds are applied from `threat_taxonomy.v1.yaml`.

5. **Validation State Assignment**
   - Each claim is marked:
     - `Validated` if corroboration threshold is met.
     - `Provisional` if threshold is not met.
   - Tier-1 authoritative source presence is recorded for explainability.

6. **Scoring**
   - Weighted deterministic score is computed per factor.
   - Unvalidated factors are dampened to reduce false confidence.

7. **Reporting**
   - Output includes:
     - posture and score
     - per-factor rationale
     - validation status
     - evidence ledger

## Conflict Handling

- Contradictory source narratives are surfaced in output via per-claim evidence entries.
- RiskBase does not suppress conflicting signals; it marks confidence and validation explicitly.

## Auditability

- Each assessment appends an audit log record:
  - run metadata
  - user input context
  - source list
  - scoring config version
  - output hash
