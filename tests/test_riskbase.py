from __future__ import annotations

import unittest

from riskbase.config import load_threat_taxonomy
from riskbase.engine import run_assessment
from riskbase.models import EvidenceItem, UserInput, utc_now_iso
from riskbase.scoring import score_assessment
from riskbase.validation import deduplicate_evidence, validate_claims


class RiskBaseTests(unittest.TestCase):
    def test_deduplicate_evidence(self) -> None:
        now = utc_now_iso()
        item = EvidenceItem(
            source_id="s1",
            source_name="S1",
            tier="tier1",
            category="advisory",
            claim_key="official_advisory",
            claim_text="A",
            event_time=now,
            fetched_at=now,
            severity="elevated",
            confidence=0.7,
            extraction_note="x",
            event_id="evt1",
        )
        deduped = deduplicate_evidence([item, item])
        self.assertEqual(len(deduped), 1)

    def test_validation_thresholds(self) -> None:
        now = utc_now_iso()
        evidence = [
            EvidenceItem(
                source_id="us_state_travel_advisories",
                source_name="US",
                tier="tier1",
                category="advisory",
                claim_key="terrorism_organized_violence",
                claim_text="A",
                event_time=now,
                fetched_at=now,
                severity="critical",
                confidence=0.9,
                extraction_note="x",
                event_id="evt-a",
            )
        ]
        taxonomy = load_threat_taxonomy()
        results = validate_claims(evidence, taxonomy["validation_thresholds"])
        self.assertEqual(len(results), 1)
        self.assertFalse(results[0].validated)
        self.assertTrue(results[0].provisional)

    def test_assessment_runs(self) -> None:
        ui = UserInput(
            residence_country="US",
            clearance_level="SECRET",
            agency="DoW",
            destination_country="Albania",
            destination_city="Tirana",
            long_report=False,
            nrt_enabled=True,
        )
        result = run_assessment(ui, show_progress=False)
        self.assertIn(result.posture, {"Low Concern", "Elevated Concern", "High Concern", "Critical Concern"})
        self.assertTrue(len(result.evidence) >= 1)
        self.assertTrue(len(result.validation) >= 1)

    def test_score_posture_mapping(self) -> None:
        taxonomy = load_threat_taxonomy()
        score, posture, _ = score_assessment(
            evidence=[],
            validation=[],
            taxonomy=taxonomy,
            nrt_enabled=False,
        )
        self.assertEqual(score, 1.6)
        self.assertEqual(posture, "Low Concern")


if __name__ == "__main__":
    unittest.main()
