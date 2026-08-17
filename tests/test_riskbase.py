from __future__ import annotations

import unittest
from unittest.mock import patch

from riskbase.cli import _resolve_agency_input
from riskbase.engine import _is_active_conflict_from_evidence
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
            strict_country_match=False,
        )
        now = utc_now_iso()
        mocked_evidence = [
            EvidenceItem(
                source_id="mock_src_1",
                source_name="Mock Source 1",
                tier="tier1",
                category="advisory",
                claim_key="official_advisory",
                claim_text="Mock advisory elevated.",
                event_time=now,
                fetched_at=now,
                severity="elevated",
                confidence=0.9,
                extraction_note="x",
                event_id="m1",
            ),
            EvidenceItem(
                source_id="mock_src_2",
                source_name="Mock Source 2",
                tier="tier1",
                category="advisory",
                claim_key="official_advisory",
                claim_text="Mock advisory corroboration.",
                event_time=now,
                fetched_at=now,
                severity="elevated",
                confidence=0.9,
                extraction_note="x",
                event_id="m2",
            ),
        ]
        with patch(
            "riskbase.engine.collect_baseline_evidence",
            return_value=(mocked_evidence, {"mock_src_1": {"status": "ok"}}, {"canonical_destination_country": "albania"}),
        ):
            result = run_assessment(ui, show_progress=False)
        self.assertIn(result.posture, {"Low Concern", "Elevated Concern", "High Concern", "Critical Concern"})
        self.assertTrue(len(result.evidence) >= 1)
        self.assertTrue(len(result.validation) >= 1)

    def test_score_posture_mapping(self) -> None:
        taxonomy = load_threat_taxonomy()
        ui = UserInput(
            residence_country="US",
            clearance_level="",
            agency="X",
            destination_country="Canada",
        )
        score, posture, _ = score_assessment(
            evidence=[],
            validation=[],
            taxonomy=taxonomy,
            nrt_enabled=False,
            user_input=ui,
        )
        self.assertEqual(score, 1.6)
        self.assertEqual(posture, "Low Concern")

    def test_resolve_agency_input_accepts_code_name_or_number(self) -> None:
        self.assertEqual(_resolve_agency_input("CIA"), "CIA")
        self.assertEqual(_resolve_agency_input("central intelligence agency"), "CIA")
        self.assertEqual(_resolve_agency_input("3"), "CIA")

    def test_active_conflict_requires_explicit_war_language(self) -> None:
        now = utc_now_iso()
        evidence = [
            EvidenceItem(
                source_id="uk_fcdo_travel_advice",
                source_name="UK FCDO",
                tier="tier1",
                category="advisory",
                claim_key="terrorism_organized_violence",
                claim_text="High unrest in area.",
                event_time=now,
                fetched_at=now,
                severity="high",
                confidence=0.9,
                extraction_note="x",
                event_id="evt-uk",
                metadata={"excerpt": "Armed conflict is ongoing in this region."},
            ),
            EvidenceItem(
                source_id="canada_travel_advisories",
                source_name="Canada",
                tier="tier1",
                category="advisory",
                claim_key="terrorism_organized_violence",
                claim_text="High terrorism risk.",
                event_time=now,
                fetched_at=now,
                severity="high",
                confidence=0.9,
                extraction_note="x",
                event_id="evt-ca",
                metadata={"excerpt": "Security bulletin notes active hostilities near the destination."},
            ),
        ]
        taxonomy = load_threat_taxonomy()
        validation = validate_claims(evidence, taxonomy["validation_thresholds"])
        self.assertTrue(_is_active_conflict_from_evidence(evidence, validation))

        non_conflict_evidence = [
            EvidenceItem(
                source_id="uk_fcdo_travel_advice",
                source_name="UK FCDO",
                tier="tier1",
                category="advisory",
                claim_key="terrorism_organized_violence",
                claim_text="High unrest in area.",
                event_time=now,
                fetched_at=now,
                severity="high",
                confidence=0.9,
                extraction_note="x",
                event_id="evt-uk-2",
                metadata={"excerpt": "Demonstrations and transport disruptions reported."},
            ),
            EvidenceItem(
                source_id="canada_travel_advisories",
                source_name="Canada",
                tier="tier1",
                category="advisory",
                claim_key="terrorism_organized_violence",
                claim_text="High terrorism risk.",
                event_time=now,
                fetched_at=now,
                severity="high",
                confidence=0.9,
                extraction_note="x",
                event_id="evt-ca-2",
                metadata={"excerpt": "Remain vigilant in crowded places."},
            ),
        ]
        non_conflict_validation = validate_claims(non_conflict_evidence, taxonomy["validation_thresholds"])
        self.assertFalse(_is_active_conflict_from_evidence(non_conflict_evidence, non_conflict_validation))


if __name__ == "__main__":
    unittest.main()
