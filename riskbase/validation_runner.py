from __future__ import annotations

from dataclasses import dataclass

from .config import load_threat_taxonomy, load_validation_gates
from .models import EvidenceItem, UserInput
from .scoring import classify_posture, score_assessment
from .validation import deduplicate_evidence, validate_claims
from .validation_fixtures import VALIDATION_CASES

POSTURE_RANK = {
    "Low Concern": 0,
    "Elevated Concern": 1,
    "High Concern": 2,
    "Critical Concern": 3,
}


@dataclass
class CaseOutcome:
    name: str
    posture: str
    score: float
    critical_environment: bool
    true_severity_score: float
    flagged_claims: int
    explained_claims: int


def _build_user_input(data: dict) -> UserInput:
    return UserInput(**data)


def _build_evidence(data: list[dict]) -> list[EvidenceItem]:
    return [EvidenceItem(**row) for row in data]


def _run_case(case: dict, taxonomy: dict) -> CaseOutcome:
    user_input = _build_user_input(case["user_input"])
    evidence = deduplicate_evidence(_build_evidence(case["evidence"]))
    validation = validate_claims(evidence, taxonomy["validation_thresholds"])
    score, posture, _ = score_assessment(
        evidence=evidence,
        validation=validation,
        taxonomy=taxonomy,
        nrt_enabled=user_input.nrt_enabled,
        user_input=user_input,
    )
    official = next((v for v in validation if v.claim_key == "official_advisory"), None)
    if official and official.validated and official.severity == "critical":
        score = max(score, 75.0)
    posture = classify_posture(score, taxonomy)

    flagged = [v for v in validation if v.severity in {"elevated", "high", "critical"} or not v.validated]
    explained_claims = len([v for v in flagged if v.reason and v.claim_key])
    return CaseOutcome(
        name=case["name"],
        posture=posture,
        score=score,
        critical_environment=bool(case["truth"]["critical_environment"]),
        true_severity_score=float(case["truth"]["true_severity_score"]),
        flagged_claims=len(flagged),
        explained_claims=explained_claims,
    )


def run_validation_suite() -> dict:
    taxonomy = load_threat_taxonomy()
    gates = load_validation_gates()["thresholds"]
    outcomes = [_run_case(case, taxonomy) for case in VALIDATION_CASES]

    critical_truth = [o for o in outcomes if o.critical_environment]
    severe_false_negatives = [o for o in critical_truth if o.posture != "Critical Concern"]
    severe_fn_rate = (
        len(severe_false_negatives) / len(critical_truth) if critical_truth else 0.0
    )

    predicted_critical = [o for o in outcomes if o.posture == "Critical Concern"]
    true_critical_hits = [o for o in predicted_critical if o.critical_environment]
    critical_precision = (
        len(true_critical_hits) / len(predicted_critical) if predicted_critical else 0.0
    )

    buckets: dict[int, list[float]] = {0: [], 1: [], 2: [], 3: []}
    for out in outcomes:
        buckets[POSTURE_RANK[out.posture]].append(out.true_severity_score)
    bucket_means = [
        (sum(vals) / len(vals)) if vals else None for _, vals in sorted(buckets.items())
    ]
    compact = [v for v in bucket_means if v is not None]
    calibration_monotonic = all(compact[i] <= compact[i + 1] for i in range(len(compact) - 1))

    total_flagged = sum(o.flagged_claims for o in outcomes)
    total_explained = sum(o.explained_claims for o in outcomes)
    explainability_completeness = (
        total_explained / total_flagged if total_flagged else 1.0
    )

    # Additional operational-quality gates:
    # - high-band recall: true severity >= 60 should map to High/Critical
    # - elevated-band recall: true severity >= 45 should map to Elevated/High/Critical
    high_truth = [o for o in outcomes if o.true_severity_score >= 60.0]
    high_hits = [o for o in high_truth if POSTURE_RANK[o.posture] >= POSTURE_RANK["High Concern"]]
    high_band_recall = (len(high_hits) / len(high_truth)) if high_truth else 1.0

    elevated_truth = [o for o in outcomes if o.true_severity_score >= 45.0]
    elevated_hits = [o for o in elevated_truth if POSTURE_RANK[o.posture] >= POSTURE_RANK["Elevated Concern"]]
    elevated_band_recall = (len(elevated_hits) / len(elevated_truth)) if elevated_truth else 1.0

    # Score mean absolute error against fixture truth scale.
    absolute_errors = [abs(o.score - o.true_severity_score) for o in outcomes]
    score_mae = (sum(absolute_errors) / len(absolute_errors)) if absolute_errors else 0.0

    metrics = {
        "severe_false_negative_rate": round(severe_fn_rate, 4),
        "critical_precision": round(critical_precision, 4),
        "calibration_monotonic": calibration_monotonic,
        "explainability_completeness": round(explainability_completeness, 4),
        "high_band_recall": round(high_band_recall, 4),
        "elevated_band_recall": round(elevated_band_recall, 4),
        "score_mae": round(score_mae, 4),
    }
    gate_results = {
        "severe_false_negative_rate_pass": severe_fn_rate <= gates["severe_false_negative_rate_max"],
        "critical_precision_pass": critical_precision >= gates["critical_precision_min"],
        "calibration_monotonic_pass": calibration_monotonic == gates["calibration_monotonic_required"],
        "explainability_completeness_pass": explainability_completeness >= gates["explainability_completeness_min"],
        "high_band_recall_pass": high_band_recall >= gates["high_band_recall_min"],
        "elevated_band_recall_pass": elevated_band_recall >= gates["elevated_band_recall_min"],
        "score_mae_pass": score_mae <= gates["score_mae_max"],
    }
    promote = all(gate_results.values())
    return {
        "metrics": metrics,
        "thresholds": gates,
        "gate_results": gate_results,
        "promote": promote,
        "mode": "promoted" if promote else "advisory_beta",
        "outcomes": [o.__dict__ for o in outcomes],
    }
