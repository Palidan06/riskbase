from __future__ import annotations

from collections import defaultdict

from .models import EvidenceItem, FactorScore, ValidationResult


SEVERITY_POINTS = {
    "low": 10,
    "elevated": 35,
    "high": 65,
    "critical": 90,
}


FACTOR_LABELS = {
    "official_advisory": "Official advisories",
    "political_unrest": "Political instability/civil unrest",
    "violent_crime_kidnapping": "Violent crime and kidnapping",
    "terrorism_organized_violence": "Terrorism/organized violence",
    "health_bio_environmental": "Health, bio, environmental",
    "infrastructure_transport": "Infrastructure/transport",
    "recency_multiplier": "Time sensitivity",
}


def _posture_from_score(score: float, posture_bands: list[dict[str, int | str]]) -> str:
    for band in posture_bands:
        if band["min_score"] <= score <= band["max_score"]:
            return str(band["posture"])
    return "Critical Concern"


def _validation_lookup(validation: list[ValidationResult]) -> dict[str, ValidationResult]:
    return {v.claim_key: v for v in validation}


def score_assessment(
    evidence: list[EvidenceItem],
    validation: list[ValidationResult],
    taxonomy: dict,
    nrt_enabled: bool,
) -> tuple[float, str, list[FactorScore]]:
    weights = taxonomy["weights"]
    grouped: dict[str, list[EvidenceItem]] = defaultdict(list)
    for item in evidence:
        grouped[item.claim_key].append(item)

    val_map = _validation_lookup(validation)
    factor_scores: list[FactorScore] = []

    for factor, weight in weights.items():
        if factor == "recency_multiplier":
            base = 30.0 if nrt_enabled else 20.0
            factor_scores.append(
                FactorScore(
                    factor=factor,
                    base_score=base,
                    weight=float(weight),
                    weighted_score=base * float(weight),
                    confidence=0.75 if nrt_enabled else 0.65,
                    rationale="NRT enabled increases recency sensitivity."
                    if nrt_enabled
                    else "Default recency weighting applied.",
                )
            )
            continue

        items = grouped.get(factor, [])
        if not items:
            factor_scores.append(
                FactorScore(
                    factor=factor,
                    base_score=0.0,
                    weight=float(weight),
                    weighted_score=0.0,
                    confidence=0.0,
                    rationale="No significant corroborated evidence found.",
                )
            )
            continue

        sev_points = [SEVERITY_POINTS.get(i.severity, 20) for i in items]
        avg_points = sum(sev_points) / len(sev_points)
        conf = sum(i.confidence for i in items) / len(items)
        val = val_map.get(factor)
        if val and not val.validated:
            avg_points = avg_points * 0.55
            rationale = "Signals found but not fully validated; score dampened."
        else:
            rationale = "Corroborated signal contribution applied."

        factor_scores.append(
            FactorScore(
                factor=factor,
                base_score=avg_points,
                weight=float(weight),
                weighted_score=avg_points * float(weight),
                confidence=conf,
                rationale=rationale,
            )
        )

    total = round(sum(f.weighted_score for f in factor_scores), 2)
    posture = _posture_from_score(total, taxonomy["classification"]["posture_bands"])
    return total, posture, factor_scores


def summarize_recommendations(posture: str) -> list[str]:
    if posture == "Low Concern":
        return [
            "Proceed with normal protective posture.",
            "Recheck status before final movement decision.",
        ]
    if posture == "Elevated Concern":
        return [
            "Proceed with mitigations and route awareness.",
            "Review latest local advisories before movement.",
        ]
    if posture == "High Concern":
        return [
            "Defer non-essential movement pending additional controls.",
            "Pre-brief contingency, extraction, and communication plans.",
        ]
    return [
        "Do not proceed without command-level approval and hardened contingency.",
        "Require real-time monitoring and alternate movement options.",
    ]
