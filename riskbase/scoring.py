from __future__ import annotations

from collections import defaultdict

from .clearance import clearance_exposure_modifier
from .models import EvidenceItem, FactorScore, UserInput, ValidationResult


SEVERITY_POINTS = {
    "low": 10,
    "elevated": 35,
    "high": 65,
    "critical": 90,
}
SEVERITY_WEIGHTS = {
    "low": 1.0,
    "elevated": 1.5,
    "high": 2.2,
    "critical": 3.2,
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
    # Use min-score thresholds to avoid fractional gap errors (e.g., 24.2).
    selected = posture_bands[0]
    for band in posture_bands:
        if score >= band["min_score"]:
            selected = band
        else:
            break
    return str(selected["posture"])


def classify_posture(score: float, taxonomy: dict) -> str:
    return _posture_from_score(score, taxonomy["classification"]["posture_bands"])


def _validation_lookup(validation: list[ValidationResult]) -> dict[str, ValidationResult]:
    return {v.claim_key: v for v in validation}


def score_assessment(
    evidence: list[EvidenceItem],
    validation: list[ValidationResult],
    taxonomy: dict,
    nrt_enabled: bool,
    user_input: UserInput,
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

        weighted_numerator = 0.0
        weighted_denominator = 0.0
        severities = []
        for item in items:
            sev = item.severity
            severities.append(sev)
            sev_points = SEVERITY_POINTS.get(sev, 20)
            sev_weight = SEVERITY_WEIGHTS.get(sev, 1.0)
            weighted_numerator += sev_points * sev_weight
            weighted_denominator += sev_weight
        avg_points = weighted_numerator / weighted_denominator if weighted_denominator else 0.0
        conf = sum(i.confidence for i in items) / len(items)
        val = val_map.get(factor)
        if val and not val.validated:
            avg_points = avg_points * 0.55
            rationale = "Signals found but not fully validated; score dampened."
        else:
            rationale = "Corroborated signal contribution applied."

        # Mixed elevated protection: if corroborated elevated/high/critical evidence exists,
        # prevent low-only dilution from collapsing the factor too far.
        if val and val.validated and any(s in {"elevated", "high", "critical"} for s in severities):
            avg_points = max(avg_points, 30.0)
            rationale = (
                rationale
                + " Mixed-source elevated protection floor applied."
            )

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
    modifier, rationale = clearance_exposure_modifier(user_input, total)
    total = min(100.0, round(total + modifier, 2))
    if modifier:
        factor_scores.append(
            FactorScore(
                factor="clearance_exposure_modifier",
                base_score=modifier,
                weight=1.0,
                weighted_score=modifier,
                confidence=0.85,
                rationale=rationale,
            )
        )
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
