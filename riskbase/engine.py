from __future__ import annotations

import time
import uuid
from dataclasses import dataclass

from .config import load_critical_zone_policy, load_provider_aliases, load_source_registry, load_threat_taxonomy
from .models import AssessmentResult, UserInput, utc_now_iso
from .scoring import classify_posture, score_assessment, summarize_recommendations
from .sources import SourceCollectionError, collect_baseline_evidence, collect_nrt_evidence
from .validation import deduplicate_evidence, validate_claims


@dataclass
class AssessmentError(RuntimeError):
    message: str
    source_debug: dict[str, dict[str, str]]

    def __str__(self) -> str:
        return self.message


def _progress(seconds: int) -> None:
    for remaining in range(seconds, 0, -1):
        print(f"\rGenerating curated report... {remaining:02d}s", end="", flush=True)
        time.sleep(1)
    print("\rGenerating curated report... done ")


CONFLICT_CLAIMS = {"terrorism_organized_violence", "violent_crime_kidnapping", "political_unrest"}
CONFLICT_KEYWORDS = (
    "active conflict",
    "armed conflict",
    "civil war",
    "war zone",
    "warzone",
    "active hostilities",
    "ongoing hostilities",
    "military clashes",
    "frontline fighting",
)


def _has_conflict_keywords(text: str) -> bool:
    lowered = text.lower()
    return any(keyword in lowered for keyword in CONFLICT_KEYWORDS)


def _is_active_conflict_from_evidence(evidence: list, validation: list) -> bool:
    val_map = {v.claim_key: v for v in validation}
    corroborating_sources: set[str] = set()
    for item in evidence:
        if item.claim_key not in CONFLICT_CLAIMS:
            continue
        val = val_map.get(item.claim_key)
        if not val or not val.validated or item.severity not in {"high", "critical"}:
            continue
        excerpt = str(item.metadata.get("excerpt", ""))
        if _has_conflict_keywords(f"{item.claim_text} {excerpt}"):
            corroborating_sources.add(item.source_id)
    return len(corroborating_sources) >= 2


def _validated_severe_conflict_count(validation: list) -> int:
    val_map = {v.claim_key: v for v in validation}
    severe_claims = 0
    for key in CONFLICT_CLAIMS:
        v = val_map.get(key)
        if v and v.validated and v.severity in {"high", "critical"}:
            severe_claims += 1
    return severe_claims


def _canonical_country(value: str) -> str:
    aliases = load_provider_aliases().get("canonical_country_aliases", {})
    normalized = "".join(ch.lower() if ch.isalnum() or ch.isspace() else " " for ch in value)
    normalized = " ".join(normalized.split())
    return aliases.get(normalized, normalized)


def _is_critical_zone_country(destination_country: str) -> bool:
    policy = load_critical_zone_policy()
    critical_zone_countries = set(policy.get("critical_zone_countries", []))
    return _canonical_country(destination_country) in critical_zone_countries


def _official_floor_allowed_for_locality(user_input: UserInput, evidence: list, validation: list) -> bool:
    if not user_input.destination_city:
        return True
    destination_country = user_input.destination_country.strip().lower()
    if destination_country not in {"united states", "us", "usa", "united states of america"}:
        # For foreign city lookups, city mentions are often absent in official country advisories.
        return True
    locality_tokens = [user_input.destination_city.lower()]
    if user_input.destination_state:
        locality_tokens.append(user_input.destination_state.lower())
    val_map = {v.claim_key: v for v in validation}
    official_val = val_map.get("official_advisory")
    if not official_val or not official_val.validated:
        return False
    corroborating_sources: set[str] = set()
    for item in evidence:
        if item.claim_key != "official_advisory":
            continue
        text = f"{item.claim_text} {str(item.metadata.get('excerpt', ''))}".lower()
        if any(token in text for token in locality_tokens):
            corroborating_sources.add(item.source_id)
    return len(corroborating_sources) >= 2


def _critical_official_floor_allowed(user_input: UserInput, evidence: list, validation: list) -> bool:
    if not user_input.destination_city:
        return True
    destination_country = user_input.destination_country.strip().lower()
    is_us_destination_city = destination_country in {"united states", "us", "usa", "united states of america"}
    if is_us_destination_city:
        return _official_floor_allowed_for_locality(user_input, evidence, validation)
    if _is_critical_zone_country(user_input.destination_country):
        return True
    # Foreign city query: only allow critical official floor with explicit
    # corroborated conflict wording to avoid country-wide overcalls.
    return _is_active_conflict_from_evidence(evidence, validation)


def run_assessment(user_input: UserInput, show_progress: bool = False) -> AssessmentResult:
    taxonomy = load_threat_taxonomy()
    load_source_registry()  # Ensures source registry is present and parseable.

    try:
        evidence, source_debug, normalization_debug = collect_baseline_evidence(user_input)
    except SourceCollectionError as exc:
        raise AssessmentError(str(exc), source_debug=exc.source_debug) from exc

    if user_input.strict_country_match:
        authoritative_matches = 0
        for source_id, meta in source_debug.items():
            if not source_id.startswith(("uk_", "canada_", "us_state_")):
                continue
            if meta.get("status") == "ok" and meta.get("country_match") == "true":
                authoritative_matches += 1
        if authoritative_matches < 2:
            raise AssessmentError(
                "Strict country-match failed: fewer than two authoritative sources positively matched destination.",
                source_debug=source_debug,
            )
    nrt_summary = None
    if user_input.nrt_enabled:
        nrt_hours = taxonomy["recency_windows_hours"]["nrt_default"]
        nrt_evidence = collect_nrt_evidence(user_input, nrt_hours)
        evidence.extend(nrt_evidence)
        if nrt_evidence:
            nrt_summary = (
                f"{len(nrt_evidence)} near-real-time signal(s) in last {nrt_hours}h; "
                "provisional until corroboration thresholds are met."
            )
        else:
            nrt_summary = f"No notable NRT changes in the last {nrt_hours}h."

    evidence = deduplicate_evidence(evidence)
    validation = validate_claims(evidence, taxonomy["validation_thresholds"])

    score, posture, factors = score_assessment(
        evidence=evidence,
        validation=validation,
        taxonomy=taxonomy,
        nrt_enabled=user_input.nrt_enabled,
        user_input=user_input,
    )
    official_validation = next((v for v in validation if v.claim_key == "official_advisory"), None)
    official_floor_allowed = _official_floor_allowed_for_locality(user_input, evidence, validation)
    if (
        official_floor_allowed
        and official_validation
        and official_validation.validated
        and official_validation.severity == "elevated"
    ):
        # Elevated advisory floor: prevent under-calling consistent elevated posture.
        score = max(score, 30.0)
    if (
        official_validation
        and official_validation.validated
        and official_validation.severity == "critical"
        and _critical_official_floor_allowed(user_input, evidence, validation)
    ):
        # Critical advisory floor is a minimum, not a maximum.
        score = max(score, 75.0)
    if _is_active_conflict_from_evidence(evidence, validation):
        # Active conflict / warzone floor should be stricter than generic critical.
        # Also a minimum only; additional risks still raise score above this floor.
        score = max(score, 85.0)
    # Hard consistency guard: posture always derives from final numeric score.
    posture = classify_posture(score, taxonomy)

    if official_validation and not official_validation.validated:
        raise AssessmentError(
            "Official advisory corroboration is incomplete at query time. "
            "Assessment halted to avoid unvalidated posture output.",
            source_debug=source_debug,
        )

    if show_progress:
        _progress(5 if user_input.long_report else 2)

    summary = (
        "Multi-source assessment complete with validation-state tagging across key risk factors."
    )
    recommendations = summarize_recommendations(posture)
    return AssessmentResult(
        run_id=str(uuid.uuid4())[:8],
        generated_at=utc_now_iso(),
        posture=posture,
        total_score=score,
        factors=factors,
        evidence=evidence,
        validation=validation,
        summary=summary,
        recommendations=recommendations,
        nrt_summary=nrt_summary,
        source_debug=source_debug,
        normalization_debug=normalization_debug,
    )
