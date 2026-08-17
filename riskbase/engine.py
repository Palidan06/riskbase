from __future__ import annotations

import time
import uuid
from dataclasses import dataclass

from .config import load_source_registry, load_threat_taxonomy
from .models import AssessmentResult, UserInput, utc_now_iso
from .scoring import score_assessment, summarize_recommendations
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
