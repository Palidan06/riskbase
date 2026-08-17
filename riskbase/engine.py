from __future__ import annotations

import time
import uuid

from .config import load_source_registry, load_threat_taxonomy
from .models import AssessmentResult, UserInput, utc_now_iso
from .scoring import score_assessment, summarize_recommendations
from .sources import collect_baseline_evidence, collect_nrt_evidence
from .validation import deduplicate_evidence, validate_claims


def _progress(seconds: int) -> None:
    for remaining in range(seconds, 0, -1):
        print(f"\rGenerating curated report... {remaining:02d}s", end="", flush=True)
        time.sleep(1)
    print("\rGenerating curated report... done ")


def run_assessment(user_input: UserInput, show_progress: bool = False) -> AssessmentResult:
    taxonomy = load_threat_taxonomy()
    load_source_registry()  # Ensures source registry is present and parseable.

    evidence = collect_baseline_evidence(user_input)
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
    )
