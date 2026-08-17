from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import asdict

from .models import AssessmentResult
from .scoring import FACTOR_LABELS


def _fmt_pct(v: float) -> str:
    return f"{round(v * 100, 1)}%"


CLAIM_MEANING = {
    "official_advisory": "Government travel advisory posture for the destination.",
    "political_unrest": "Likelihood of protests, civil disorder, or instability affecting movement.",
    "violent_crime_kidnapping": "Threat of violent crime, armed robbery, or kidnapping exposure.",
    "terrorism_organized_violence": "Risk of terrorism, insurgency, or organized violence events.",
    "health_bio_environmental": "Public health and environmental conditions that can degrade safety.",
    "infrastructure_transport": "Transport and infrastructure reliability impacting movement routes.",
}

CLAIM_WHY_MATTERS = {
    "official_advisory": "Advisory levels condense broad national risk and often trigger internal travel policy checks.",
    "political_unrest": "Civil disruption can close roads, delay flights, and trigger sudden security posture changes.",
    "violent_crime_kidnapping": "These threats directly affect personal safety and movement viability.",
    "terrorism_organized_violence": "Low-frequency, high-impact events can rapidly invalidate normal travel assumptions.",
    "health_bio_environmental": "Health and environment risks can reduce operational endurance and medical access.",
    "infrastructure_transport": "Route reliability determines whether plans are executable under real conditions.",
}


def render_quick_report(result: AssessmentResult) -> str:
    lines = [
        "=== RiskBase Quick Posture ===",
        f"Run ID: {result.run_id}",
        f"Generated: {result.generated_at}",
        f"Advisory Posture: {result.posture}",
        f"Score: {result.total_score}/100",
        f"Summary: {result.summary}",
        "",
        "Immediate Recommendations:",
    ]
    lines.extend(f"- {rec}" for rec in result.recommendations[:2])
    lines.append("")
    lines.append("Use -LR for full detail.")
    return "\n".join(lines)


def render_long_report(result: AssessmentResult, explain_score: bool = False) -> str:
    lines = [
        "=== RiskBase Detailed Assessment ===",
        f"Run ID: {result.run_id}",
        f"Generated: {result.generated_at}",
        f"Advisory Posture: {result.posture}",
        f"Score: {result.total_score}/100",
        "",
        "What Changed:",
        f"- {result.summary}",
    ]

    if result.nrt_summary:
        lines.extend(["", "Near-Real-Time Layer:", f"- {result.nrt_summary}"])

    lines.extend(["", "What Matters:"])
    lines.extend(f"- {rec}" for rec in result.recommendations)

    if explain_score:
        lines.extend(["", "Score Explainability:"])
        for factor in result.factors:
            label = FACTOR_LABELS.get(factor.factor, factor.factor)
            lines.append(
                f"- {label}: base={round(factor.base_score, 2)} "
                f"weight={factor.weight} weighted={round(factor.weighted_score, 2)} "
                f"confidence={_fmt_pct(factor.confidence)}"
            )
            lines.append(f"  rationale: {factor.rationale}")

    lines.extend(["", "Validation Status by Claim:"])
    for val in result.validation:
        state = "Validated" if val.validated else "Provisional"
        lines.append(
            f"- {val.claim_key}: {state} | severity={val.severity} | "
            f"sources={val.independent_sources} | reason={val.reason}"
        )

    grouped_evidence: dict[str, list] = defaultdict(list)
    for ev in result.evidence:
        grouped_evidence[ev.claim_key].append(ev)

    lines.extend(["", "Flagged Events Deep Dive:"])
    flagged = [v for v in result.validation if v.severity in {"elevated", "high", "critical"} or not v.validated]
    if not flagged:
        lines.append("- No elevated/high/critical findings were flagged in this run.")
    for val in flagged:
        label = FACTOR_LABELS.get(val.claim_key, val.claim_key)
        status = "Validated" if val.validated else "Provisional"
        lines.extend(
            [
                "",
                f"- {label} [{val.severity.upper()} | {status}]",
                f"  what this means: {CLAIM_MEANING.get(val.claim_key, 'Risk factor requires analyst review.')}",
                f"  why you should care: {CLAIM_WHY_MATTERS.get(val.claim_key, 'This factor can impact movement safety and reliability.')}",
                f"  evidence posture: {val.reason}",
            ]
        )
        claim_events = grouped_evidence.get(val.claim_key, [])
        for idx, ev in enumerate(claim_events[:4], start=1):
            lines.append(
                f"  event {idx}: {ev.source_name} | severity={ev.severity} | conf={_fmt_pct(ev.confidence)} | {ev.claim_text}"
            )

    lines.extend(["", "Evidence Ledger:"])
    for ev in result.evidence:
        lines.append(
            f"- [{ev.source_name}/{ev.source_id}] {ev.claim_key} | {ev.severity} | "
            f"{ev.event_time} | conf={_fmt_pct(ev.confidence)} | {ev.claim_text}"
        )
    return "\n".join(lines)


def render_json(result: AssessmentResult) -> str:
    return json.dumps(asdict(result), indent=2)
