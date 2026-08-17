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


SEVERITY_ORDER = {"low": 0, "elevated": 1, "high": 2, "critical": 3}


def _severity_max(values: list[str]) -> str:
    if not values:
        return "low"
    return max(values, key=lambda v: SEVERITY_ORDER.get(v, 0))


def _factor_conflict_line(claim_events: list) -> str:
    if not claim_events:
        return "no source evidence events available for this factor."
    counts: dict[str, int] = {"low": 0, "elevated": 0, "high": 0, "critical": 0}
    for ev in claim_events:
        counts[ev.severity] = counts.get(ev.severity, 0) + 1
    non_zero = [(k, v) for k, v in counts.items() if v > 0]
    if len(non_zero) == 1:
        sev, c = non_zero[0]
        return f"all corroborating sources align at {sev} ({c}/{len(claim_events)})."
    spread = ", ".join(f"{sev}={count}" for sev, count in non_zero)
    return f"source disagreement detected ({spread}); treat with elevated analyst review."


def _is_active_conflict(result: AssessmentResult) -> bool:
    val_map = {v.claim_key: v for v in result.validation}
    official = val_map.get("official_advisory")
    if official and official.validated and official.severity == "critical":
        return True
    severe_claims = 0
    for key in ("terrorism_organized_violence", "violent_crime_kidnapping", "political_unrest"):
        v = val_map.get(key)
        if v and v.validated and v.severity in {"high", "critical"}:
            severe_claims += 1
    return severe_claims >= 2


def _top_risk_drivers(result: AssessmentResult, count: int = 3) -> list[str]:
    ranked = sorted(result.factors, key=lambda f: f.weighted_score, reverse=True)
    return [FACTOR_LABELS.get(f.factor, f.factor) for f in ranked[:count] if f.weighted_score > 0]


def render_quick_report(result: AssessmentResult) -> str:
    lines = []
    if _is_active_conflict(result):
        lines.extend(
            [
                "***ALERT*** ACTIVE CONFLICT / WARZONE SIGNAL DETECTED",
                "Validated high-severity conflict indicators are present for this destination.",
                "",
            ]
        )
    lines.extend(
        [
        "=== RiskBase Quick Posture ===",
        f"Run ID: {result.run_id}",
        f"Generated: {result.generated_at}",
        f"Advisory Posture: {result.posture}",
        f"Score: {result.total_score}/100",
        f"Summary: {result.summary}",
        "",
        "Immediate Recommendations:",
        ]
    )
    lines.extend(f"- {rec}" for rec in result.recommendations[:2])
    lines.append("")
    lines.append("Use -LR for full detail.")
    return "\n".join(lines)


def render_long_report(result: AssessmentResult, explain_score: bool = False) -> str:
    lines = []
    if _is_active_conflict(result):
        lines.extend(
            [
                "***ALERT*** ACTIVE CONFLICT / WARZONE SIGNAL DETECTED",
                "Validated critical/high conflict indicators are present. Treat destination as warzone-equivalent until disproven.",
                "",
            ]
        )
    drivers = _top_risk_drivers(result)
    lines.extend(
        [
        "=== RiskBase Detailed Assessment ===",
        f"Run ID: {result.run_id}",
        f"Generated: {result.generated_at}",
        f"Advisory Posture: {result.posture}",
        f"Score: {result.total_score}/100",
        "",
        "Decision Snapshot:",
        f"- Current posture: {result.posture} ({result.total_score}/100)",
        f"- Primary risk drivers: {', '.join(drivers) if drivers else 'No major drivers detected'}",
        f"- Action bias: {result.recommendations[0] if result.recommendations else 'No recommendation'}",
        "",
        "What Changed:",
        f"- {result.summary}",
        ]
    )

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
        claim_events = grouped_evidence.get(val.claim_key, [])
        lines.extend(
            [
                "",
                f"- {label} [{val.severity.upper()} | {status}]",
                f"  what this means: {CLAIM_MEANING.get(val.claim_key, 'Risk factor requires analyst review.')}",
                f"  why you should care: {CLAIM_WHY_MATTERS.get(val.claim_key, 'This factor can impact movement safety and reliability.')}",
                f"  evidence posture: {val.reason}",
                f"  conflict synthesis: {_factor_conflict_line(claim_events)}",
            ]
        )
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
