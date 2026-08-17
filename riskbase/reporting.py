from __future__ import annotations

import json
from dataclasses import asdict

from .models import AssessmentResult
from .scoring import FACTOR_LABELS


def _fmt_pct(v: float) -> str:
    return f"{round(v * 100, 1)}%"


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

    lines.extend(["", "Evidence Ledger:"])
    for ev in result.evidence:
        lines.append(
            f"- [{ev.source_name}/{ev.source_id}] {ev.claim_key} | {ev.severity} | "
            f"{ev.event_time} | conf={_fmt_pct(ev.confidence)} | {ev.claim_text}"
        )
    return "\n".join(lines)


def render_json(result: AssessmentResult) -> str:
    return json.dumps(asdict(result), indent=2)
