from __future__ import annotations

import re

from .models import UserInput


def parse_clearance_text(clearance: str) -> dict[str, bool]:
    text = clearance.lower()
    return {
        "has_secret": bool(re.search(r"\bsecret\b|\bs\b", text)),
        "has_top_secret": bool(re.search(r"\btop\s*secret\b|\bts\b", text)),
        "has_sci": "sci" in text,
        "has_ci_poly": "ci poly" in text or "counterintelligence poly" in text or "cip" in text,
        "has_sap": "sap" in text,
    }


def clearance_exposure_modifier(user_input: UserInput, base_score: float) -> tuple[float, str]:
    parsed = parse_clearance_text(user_input.clearance_level)
    modifier = 0.0
    if parsed["has_secret"]:
        modifier += 1.0
    if parsed["has_top_secret"]:
        modifier += 2.5
    if parsed["has_sci"]:
        modifier += 2.5
    if parsed["has_ci_poly"]:
        modifier += 1.5
    if parsed["has_sap"]:
        modifier += 1.5

    if base_score >= 50:
        modifier *= 1.4
    elif base_score >= 25:
        modifier *= 1.15

    rationale = (
        "Clearance profile sensitivity modifier applied for targeting/handling risk "
        f"(+{round(modifier,2)})."
        if modifier > 0
        else "No clearance-based sensitivity modifier applied."
    )
    return round(modifier, 2), rationale
