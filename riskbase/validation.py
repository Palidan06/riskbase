from __future__ import annotations

from collections import defaultdict

from .models import EvidenceItem, ValidationResult


SEVERITY_ORDER = {"low": 0, "elevated": 1, "high": 2, "critical": 3}


def deduplicate_evidence(evidence: list[EvidenceItem]) -> list[EvidenceItem]:
    seen: set[tuple[str, str, str]] = set()
    unique: list[EvidenceItem] = []
    for item in evidence:
        key = (item.claim_key, item.source_id, item.event_id)
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)
    return unique


def _highest_severity(severities: list[str]) -> str:
    return max(severities, key=lambda s: SEVERITY_ORDER.get(s, 0))


def validate_claims(
    evidence: list[EvidenceItem], thresholds: dict[str, dict[str, int | bool]]
) -> list[ValidationResult]:
    grouped: dict[str, list[EvidenceItem]] = defaultdict(list)
    for item in evidence:
        grouped[item.claim_key].append(item)

    results: list[ValidationResult] = []
    for claim_key, items in grouped.items():
        severity = _highest_severity([i.severity for i in items])
        threshold = thresholds.get(severity, thresholds["elevated"])

        independent_sources = len({i.source_id for i in items})
        authoritative = any(i.tier == "tier1" for i in items)
        min_sources = int(threshold["minimum_independent_sources"])
        allow_tier1_plus_corrob = bool(threshold["allow_tier1_plus_corrob"])

        validated = independent_sources >= min_sources
        if not validated and allow_tier1_plus_corrob and authoritative and independent_sources >= 2:
            validated = True

        provisional = not validated
        reason = (
            f"validated with {independent_sources} independent source(s)"
            if validated
            else f"insufficient corroboration ({independent_sources}/{min_sources})"
        )
        results.append(
            ValidationResult(
                claim_key=claim_key,
                severity=severity,
                independent_sources=independent_sources,
                authoritative_source_present=authoritative,
                validated=validated,
                provisional=provisional,
                reason=reason,
            )
        )
    return results
