from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class UserInput:
    residence_country: str
    clearance_level: str
    agency: str
    destination_country: str
    destination_city: str | None = None
    long_report: bool = False
    nrt_enabled: bool = False


@dataclass
class EvidenceItem:
    source_id: str
    source_name: str
    tier: str
    category: str
    claim_key: str
    claim_text: str
    event_time: str
    fetched_at: str
    severity: str
    confidence: float
    extraction_note: str
    event_id: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ValidationResult:
    claim_key: str
    severity: str
    independent_sources: int
    authoritative_source_present: bool
    validated: bool
    provisional: bool
    reason: str


@dataclass
class FactorScore:
    factor: str
    base_score: float
    weight: float
    weighted_score: float
    confidence: float
    rationale: str


@dataclass
class AssessmentResult:
    run_id: str
    generated_at: str
    posture: str
    total_score: float
    factors: list[FactorScore]
    evidence: list[EvidenceItem]
    validation: list[ValidationResult]
    summary: str
    recommendations: list[str]
    nrt_summary: str | None = None
