from __future__ import annotations

from datetime import datetime, timedelta, timezone
from hashlib import sha1

from .models import EvidenceItem, UserInput, utc_now_iso


def _event_id(seed: str) -> str:
    return sha1(seed.encode("utf-8")).hexdigest()[:12]


def _iso_hours_ago(hours: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()


def collect_baseline_evidence(user_input: UserInput) -> list[EvidenceItem]:
    destination = user_input.destination_country.strip().lower()
    city = (user_input.destination_city or "").strip().lower()
    key = f"{destination}:{city}"
    now = utc_now_iso()

    base: list[EvidenceItem] = [
        EvidenceItem(
            source_id="us_state_travel_advisories",
            source_name="US State Dept",
            tier="tier1",
            category="advisory",
            claim_key="official_advisory",
            claim_text="Government advisory indicates elevated caution.",
            event_time=_iso_hours_ago(18),
            fetched_at=now,
            severity="elevated",
            confidence=0.88,
            extraction_note="Mapped advisory level to posture factor.",
            event_id=_event_id(f"{key}:advisory:us"),
        ),
        EvidenceItem(
            source_id="canada_travel_advisories",
            source_name="Canada Travel Advice",
            tier="tier1",
            category="advisory",
            claim_key="official_advisory",
            claim_text="Corroborating advisory notes regional protest risk.",
            event_time=_iso_hours_ago(20),
            fetched_at=now,
            severity="elevated",
            confidence=0.86,
            extraction_note="Cross-advisory corroboration.",
            event_id=_event_id(f"{key}:advisory:ca"),
        ),
        EvidenceItem(
            source_id="reliefweb_disasters",
            source_name="ReliefWeb",
            tier="tier2",
            category="humanitarian",
            claim_key="infrastructure_transport",
            claim_text="Transportation disruption reported near destination corridor.",
            event_time=_iso_hours_ago(7),
            fetched_at=now,
            severity="high",
            confidence=0.76,
            extraction_note="Disaster/incident metadata indicates movement friction.",
            event_id=_event_id(f"{key}:infra:rw"),
        ),
    ]

    if destination in {"haiti", "ukraine", "sudan"}:
        base.append(
            EvidenceItem(
                source_id="uk_fcdo_travel_advice",
                source_name="UK FCDO",
                tier="tier1",
                category="advisory",
                claim_key="terrorism_organized_violence",
                claim_text="Official advisory references severe armed violence risk.",
                event_time=_iso_hours_ago(10),
                fetched_at=now,
                severity="critical",
                confidence=0.93,
                extraction_note="High-severity advisory language extracted.",
                event_id=_event_id(f"{key}:violence:uk"),
            )
        )
    else:
        base.append(
            EvidenceItem(
                source_id="open_local_social",
                source_name="Open Local Signals",
                tier="tier3",
                category="osint",
                claim_key="political_unrest",
                claim_text="Localized chatter about possible demonstrations.",
                event_time=_iso_hours_ago(5),
                fetched_at=now,
                severity="elevated",
                confidence=0.54,
                extraction_note="Unverified public-signal extraction.",
                event_id=_event_id(f"{key}:unrest:osint"),
            )
        )

    return base


def collect_nrt_evidence(user_input: UserInput, window_hours: int) -> list[EvidenceItem]:
    destination = user_input.destination_country.strip().lower()
    city = (user_input.destination_city or "").strip().lower()
    now = utc_now_iso()
    key = f"{destination}:{city}:nrt:{window_hours}"
    signals: list[EvidenceItem] = []
    if destination in {"albania", "france", "mexico"}:
        signals.append(
            EvidenceItem(
                source_id="open_local_social",
                source_name="Open Local Signals",
                tier="tier3",
                category="osint",
                claim_key="political_unrest",
                claim_text="Recent social reports of gathering near transit routes.",
                event_time=_iso_hours_ago(2),
                fetched_at=now,
                severity="elevated",
                confidence=0.47,
                extraction_note="Near-real-time signal; not yet corroborated.",
                event_id=_event_id(f"{key}:social"),
            )
        )
    if destination in {"ukraine", "haiti", "sudan"}:
        signals.append(
            EvidenceItem(
                source_id="reliefweb_disasters",
                source_name="ReliefWeb",
                tier="tier2",
                category="humanitarian",
                claim_key="infrastructure_transport",
                claim_text="Fresh report indicates active movement constraints.",
                event_time=_iso_hours_ago(1),
                fetched_at=now,
                severity="high",
                confidence=0.79,
                extraction_note="NRT feed update within active window.",
                event_id=_event_id(f"{key}:rw"),
            )
        )
    return signals
