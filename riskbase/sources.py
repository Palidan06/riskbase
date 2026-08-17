from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from datetime import datetime, timezone
from hashlib import sha1
from html import unescape
from typing import Any

from .config import load_provider_aliases, load_provider_rules
from .models import EvidenceItem, UserInput, utc_now_iso


class SourceCollectionError(RuntimeError):
    def __init__(self, message: str, source_debug: dict[str, dict[str, str]]):
        super().__init__(message)
        self.source_debug = source_debug

def _event_id(seed: str) -> str:
    return sha1(seed.encode("utf-8")).hexdigest()[:12]


def _fetch_text(url: str, timeout: int = 15) -> str:
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "RiskBase/0.1 (+internal assessment tooling)",
            "Accept-Language": "en-US,en;q=0.8",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as response:
        html = response.read().decode("utf-8", errors="ignore")
    html = re.sub(r"<script.*?>.*?</script>", " ", html, flags=re.DOTALL | re.IGNORECASE)
    html = re.sub(r"<style.*?>.*?</style>", " ", html, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r"<[^>]+>", " ", html)
    text = unescape(text)
    return re.sub(r"\s+", " ", text).strip()


def _fetch_json(url: str, timeout: int = 20) -> Any:
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "RiskBase/0.1 (+internal assessment tooling)",
            "Accept": "application/json",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as response:
        return json.load(response)


def _slugify_country(country: str) -> str:
    normalized = country.strip().lower()
    return re.sub(r"[^a-z0-9]+", "-", normalized).strip("-")


def _severity_rank(value: str) -> int:
    return {"low": 0, "elevated": 1, "high": 2, "critical": 3}.get(value, 0)


def _max_severity(*values: str) -> str:
    return max(values, key=_severity_rank)


def _slice_relevant_text(provider_id: str, text: str) -> str:
    t = text.lower()
    if provider_id == "uk_fcdo_travel_advice":
        marker = "summary"
        idx = t.find(marker)
        if idx != -1:
            return text[idx : idx + 8000]
    if provider_id == "canada_travel_advisories":
        marker = "risk level"
        idx = t.find(marker)
        if idx != -1:
            return text[idx : idx + 8000]
    return text[:8000]


def _apply_patterns(text: str, patterns: list[dict[str, str]], fallback: str) -> str:
    detected = fallback
    for rule in patterns:
        if re.search(rule["regex"], text, flags=re.IGNORECASE):
            detected = _max_severity(detected, rule["severity"])
    return detected


def _severity_confidence(severity: str, source_tier: str = "tier1") -> float:
    base = {
        "low": 0.82,
        "elevated": 0.85,
        "high": 0.89,
        "critical": 0.92,
    }.get(severity, 0.8)
    return base if source_tier == "tier1" else max(0.5, base - 0.08)


def _provider_slug(destination: str, provider_id: str) -> str:
    aliases_cfg = load_provider_aliases()
    canonical_map = aliases_cfg.get("canonical_country_aliases", {})
    provider_map = aliases_cfg.get("provider_slugs", {}).get(provider_id, {})
    raw = destination.strip().lower()
    canonical = canonical_map.get(raw, raw)
    override_slug = provider_map.get(canonical)
    if override_slug:
        return override_slug
    return _slugify_country(canonical)


def _live_advisory_sources(destination: str) -> list[tuple[str, str, str, str]]:
    return [
        (
            "us_state_travel_advisories_api",
            "US State Advisories API",
            "https://cadataapi.state.gov/api/TravelAdvisories",
            "api",
        ),
        (
            "us_state_travel_advisories_api_mirror",
            "US State Advisories API Mirror",
            "https://ivvcadataapi.state.gov/api/TravelAdvisories",
            "api",
        ),
        (
            "uk_fcdo_travel_advice",
            "UK FCDO",
            f"https://www.gov.uk/foreign-travel-advice/{_provider_slug(destination, 'uk_fcdo_travel_advice')}",
            "html",
        ),
        (
            "canada_travel_advisories",
            "Canada Travel Advice",
            f"https://travel.gc.ca/destinations/{_provider_slug(destination, 'canada_travel_advisories')}",
            "html",
        ),
        (
            "us_state_travel_rss",
            "US State Advisories RSS",
            "https://travel.state.gov/_res/rss/TAsTWs.xml",
            "xml",
        ),
    ]


def _normalize_country_name(value: str) -> str:
    aliases_cfg = load_provider_aliases()
    canonical_map = aliases_cfg.get("canonical_country_aliases", {})
    normalized = re.sub(r"[^a-z0-9]+", " ", value.lower()).strip()
    return canonical_map.get(normalized, normalized)


def _normalize_city_name(value: str | None) -> str:
    if not value:
        return ""
    aliases_cfg = load_provider_aliases()
    canonical_map = aliases_cfg.get("canonical_city_aliases", {})
    normalized = re.sub(r"[^a-z0-9]+", " ", value.lower()).strip()
    return canonical_map.get(normalized, normalized)


def _provider_city_value(city: str, provider_id: str) -> str:
    if not city:
        return ""
    aliases_cfg = load_provider_aliases()
    provider_city_map = aliases_cfg.get("provider_city_aliases", {})
    provider_map = provider_city_map.get(provider_id, provider_city_map.get("default", {}))
    return provider_map.get(city, _slugify_country(city))


def _severity_from_level(level: int) -> str:
    return {
        1: "low",
        2: "elevated",
        3: "high",
        4: "critical",
    }.get(level, "elevated")


def _extract_state_api_entry(data: list[dict[str, Any]], destination: str) -> dict[str, Any] | None:
    needle = _normalize_country_name(destination)
    for item in data:
        title = str(item.get("Title", ""))
        country_part = title.split(" - ")[0].strip()
        if _normalize_country_name(country_part) == needle:
            return item
    return None


def _state_api_to_evidence(
    source_id: str,
    source_name: str,
    payload: dict[str, Any],
    key: str,
    now: str,
) -> list[EvidenceItem]:
    title = str(payload.get("Title", ""))
    summary = str(payload.get("Summary", ""))
    combined = f"{title} {summary}"
    excerpt = combined[:1200]
    m = re.search(r"level\s*([1-4])", title, flags=re.IGNORECASE)
    level = int(m.group(1)) if m else 2
    advisory_sev = _severity_from_level(level)

    rules = load_provider_rules()["providers"]["canada_travel_advisories"]
    factors = [
        "official_advisory",
        "political_unrest",
        "violent_crime_kidnapping",
        "terrorism_organized_violence",
        "health_bio_environmental",
        "infrastructure_transport",
    ]
    output: list[EvidenceItem] = []
    for claim_key in factors:
        if claim_key == "official_advisory":
            sev = advisory_sev
        else:
            factor_patterns = rules.get("factor_patterns", {}).get(claim_key, [])
            sev = _apply_patterns(combined, factor_patterns, fallback="low")
        output.append(
            EvidenceItem(
                source_id=source_id,
                source_name=source_name,
                tier="tier1",
                category="advisory",
                claim_key=claim_key,
                claim_text=f"US State advisory API indicates {sev} posture for {claim_key}.",
                event_time=now,
                fetched_at=now,
                severity=sev,
                confidence=_severity_confidence(sev),
                extraction_note="Live fetch and deterministic parse from US State API payload.",
                event_id=_event_id(f"{key}:{source_id}:{claim_key}:{now}"),
                metadata={"title": title, "link": payload.get("Link"), "excerpt": excerpt},
            )
        )
    return output


def _rss_text_for_destination(xml_text: str, destination: str) -> str:
    country = _normalize_country_name(destination)
    # Keep this simple and deterministic: find the first item block matching country.
    items = re.findall(r"<item>(.*?)</item>", xml_text, flags=re.DOTALL | re.IGNORECASE)
    for item in items:
        cleaned = re.sub(r"<[^>]+>", " ", item)
        cleaned = re.sub(r"\\s+", " ", unescape(cleaned)).strip()
        if country in _normalize_country_name(cleaned):
            return cleaned
    return ""


def collect_baseline_evidence(
    user_input: UserInput,
) -> tuple[list[EvidenceItem], dict[str, dict[str, str]], dict[str, str]]:
    destination = user_input.destination_country.strip().lower()
    canonical_destination = _normalize_country_name(destination)
    city = _normalize_city_name(user_input.destination_city)
    key = f"{destination}:{city}"
    now = utc_now_iso()
    provider_rules = load_provider_rules().get("providers", {})
    base: list[EvidenceItem] = []
    source_debug: dict[str, dict[str, str]] = {}
    normalization_debug: dict[str, str] = {
        "raw_destination_country": user_input.destination_country.strip(),
        "canonical_destination_country": canonical_destination,
        "raw_destination_city": (user_input.destination_city or "").strip(),
        "canonical_destination_city": city,
    }

    for source_id, source_name, url, source_type in _live_advisory_sources(destination):
        if source_type == "html":
            normalization_debug[f"{source_id}_country_slug"] = _provider_slug(destination, source_id)
        if city:
            normalization_debug[f"{source_id}_city_context"] = _provider_city_value(city, source_id)
        try:
            advisory_sev = "unknown"
            if source_type == "api":
                payload = _fetch_json(url)
                entry = _extract_state_api_entry(payload, destination)
                if not entry:
                    if _normalize_country_name(destination) == "united states":
                        raise RuntimeError(
                            "Destination not present in US outbound advisory set (expected for domestic destination)."
                        )
                    raise RuntimeError("Destination not found in API payload.")
                m = re.search(r"level\s*([1-4])", str(entry.get("Title", "")), flags=re.IGNORECASE)
                advisory_sev = _severity_from_level(int(m.group(1))) if m else "elevated"
                base.extend(_state_api_to_evidence(source_id, source_name, entry, key, now))
            elif source_type == "xml":
                req = urllib.request.Request(url, headers={"User-Agent": "RiskBase/0.1"})
                with urllib.request.urlopen(req, timeout=15) as response:
                    xml_text = response.read().decode("utf-8", errors="ignore")
                rss_text = _rss_text_for_destination(xml_text, destination)
                if not rss_text:
                    if _normalize_country_name(destination) == "united states":
                        raise RuntimeError(
                            "Destination not present in US outbound advisory RSS set (expected for domestic destination)."
                        )
                    raise RuntimeError("Destination not found in RSS feed.")
                rules = provider_rules.get("canada_travel_advisories", {})
                advisory_patterns = rules.get("advisory_patterns", [])
                advisory_sev = _apply_patterns(rss_text, advisory_patterns, fallback="elevated")
                for claim_key in [
                    "official_advisory",
                    "political_unrest",
                    "violent_crime_kidnapping",
                    "terrorism_organized_violence",
                    "health_bio_environmental",
                    "infrastructure_transport",
                ]:
                    if claim_key == "official_advisory":
                        sev = advisory_sev
                    else:
                        factor_patterns = rules.get("factor_patterns", {}).get(claim_key, [])
                        sev = _apply_patterns(rss_text, factor_patterns, fallback="low")
                    base.append(
                        EvidenceItem(
                            source_id=source_id,
                            source_name=source_name,
                            tier="tier1",
                            category="advisory",
                            claim_key=claim_key,
                            claim_text=f"US State RSS indicates {sev} posture for {claim_key}.",
                            event_time=now,
                            fetched_at=now,
                            severity=sev,
                            confidence=_severity_confidence(sev),
                            extraction_note="Live fetch and deterministic parse from US State RSS advisory text.",
                            event_id=_event_id(f"{key}:{source_id}:{claim_key}:{now}"),
                            metadata={"url": url, "excerpt": rss_text[:1200]},
                        )
                    )
            elif source_type == "html":
                text = _slice_relevant_text(source_id, _fetch_text(url))
                rules = provider_rules.get(source_id, {})
                advisory_patterns = rules.get("advisory_patterns", [])
                advisory_sev = _apply_patterns(text, advisory_patterns, fallback="elevated")
                for claim_key in [
                    "official_advisory",
                    "political_unrest",
                    "violent_crime_kidnapping",
                    "terrorism_organized_violence",
                    "health_bio_environmental",
                    "infrastructure_transport",
                ]:
                    if claim_key == "official_advisory":
                        sev = advisory_sev
                    else:
                        factor_patterns = rules.get("factor_patterns", {}).get(claim_key, [])
                        sev = _apply_patterns(text, factor_patterns, fallback="low")
                    base.append(
                        EvidenceItem(
                            source_id=source_id,
                            source_name=source_name,
                            tier="tier1",
                            category="advisory",
                            claim_key=claim_key,
                            claim_text=f"Live provider parse indicates {sev} posture for {claim_key}.",
                            event_time=now,
                            fetched_at=now,
                            severity=sev,
                            confidence=_severity_confidence(sev),
                            extraction_note=f"Live scrape and provider-rule parse from {url}",
                            event_id=_event_id(f"{key}:{source_id}:{claim_key}:{now}"),
                            metadata={"url": url, "excerpt": text[:1200]},
                        )
                    )
            source_debug[source_id] = {
                "source_name": source_name,
                "status": "ok",
                "url": url,
                "advisory_severity": advisory_sev,
                "country_match": "true",
                "details": (
                    "live fetch and provider-rule parsing succeeded"
                    + (f"; city_context={_provider_city_value(city, source_id)}" if city else "")
                ),
            }
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, RuntimeError) as exc:
            details = str(exc)
            status = "error"
            if "expected for domestic destination" in details:
                status = "not_applicable"
            source_debug[source_id] = {
                "source_name": source_name,
                "status": status,
                "url": url,
                "advisory_severity": "unknown",
                "country_match": "false",
                "details": details,
            }

    # Keep at most one US-State API source (primary preferred) to avoid duplicate-source inflation.
    if any(item.source_id == "us_state_travel_advisories_api" for item in base):
        base = [i for i in base if i.source_id != "us_state_travel_advisories_api_mirror"]

    if any(item.source_id == "us_state_travel_advisories_api" for item in base):
        base = [i for i in base if i.source_id != "us_state_travel_rss"]
    elif any(item.source_id == "us_state_travel_advisories_api_mirror" for item in base):
        base = [i for i in base if i.source_id != "us_state_travel_rss"]

    if not base:
        raise SourceCollectionError(
            "No live advisory sources available at query time. "
            "All configured sources failed during collection.",
            source_debug=source_debug,
        )

    return base, source_debug, normalization_debug


def collect_nrt_evidence(user_input: UserInput, window_hours: int) -> list[EvidenceItem]:
    # NRT ingestion is intentionally conservative until a dedicated
    # event feed adapter is configured. Returning no signals avoids
    # synthetic data while preserving strict live-only behavior.
    _ = (user_input, window_hours)
    return []
