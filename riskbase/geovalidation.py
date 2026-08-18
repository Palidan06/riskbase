from __future__ import annotations

import json
import subprocess
import urllib.parse
import urllib.request

from .config import load_provider_aliases
from .models import UserInput


class GeographyValidationError(RuntimeError):
    pass


def _canonical_country(value: str) -> str:
    aliases_cfg = load_provider_aliases()
    canonical_map = aliases_cfg.get("canonical_country_aliases", {})
    normalized = "".join(ch.lower() if ch.isalnum() or ch.isspace() else " " for ch in value).strip()
    normalized = " ".join(normalized.split())
    return canonical_map.get(normalized, normalized)


def _fetch_json(url: str, timeout: int = 15) -> list[dict]:
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "RiskBase/0.1 (+internal assessment tooling)",
            "Accept": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            return json.load(response)
    except Exception:
        # Some environments have Python TLS trust-store issues while system curl succeeds.
        proc = subprocess.run(
            ["curl", "-sS", "--max-time", str(timeout), url],
            check=True,
            capture_output=True,
            text=True,
        )
        return json.loads(proc.stdout)


def validate_destination_geography(user_input: UserInput) -> tuple[bool, str]:
    raw_country = user_input.destination_country.strip()
    country = _canonical_country(raw_country)
    city = (user_input.destination_city or "").strip()
    state = (user_input.destination_state or "").strip()

    # Validate destination country name first.
    country_params = {
        "format": "jsonv2",
        "limit": "1",
        "country": country,
    }
    country_url = "https://nominatim.openstreetmap.org/search?" + urllib.parse.urlencode(country_params)
    try:
        country_rows = _fetch_json(country_url)
    except Exception as exc:
        raise GeographyValidationError(f"Could not validate destination geography: {exc}") from exc
    if not country_rows:
        return (
            False,
            f"No live geographic match found for destination country '{raw_country}'. Please verify spelling.",
        )

    if not city:
        return True, ""

    params = {
        "format": "jsonv2",
        "limit": "3",
        "country": country,
        "city": city,
    }
    if state:
        params["state"] = state
    url = "https://nominatim.openstreetmap.org/search?" + urllib.parse.urlencode(params)
    try:
        rows = _fetch_json(url)
    except Exception as exc:
        raise GeographyValidationError(f"Could not validate destination geography: {exc}") from exc

    if not rows:
        if state:
            return (
                False,
                f"No live geographic match found for '{city}, {state}, {country}'. "
                "Please verify spelling or enter a real city/state combination.",
            )
        return (
            False,
            f"No live geographic match found for '{city}, {country}'. "
            "Please verify spelling or provide state/province where applicable.",
        )

    return True, ""


def validate_country_name(country: str, field_label: str = "country") -> tuple[bool, str]:
    raw = country.strip()
    canonical = _canonical_country(raw)
    if not raw:
        return False, f"{field_label.capitalize()} cannot be empty."
    params = {
        "format": "jsonv2",
        "limit": "1",
        "country": canonical,
    }
    url = "https://nominatim.openstreetmap.org/search?" + urllib.parse.urlencode(params)
    try:
        rows = _fetch_json(url)
    except Exception as exc:
        raise GeographyValidationError(f"Could not validate {field_label}: {exc}") from exc
    if not rows:
        return False, f"No live geographic match found for {field_label} '{raw}'. Please verify spelling."
    return True, ""
