from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path

from .engine import AssessmentError, run_assessment
from .models import UserInput

POSTURE_RANK = {
    "Low Concern": 0,
    "Elevated Concern": 1,
    "High Concern": 2,
    "Critical Concern": 3,
}


@dataclass
class BenchmarkOutcome:
    case_id: str
    continent: str
    country: str
    city: str | None
    state: str | None
    expected_min_posture: str
    expected_max_posture: str
    status: str
    posture: str | None = None
    score: float | None = None
    error_bucket: str | None = None
    notes: str | None = None


def _load_benchmark_locations() -> list[dict]:
    spec_path = Path(__file__).resolve().parent.parent / "specs" / "benchmark_locations.v1.json"
    payload = json.loads(spec_path.read_text(encoding="utf-8"))
    return payload["locations"]


def _expected_band_ok(posture: str, expected_min: str, expected_max: str) -> bool:
    posture_rank = POSTURE_RANK[posture]
    min_rank = POSTURE_RANK[expected_min]
    max_rank = POSTURE_RANK[expected_max]
    return min_rank <= posture_rank <= max_rank


def _source_outage_note(source_debug: dict[str, dict[str, str]]) -> str:
    failed = []
    for source_id, meta in source_debug.items():
        status = meta.get("status")
        if status in {"error", "timeout"}:
            failed.append(f"{source_id}:{meta.get('details', 'source error')}")
    return "; ".join(failed)


def run_live_benchmark(
    max_error_rate: float = 0.15,
    residence_country: str = "United States",
    clearance_level: str = "Secret",
    agency: str = "CIA",
) -> dict:
    locations = _load_benchmark_locations()
    outcomes: list[BenchmarkOutcome] = []

    evaluated_count = 0
    error_count = 0
    source_unavailable_count = 0
    bucket_counts = {
        "overcall": 0,
        "undercall": 0,
        "source_outage": 0,
        "assessment_error": 0,
    }
    continent_coverage: dict[str, int] = {}

    for loc in locations:
        continent = loc["continent"]
        continent_coverage[continent] = continent_coverage.get(continent, 0) + 1
        user_input = UserInput(
            residence_country=residence_country,
            clearance_level=clearance_level,
            agency=agency,
            destination_country=loc["country"],
            destination_city=loc.get("city"),
            destination_state=loc.get("state"),
            long_report=False,
            nrt_enabled=False,
            strict_country_match=True,
        )
        try:
            result = run_assessment(user_input, show_progress=False)
        except AssessmentError as exc:
            outage_note = _source_outage_note(exc.source_debug)
            status = "source_unavailable" if outage_note else "assessment_error"
            if status == "source_unavailable":
                bucket_counts["source_outage"] += 1
                source_unavailable_count += 1
            else:
                bucket_counts["assessment_error"] += 1
            outcomes.append(
                BenchmarkOutcome(
                    case_id=loc["id"],
                    continent=continent,
                    country=loc["country"],
                    city=loc.get("city"),
                    state=loc.get("state"),
                    expected_min_posture=loc["expected_min_posture"],
                    expected_max_posture=loc["expected_max_posture"],
                    status=status,
                    error_bucket=status,
                    notes=outage_note or str(exc),
                )
            )
            continue

        evaluated_count += 1
        posture = result.posture
        score = result.total_score
        expected_min = loc["expected_min_posture"]
        expected_max = loc["expected_max_posture"]
        if _expected_band_ok(posture, expected_min, expected_max):
            outcomes.append(
                BenchmarkOutcome(
                    case_id=loc["id"],
                    continent=continent,
                    country=loc["country"],
                    city=loc.get("city"),
                    state=loc.get("state"),
                    expected_min_posture=expected_min,
                    expected_max_posture=expected_max,
                    status="pass",
                    posture=posture,
                    score=score,
                )
            )
            continue

        error_count += 1
        predicted_rank = POSTURE_RANK[posture]
        min_rank = POSTURE_RANK[expected_min]
        error_bucket = "overcall" if predicted_rank > min_rank else "undercall"
        bucket_counts[error_bucket] += 1
        outcomes.append(
            BenchmarkOutcome(
                case_id=loc["id"],
                continent=continent,
                country=loc["country"],
                city=loc.get("city"),
                state=loc.get("state"),
                expected_min_posture=expected_min,
                expected_max_posture=expected_max,
                status="error",
                posture=posture,
                score=score,
                error_bucket=error_bucket,
            )
        )

    first_run_error_rate = (error_count / evaluated_count) if evaluated_count else 1.0
    pass_threshold = first_run_error_rate <= max_error_rate

    return {
        "summary": {
            "total_locations": len(locations),
            "continents_tested": len(continent_coverage),
            "continent_coverage": continent_coverage,
            "evaluated_locations": evaluated_count,
            "source_unavailable_locations": source_unavailable_count,
            "error_locations": error_count,
            "first_run_error_rate": round(first_run_error_rate, 4),
            "max_error_rate_threshold": max_error_rate,
            "pass": pass_threshold,
            "error_buckets": bucket_counts,
        },
        "outcomes": [asdict(o) for o in outcomes],
    }
