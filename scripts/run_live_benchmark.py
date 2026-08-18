#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from riskbase.benchmark_runner import run_live_benchmark


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="run_live_benchmark",
        description="Run 50-location live benchmark and report first-run error rate.",
    )
    parser.add_argument(
        "--max-error-rate",
        type=float,
        default=0.15,
        help="Maximum acceptable first-run error rate (e.g. 0.15 for 15%%, 0.0015 for 0.15%%).",
    )
    parser.add_argument(
        "--output",
        type=str,
        default="Reports/live_benchmark_results.json",
        help="Output path for JSON benchmark report.",
    )
    parser.add_argument("--residence-country", type=str, default="United States")
    parser.add_argument("--clearance-level", type=str, default="Secret")
    parser.add_argument("--agency", type=str, default="CIA")
    args = parser.parse_args()

    result = run_live_benchmark(
        max_error_rate=args.max_error_rate,
        residence_country=args.residence_country,
        clearance_level=args.clearance_level,
        agency=args.agency,
    )

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(result, indent=2), encoding="utf-8")

    print(json.dumps(result["summary"], indent=2))
    print(f"\nSaved benchmark report to {output_path.resolve()}")
    if result["summary"]["pass"]:
        print("Live benchmark result: PASS")
        return 0
    print("Live benchmark result: FAIL")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
