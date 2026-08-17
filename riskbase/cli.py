from __future__ import annotations

import argparse
from pathlib import Path

from .audit import write_audit_log
from .engine import run_assessment
from .models import UserInput
from .reporting import render_json, render_long_report, render_quick_report


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="riskbase",
        description="Internal travel threat posture CLI with validation-aware reporting.",
    )
    parser.add_argument("-LR", "--long-report", action="store_true", help="Generate long report.")
    parser.add_argument("-NRT", "--near-real-time", action="store_true", help="Enable NRT scan.")
    parser.add_argument("-O", "--output", type=str, help="Write report output to file path.")
    parser.add_argument("--json", action="store_true", help="Emit JSON output.")
    parser.add_argument(
        "--explain-score",
        action="store_true",
        help="Include weighted factor math and rationale.",
    )
    parser.add_argument("--residence-country", type=str, help="Country of residence.")
    parser.add_argument("--clearance-level", type=str, help="Security clearance level.")
    parser.add_argument("--agency", type=str, help="Agency or department.")
    parser.add_argument("--destination-country", type=str, help="Destination country.")
    parser.add_argument("--destination-city", type=str, help="Destination city (optional).")
    return parser


def _prompt_if_missing(args: argparse.Namespace) -> UserInput:
    residence_country = args.residence_country or input("Country of residence: ").strip()
    clearance_level = args.clearance_level or input("Security clearance level: ").strip()
    agency = args.agency or input("Agency/Department: ").strip()
    destination_country = args.destination_country or input("Destination country: ").strip()
    destination_city = args.destination_city
    if destination_city is None:
        prompt_city = input("Destination city (optional): ").strip()
        destination_city = prompt_city if prompt_city else None

    return UserInput(
        residence_country=residence_country,
        clearance_level=clearance_level,
        agency=agency,
        destination_country=destination_country,
        destination_city=destination_city,
        long_report=bool(args.long_report),
        nrt_enabled=bool(args.near_real_time),
    )


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()
    user_input = _prompt_if_missing(args)

    result = run_assessment(user_input, show_progress=user_input.long_report)

    if args.json:
        output_text = render_json(result)
    elif user_input.long_report:
        output_text = render_long_report(result, explain_score=bool(args.explain_score))
    else:
        output_text = render_quick_report(result)

    disclaimer = (
        "\n[Operational Notice] RiskBase is decision-support and must not be used as "
        "the sole authority for movement decisions."
    )
    output_text = output_text + disclaimer
    print(output_text)

    if args.output:
        output_path = Path(args.output).expanduser().resolve()
        output_path.write_text(output_text + "\n", encoding="utf-8")
        print(f"\nSaved report to {output_path}")

    if not user_input.long_report:
        answer = input("\nWould you like a deeper dive? (yes/no): ").strip().lower()
        if answer in {"yes", "y"}:
            long_text = render_long_report(result, explain_score=True)
            long_text = long_text + disclaimer
            print("\n" + long_text)
            if args.output:
                output_path = Path(args.output).expanduser().resolve()
                output_path.write_text(long_text + "\n", encoding="utf-8")
                print(f"\nSaved detailed report to {output_path}")
        else:
            print("Session complete. Exiting RiskBase.")

    sources = sorted({e.source_id for e in result.evidence})
    log_path = write_audit_log(
        user_input=user_input,
        result=result,
        model_config_version="threat_taxonomy.v1",
        queried_sources=sources,
    )
    print(f"Audit record written to {log_path}")


if __name__ == "__main__":
    main()
