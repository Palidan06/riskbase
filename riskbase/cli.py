from __future__ import annotations

import argparse
import json
from pathlib import Path

from .audit import write_audit_log
from .engine import AssessmentError, run_assessment
from .models import UserInput
from .reporting import render_json, render_long_report, render_quick_report


REPORTS_DIR = Path("Reports")
CONTINENT_NAMES = {
    "africa",
    "antarctica",
    "asia",
    "australia",
    "europe",
    "north america",
    "south america",
    "oceania",
}


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="riskbase",
        description="Internal travel threat posture CLI with validation-aware reporting.",
    )
    parser.add_argument("-LR", "--long-report", action="store_true", help="Generate long report.")
    parser.add_argument("-NRT", "--near-real-time", action="store_true", help="Enable NRT scan.")
    parser.add_argument(
        "--strict-country-match",
        dest="strict_country_match",
        action="store_true",
        help="Require canonical destination country match in at least two authoritative sources (default).",
    )
    parser.add_argument(
        "--no-strict-country-match",
        dest="strict_country_match",
        action="store_false",
        help="Disable strict country-match gating (not recommended).",
    )
    parser.set_defaults(strict_country_match=True)
    parser.add_argument("-O", "--output", type=str, help="Write report output to file path.")
    parser.add_argument("--json", action="store_true", help="Emit JSON output.")
    parser.add_argument(
        "--explain-score",
        action="store_true",
        help="Include weighted factor math and rationale.",
    )
    parser.add_argument(
        "--debug-sources",
        action="store_true",
        help="Print per-source fetch/parse diagnostic status.",
    )
    parser.add_argument(
        "--debug-normalization",
        action="store_true",
        help="Print country/city normalization and provider query mappings.",
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
        strict_country_match=bool(args.strict_country_match),
    )


def _resolve_output_path(raw_output: str) -> Path:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    return (REPORTS_DIR / Path(raw_output).name).resolve()


def _reset_for_new_location(args: argparse.Namespace) -> None:
    args.residence_country = None
    args.clearance_level = None
    args.agency = None
    args.destination_country = None
    args.destination_city = None


def _reset_destination_only(args: argparse.Namespace) -> None:
    args.destination_country = None
    args.destination_city = None


def _write_report_file(raw_output: str, text: str) -> Path:
    output_path = _resolve_output_path(raw_output)
    output_path.write_text(text + "\n", encoding="utf-8")
    return output_path


def _post_run_menu(
    args: argparse.Namespace,
    result,
    disclaimer: str,
    current_report_text: str,
) -> tuple[str, str]:
    source_debug = result.source_debug
    normalization_debug = result.normalization_debug
    while True:
        print("\nOptions:")
        print("1) Exit")
        print("2) Generate Deep Dive")
        print("3) Generate Report for Export")
        print("4) New Location")
        print("5) Show Source Debug")
        print("6) Show Normalization Debug")
        selection = input("Select option (1-6): ").strip()

        if selection == "1":
            return "exit", current_report_text
        if selection == "2":
            deep_text = render_long_report(result, explain_score=True) + disclaimer
            print("\n" + deep_text)
            current_report_text = deep_text
            continue
        if selection == "3":
            filename = args.output or input("Export filename (e.g. sudan.txt): ").strip()
            if not filename:
                print("No filename provided. Export canceled.")
                continue
            output_path = _write_report_file(filename, current_report_text)
            print(f"Saved report to {output_path}")
            continue
        if selection == "4":
            return "new_location", current_report_text
        if selection == "5":
            print("\nSource Debug:")
            print(json.dumps(source_debug, indent=2))
            continue
        if selection == "6":
            print("\nNormalization Debug:")
            print(json.dumps(normalization_debug, indent=2))
            continue
        print("Invalid selection. Enter a number from 1 to 6.")


def _normalize_geo(value: str | None) -> str:
    if not value:
        return ""
    normalized = "".join(ch.lower() if ch.isalnum() or ch.isspace() else " " for ch in value)
    return " ".join(normalized.split())


def _validate_destination_inputs(user_input: UserInput) -> tuple[bool, str]:
    destination_country = _normalize_geo(user_input.destination_country)
    destination_city = _normalize_geo(user_input.destination_city)

    if destination_country in CONTINENT_NAMES:
        hint = ""
        # Common operator mistake: country is continent, city is actually country.
        if destination_city in {"sudan", "iraq", "albania", "ukraine", "haiti"}:
            hint = f" Did you mean country '{user_input.destination_city}'?"
        return (
            False,
            f"Destination country '{user_input.destination_country}' appears to be a continent, not a country.{hint}",
        )
    return True, ""


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()
    while True:
        user_input = _prompt_if_missing(args)
        # Persist current answers as session defaults so retries only ask missing fields.
        args.residence_country = user_input.residence_country
        args.clearance_level = user_input.clearance_level
        args.agency = user_input.agency
        args.destination_country = user_input.destination_country
        args.destination_city = user_input.destination_city
        valid_destination, validation_message = _validate_destination_inputs(user_input)
        if not valid_destination:
            print(f"Input validation failed: {validation_message}")
            print("Please enter a valid destination country.")
            _reset_destination_only(args)
            continue

        source_debug: dict[str, dict[str, str]] = {}
        try:
            result = run_assessment(user_input, show_progress=user_input.long_report)
        except AssessmentError as exc:
            source_debug = exc.source_debug
            print("RiskBase could not complete a live validated assessment.")
            print(f"Reason: {exc}")
            if args.debug_sources and source_debug:
                print("\nSource Debug:")
                print(json.dumps(source_debug, indent=2))
            print("No static fallback was used. Please retry when sources are reachable.")
            raise SystemExit(2) from exc

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
        source_debug = result.source_debug
        normalization_debug = result.normalization_debug
        if args.debug_normalization and normalization_debug:
            print("\nNormalization Debug:")
            print(json.dumps(normalization_debug, indent=2))
        if args.debug_sources and source_debug:
            print("\nSource Debug:")
            print(json.dumps(source_debug, indent=2))

        if args.output:
            output_path = _write_report_file(args.output, output_text)
            print(f"\nSaved report to {output_path}")

        sources = sorted({e.source_id for e in result.evidence})
        log_path = write_audit_log(
            user_input=user_input,
            result=result,
            model_config_version="threat_taxonomy.v1",
            queried_sources=sources,
        )
        print(f"Audit record written to {log_path}")

        action, _ = _post_run_menu(args, result, disclaimer, output_text)
        if action == "new_location":
            _reset_for_new_location(args)
            continue
        if action == "exit":
            print("Session complete. Exiting RiskBase.")
            break
        print("Session complete. Exiting RiskBase.")
        break


if __name__ == "__main__":
    main()
