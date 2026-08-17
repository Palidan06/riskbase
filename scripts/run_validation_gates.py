#!/usr/bin/env python3
from __future__ import annotations

import json
import sys

from riskbase.validation_runner import run_validation_suite


def main() -> int:
    result = run_validation_suite()
    print(json.dumps(result, indent=2))
    if result["promote"]:
        print("\nValidation gate result: PROMOTE")
        return 0
    print("\nValidation gate result: ADVISORY_BETA (tuning required)")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
