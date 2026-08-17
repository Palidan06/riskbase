from __future__ import annotations

import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
SPECS_DIR = ROOT / "specs"


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def load_threat_taxonomy() -> dict[str, Any]:
    return load_json(SPECS_DIR / "threat_taxonomy.v1.json")


def load_source_registry() -> dict[str, Any]:
    return load_json(SPECS_DIR / "source_registry.v1.json")


def load_provider_rules() -> dict[str, Any]:
    return load_json(SPECS_DIR / "provider_rules.v1.json")


def load_provider_aliases() -> dict[str, Any]:
    return load_json(SPECS_DIR / "provider_aliases.v1.json")
