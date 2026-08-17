from __future__ import annotations

import hashlib
import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from .models import AssessmentResult, UserInput


def _sha256(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def write_audit_log(
    user_input: UserInput,
    result: AssessmentResult,
    model_config_version: str,
    queried_sources: list[str],
) -> Path:
    root = Path(".riskbase")
    root.mkdir(parents=True, exist_ok=True)
    log_path = root / "audit.jsonl"

    result_json = json.dumps(asdict(result), sort_keys=True, default=str)
    output_hash = _sha256(result_json)
    payload: dict[str, Any] = {
        "run_id": result.run_id,
        "generated_at": result.generated_at,
        "input": asdict(user_input),
        "sources_queried": queried_sources,
        "model_config_version": model_config_version,
        "output_hash_sha256": output_hash,
    }
    with log_path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(payload) + "\n")
    return log_path
