#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_DIR="${ROOT_DIR}/.venv"

echo "[riskbase] Creating virtual environment at ${VENV_DIR}"
python3 -m venv "${VENV_DIR}"

echo "[riskbase] Activating virtual environment"
# shellcheck disable=SC1091
source "${VENV_DIR}/bin/activate"

echo "[riskbase] Upgrading pip"
python -m pip install --upgrade pip

echo "[riskbase] Installing RiskBase (editable)"
python -m pip install -e "${ROOT_DIR}"

echo
echo "[riskbase] Setup complete."
echo "Activate with:"
echo "  source .venv/bin/activate"
echo
echo "Run examples:"
echo "  riskbase"
echo "  riskbase -LR -NRT --explain-score"
