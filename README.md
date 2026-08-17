# RiskBase

RiskBase is an internal-only terminal application for rapid travel threat posture assessment and evidence-backed deep-dive reporting.

## Features

- Fast advisory posture output.
- Optional long report mode.
- Near-real-time supplemental scan mode.
- Multi-source validation states and confidence indicators.
- Terminal output and optional file export.

## Install

```bash
python3 -m pip install -e .
```

## Dev Setup (Recommended)

```bash
./scripts/dev-setup.sh
source .venv/bin/activate
```

## Usage

```bash
riskbase
riskbase -LR -O albania.txt
riskbase -NRT --explain-score
riskbase --json
riskbase --debug-normalization --debug-sources
riskbase --no-strict-country-match
```

## Validation Defaults

- Strict country matching is enabled by default.
- RiskBase requires at least two authoritative sources to positively match the destination country before scoring.
- To disable this gate for troubleshooting only, use:

```bash
riskbase --no-strict-country-match
```

## Debug Flags

- `--debug-normalization` prints canonical destination normalization and provider query mappings.
- `--debug-sources` prints per-source fetch/parse status and details.

## Man Page

A man page is included at `man/man1/riskbase.1`.

To install locally:

```bash
mkdir -p ~/.local/share/man/man1
cp man/man1/riskbase.1 ~/.local/share/man/man1/
man riskbase
```

## Safety Note

RiskBase is decision support, not sole authority. Always combine output with organizational policy and live operational command guidance.
