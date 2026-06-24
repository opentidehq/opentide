#!/usr/bin/env bash
# Local CI parity — run the same checks as .github/workflows/ci.yml before pushing.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

usage() {
  cat <<'EOF'
Usage: scripts/ci-local.sh [OPTIONS]

Run local checks that mirror GitHub CI. Faster than waiting on remote runners.

Options:
  --quick       Lint + type-check only (ruff, ty) — ~seconds
  --test        Lint + pytest without coverage — default
  --full        Lint + pytest + coverage gate (pyproject.toml fail_under) — pre-push
  --coverage    Alias for --full
  -h, --help    Show this help

Examples:
  scripts/ci-local.sh              # default: lint + tests
  scripts/ci-local.sh --quick      # before every commit (also via pre-commit)
  scripts/ci-local.sh --full       # before opening a PR
EOF
}

mode="test"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --quick) mode="quick" ;;
    --test) mode="test" ;;
    --full|--coverage) mode="full" ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage; exit 1 ;;
  esac
  shift
done

echo "==> Syncing dev dependencies"
uv sync --group dev --quiet

echo "==> Ruff check"
uv run ruff check tests src/opentide

echo "==> Ruff format"
uv run ruff format --check tests src/opentide

echo "==> Ty type check"
uv run ty check src/opentide

if [[ "$mode" == "quick" ]]; then
  echo "==> Quick checks passed"
  exit 0
fi

echo "==> Pytest with coverage"
if [[ "$mode" == "full" ]]; then
  # Same as CI COVERAGE_PYTHON cell: pytest addopts carry --cov; gate from pyproject.toml
  uv run pytest tests/ -q
  uv run coverage report
else
  uv run pytest tests/ --no-cov -q
fi

echo "==> All checks passed ($mode)"
