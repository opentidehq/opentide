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
  --quick       Lint + type-check + package build (ruff, ty, uv build)
  --test        Lint + unit pytest (excludes cli_e2e/cli_smoke) — default
  --full        Lint + unit pytest + coverage gate + CLI E2E (3.14) — pre-push
  --coverage    Alias for --full
  -h, --help    Show this help

Examples:
  scripts/ci-local.sh              # default: lint + unit tests
  scripts/ci-local.sh --quick      # before every commit (also via pre-commit)
  scripts/ci-local.sh --full       # before opening a PR (unit then E2E)
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

echo "==> uv build (sdist + wheel)"
uv build
echo "==> twine check"
uvx twine check dist/*

if [[ "$mode" == "quick" ]]; then
  echo "==> Quick checks passed"
  exit 0
fi

echo "==> Pytest"
unit_marker='not cli_e2e and not cli_smoke'
if [[ "$mode" == "full" ]]; then
  uv run pytest tests/ -q -m "$unit_marker"
  uv run coverage report
  echo "==> CLI E2E pytest"
  uv run pytest tests/test_cli/e2e/ -m "cli_e2e or cli_smoke" -q --no-cov
else
  uv run pytest tests/ --no-cov -q -m "$unit_marker"
fi

echo "==> All checks passed ($mode)"
