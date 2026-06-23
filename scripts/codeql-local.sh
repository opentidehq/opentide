#!/usr/bin/env bash
# Optional local CodeQL — mirrors .github/workflows/codeql.yml (security-extended).
#
# NOT wired into pre-commit or pre-push: each run rebuilds the full CodeQL database
# (~15–25s) and evaluates all queries (~20–40s). No incremental analysis yet.
#
# Usage:
#   scripts/codeql-local.sh              # create DB + analyze Python
#   scripts/codeql-local.sh --install    # brew install CodeQL CLI only
#   scripts/codeql-local.sh --help
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

DB_DIR="${CODEQL_DB_DIR:-${ROOT}/.codeql-db}"
SARIF_OUT="${ROOT}/codeql-results.sarif"
QUERY_SUITE="codeql/python-queries:codeql-suites/python-security-extended.qls"
INSTALL_ONLY=0

usage() {
  sed -n '2,12p' "$0"
  echo
  echo "Environment:"
  echo "  CODEQL_DB_DIR   Database path (default: .codeql-db/)"
}

for arg in "$@"; do
  case "$arg" in
    --install) INSTALL_ONLY=1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $arg" >&2; usage; exit 1 ;;
  esac
done

ensure_codeql() {
  if command -v codeql >/dev/null 2>&1; then
    echo "CodeQL: $(codeql version | head -1)"
    return 0
  fi
  if command -v brew >/dev/null 2>&1; then
    echo "==> Installing CodeQL CLI (brew cask)"
    brew install --cask codeql
    return 0
  fi
  echo "Install CodeQL: https://github.com/github/codeql-cli-binaries/releases" >&2
  exit 1
}

ensure_codeql
[[ "$INSTALL_ONLY" == 1 ]] && exit 0

echo "==> Syncing dependencies"
uv sync --group dev --quiet

echo "==> Creating CodeQL database (Python)"
rm -rf "$DB_DIR"
codeql database create "$DB_DIR" --language=python --source-root="$ROOT" --overwrite

echo "==> Downloading query packs (if needed)"
codeql pack download codeql/python-queries >/dev/null

echo "==> Analyzing (security-extended)"
codeql database analyze "$DB_DIR" "$QUERY_SUITE" \
  --format=sarif-latest \
  --output="$SARIF_OUT"

echo
echo "==> Done"
echo "  SARIF: ${SARIF_OUT}"
echo "  Upload in CI is automatic via .github/workflows/codeql.yml"
echo "  Typical local runtime: ~40–60s cold (not suitable for pre-commit hooks)"
