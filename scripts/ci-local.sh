#!/usr/bin/env bash
# Local CI parity — run the same checks as .github/workflows/ci.yml before pushing.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# CI runners export none of these. A shell that does changes what the CLI
# prints, which hides output drift from the golden tests until CI runs them.
unset NO_COLOR FORCE_COLOR PY_COLORS CLICOLOR_FORCE

# This script runs from the pre-push hook, and `git push` exports the
# repository-location GIT_* family to its hooks. Those variables take
# precedence over any `cwd`, so anything below that invokes git -- including
# the test fixtures that create throwaway repositories -- would operate on THIS
# checkout instead. That once switched a contributor's worktree to a fixture
# branch and published a commit deleting the repository.
#
# The suite also strips these in tests/conftest.py; doing it here as well
# protects the steps that are not pytest.
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_OBJECT_DIRECTORY \
      GIT_ALTERNATE_OBJECT_DIRECTORIES GIT_COMMON_DIR GIT_NAMESPACE \
      GIT_CEILING_DIRECTORIES GIT_PREFIX

usage() {
  cat <<'EOF'
Usage: scripts/ci-local.sh [OPTIONS]

Run local checks that mirror GitHub CI. Faster than waiting on remote runners.

Options:
  --quick       Lint + type-check + package build (ruff, ty, uv build)
  --test        Lint + unit pytest (excludes cli_e2e/cli_smoke) — default
  --full        Lint + unit pytest + coverage gate + CLI E2E + GitLab CI lint — pre-push
  --coverage    Alias for --full
  --store-e2e-durations
                Re-measure the E2E suite serially and rewrite
                .test_durations_e2e, which balances the CI shard matrix.
                Run it after adding or removing slow E2E tests; commit the
                result. Takes about as long as a serial E2E run (~9 min).
  -h, --help    Show this help

Environment:
  PYTEST_WORKERS  xdist worker count for the E2E suite (default: 4, matching
                  ci.yml). 0 runs it serially, which is what you want to read a
                  failure. More is not reliably faster -- each worker holds an
                  interpreter plus a spawned subprocess, and `auto` measured
                  slower than 4 on a 10-core host.

Examples:
  scripts/ci-local.sh              # default: lint + unit tests
  scripts/ci-local.sh --quick      # before every commit (also via pre-commit)
  scripts/ci-local.sh --full       # before opening a PR (unit then E2E)
  PYTEST_WORKERS=0 scripts/ci-local.sh   # serial, readable output
EOF
}

mode="test"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --quick) mode="quick" ;;
    --test) mode="test" ;;
    --full|--coverage) mode="full" ;;
    --store-e2e-durations) mode="store-e2e-durations" ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage; exit 1 ;;
  esac
  shift
done

echo "==> Syncing dev dependencies"
uv sync --group dev --quiet

if [[ "$mode" == "store-e2e-durations" ]]; then
  echo "==> Re-measuring E2E durations (serial) -> .test_durations_e2e"
  # Serial on purpose. Durations recorded under xdist absorb worker startup and
  # CPU contention, which skews the per-test weights the shard packer reads and
  # would unbalance CI rather than improve it.
  uv run pytest tests/ -m "cli_e2e or cli_smoke" -q --no-cov \
    --store-durations --durations-path .test_durations_e2e
  echo "==> Wrote .test_durations_e2e — commit it to keep the CI shards balanced"
  exit 0
fi

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
unit_marker='not cli_e2e and not cli_smoke and not gitlab_ci_lint'

# Both suites are sharded. The E2E one is the long pole -- 722 tests, mostly
# console-script subprocesses. The unit suite was serial until #530: a few tests
# left a partial index in IndexManager._cache and a mocked registry in
# opentide.deployment.utils, so it passed only because the serial file order put
# the victims before the polluters. Both leaks are fixed and the suite now gives
# the same result serially and at -n 2/4/8, with identical coverage totals.
# Mirrors ci.yml. PYTEST_WORKERS=0 forces serial.
#
# Defaults to 4 to match ci.yml, NOT to `auto`. Each worker holds an interpreter
# plus the subprocess its test spawned, so the suite hits a memory cliff before
# it runs out of cores: on a 10-core host one E2E shard measured 62s at -n 4 and
# 137s at `auto` (10 workers), i.e. `auto` was slower than 4. If you have the
# headroom, PYTEST_WORKERS=6 measured best here -- but measure, do not assume
# more is faster.
workers="${PYTEST_WORKERS:-4}"
if [[ "$workers" == "0" ]]; then
  parallel=()
else
  parallel=(-n "$workers")
fi

# coverage's sys.monitoring backend (PEP 669) costs roughly half what the C
# trace function does for the same line data, but it needs 3.12+. The gate runs
# on whatever interpreter uv resolved here, which may be older.
cov_env=()
if uv run python -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 12) else 1)'; then
  cov_env=(env COVERAGE_CORE=sysmon)
fi

if [[ "$mode" == "full" ]]; then
  "${cov_env[@]}" uv run pytest tests/ -q "${parallel[@]}" -m "$unit_marker"
  uv run coverage report
  echo "==> E2E pytest (CLI + MCP stdio)"
  uv run pytest tests/ -m "cli_e2e or cli_smoke" -q "${parallel[@]}" --no-cov
  echo "==> Generated GitLab CI lint (glint + gitlab-ci-verify)"
  linters="$ROOT/.cache/gitlab-ci-linters"
  bash scripts/install-gitlab-ci-linters.sh "$linters"
  PATH="$linters:$PATH" OPENTIDE_GITLAB_CI_LINT=1 \
    uv run pytest tests/test_ci/test_gitlab_pipeline_lint.py -m gitlab_ci_lint -q --no-cov
else
  uv run pytest tests/ --no-cov -q "${parallel[@]}" -m "$unit_marker"
fi

echo "==> All checks passed ($mode)"
