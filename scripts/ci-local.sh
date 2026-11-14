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
  --quick       Lint + type-check + package build (ruff, ty, cargo fmt and clippy,
                cargo xtask check-layers, engine checks, docs structure, uv build)
  --test        Lint + cargo test + unit pytest (excludes cli_e2e/cli_smoke) — default
  --full        Lint + cargo test + unit pytest + coverage gate + CLI E2E +
                GitLab CI lint, and ci.yml's Rust jobs: cargo nextest (profile
                ci), doctests, the editor against validate (lsp parity),
                rustdoc, the crates' package and licence scan;
                the WebAssembly build, the grammar drift check and the fuzz
                smoke run when their tools are installed (each says what it
                skipped and why) — pre-push
  --coverage    Alias for --full
  --store-e2e-durations
                Re-measure the E2E suite serially and rewrite
                .test_durations_e2e, which balances the CI shard matrix.
                Run it after adding or removing slow E2E tests; commit the
                result. Takes about as long as a serial E2E run (~9 min).
  -h, --help    Show this help

Environment:
  FUZZ_SMOKE_SECONDS
                  Seconds per fuzz target in --full's fuzz smoke run (default
                  60, as ci.yml's fuzz-smoke); 0 skips it.
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

skip() { echo "==> SKIPPED: $*"; skipped+=("$1"); }
skipped=()

# A test writes under a temporary folder, never in the checkout (#931), as
# ci.yml's engine-test job checks: `git status` before and after the tests.
tree_state() { git status --porcelain --untracked-files=all; }
tree_unchanged() {
  local after
  after="$(tree_state)"
  if [[ "$after" != "$1" ]]; then
    echo "A test wrote into the checkout: write under a temporary folder (tempfile::tempdir) instead." >&2
    diff <(printf '%s\n' "$1") <(printf '%s\n' "$after") >&2 || true
    exit 1
  fi
}

# ci.yml's Rust jobs (engine, engine-test, engine-package, engine-wasm, grammars,
# fuzz-smoke) for --full; rustfmt, clippy and the layers ran above.
rust_jobs() {
  echo "==> Cargo workspace: nextest (profile ci)"
  if ! cargo nextest --version >/dev/null 2>&1; then
    echo "cargo-nextest is not installed: cargo install cargo-nextest --locked" >&2
    exit 1
  fi
  local before
  before="$(tree_state)"
  cargo nextest run --workspace --locked --profile ci
  echo "==> Cargo workspace: doctests"
  cargo test --workspace --locked --doc --quiet
  tree_unchanged "$before"
  echo "==> The editor's diagnostics are validate's (corpus job: lsp parity)"
  cargo xtask lsp parity --corpus faults
  echo "==> rustdoc (RUSTDOCFLAGS=-D warnings)"
  RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace --locked --quiet
  echo "==> Engine crates package and licence scan"
  # vendor copies each crate's shared assets into it (untracked files, which
  # a later `git add -A` would commit): `vendor --clean` removes them on any
  # exit, an interrupted push included.
  trap 'python3 scripts/engine/release.py vendor --clean >/dev/null' EXIT
  python3 scripts/engine/release.py vendor
  # Every crate the release train publishes, from its package, as in ci.yml's
  # engine-package job; the unpublished members' sources are scanned, and
  # opentide-cli, which carries opentide's package data, as a product.
  cargo package --locked --workspace --exclude opentide-native --exclude xtask --exclude opentide-compare --exclude opentide-cassette --exclude opentide-wasm --exclude opentide-node --allow-dirty --quiet
  find "${CARGO_TARGET_DIR:-target}/package" -maxdepth 1 -name '*.crate' ! -name 'opentide-cli-*' -print0 | xargs -0 bash scripts/engine/license-scan.sh
  bash scripts/engine/license-scan.sh --product "${CARGO_TARGET_DIR:-target}"/package/opentide-cli-*.crate
  bash scripts/engine/license-scan.sh crates/opentide-compare crates/opentide-cassette crates/opentide-wasm bindings/node bindings/python
  python3 scripts/engine/release.py vendor --clean
  trap - EXIT

  # The rest need tools a contributor may not have: each says what to install.
  local installed
  installed="$(rustup target list --installed 2>/dev/null || true)"
  if ! grep -qx wasm32-unknown-unknown <<<"$installed" || ! grep -qx wasm32-wasip1 <<<"$installed"; then
    skip "WebAssembly build: rustup target add wasm32-unknown-unknown wasm32-wasip1"
  elif ! command -v wasm-bindgen >/dev/null || ! command -v node >/dev/null; then
    skip "WebAssembly build: install node and wasm-bindgen-cli (the version Cargo.lock pins)"
  else
    echo "==> WebAssembly engine (browser and WASI), clippy on wasm32, npm packs"
    RUSTFLAGS="-Dwarnings" bash scripts/engine/build-wasm.sh
    RUSTFLAGS="-Dwarnings" bash scripts/engine/build-wasm.sh clippy
    for p in lsp-client lsp-worker wasi-host; do (cd "packages/$p" && npm ci --silent); done
    node scripts/engine/check-npm-packs.mjs
    echo "==> wasi-host (opentide/fetch against opentide serve)"
    cargo build --locked -p opentide-cli
    OPENTIDE_BIN=target/debug/opentide-cli node --experimental-strip-types --test packages/wasi-host/src/index.test.ts
  fi

  if [[ -n "${TREE_SITTER_CLI:-}" || -x /tmp/ts-cli/node_modules/.bin/tree-sitter ]] \
    || command -v tree-sitter >/dev/null; then
    echo "==> Grammars regenerate (check-grammars.sh)"
    bash scripts/engine/check-grammars.sh
  else
    skip "grammar drift check: npm install --prefix /tmp/ts-cli tree-sitter-cli@0.25.10"
  fi

  local seconds="${FUZZ_SMOKE_SECONDS:-60}"
  if [[ "$seconds" == "0" ]]; then
    skip "fuzz smoke: FUZZ_SMOKE_SECONDS=0"
  elif ! rustup run "$(cat fuzz/NIGHTLY)" cargo fuzz --version >/dev/null 2>&1; then
    skip "fuzz smoke: rustup toolchain install $(cat fuzz/NIGHTLY) && cargo +$(cat fuzz/NIGHTLY) install cargo-fuzz --locked"
  else
    local target
    for target in fuzz/fuzz_targets/*.rs; do
      target="$(basename "$target" .rs)"
      echo "==> Fuzz smoke: $target (${seconds}s)"
      bash scripts/engine/fuzz.sh "$target" "$seconds"
    done
  fi
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
  uv run pytest tests/ -m "(cli_e2e or cli_smoke) and not full_set" -q --no-cov \
    --store-durations --durations-path .test_durations_e2e
  echo "==> Wrote .test_durations_e2e — commit it to keep the CI shards balanced"
  exit 0
fi

echo "==> Ruff check"
uv run ruff check src/opentide tests scripts

echo "==> Ruff format"
uv run ruff format --check src/opentide tests scripts

if command -v actionlint >/dev/null 2>&1; then
  echo "==> actionlint (the workflows; shellcheck over their scripts when installed)"
  actionlint
else
  echo "==> actionlint not installed: skipped (CI's lint job runs it)"
fi

echo "==> Ty type check"
uv run ty check src/opentide

echo "==> Cargo workspace: rustfmt, clippy, crate layers, deploy cassettes"
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked --quiet -- -D warnings
cargo xtask check-layers
cargo xtask cassettes check

echo "==> Engine invariants (I/O-free crates, names, skills, generated highlights)"
bash scripts/engine/check-io-free.sh
bash scripts/engine/check-names.sh
bash scripts/engine/validate-skills.sh
cargo run --quiet --locked -p opentide-lsp -- generate-highlights --check

echo "==> Docs structure (validate-docs.sh, as ci.yml's docs job runs it)"
bash scripts/validate-docs.sh

echo "==> The engine's bundled Tide catalog and the generated artifacts match the models"
cargo xtask codegen --check

echo "==> uv build (sdist + wheel)"
rm -rf dist
uv build
echo "==> twine check"
uvx twine check dist/*

if [[ "$mode" == "quick" ]]; then
  echo "==> Quick checks passed"
  exit 0
fi

# One engine test compares with Python's difflib (.venv, synced above).
# As in CI: insta compares snapshots and never writes one.
export INSTA_UPDATE=no
if [[ "$mode" == "full" ]]; then
  rust_jobs
else
  echo "==> Cargo workspace: tests"
  before="$(tree_state)"
  cargo test --workspace --locked --quiet
  tree_unchanged "$before"
fi
echo "==> The engine release script's tests"
uv run python -m unittest discover -s scripts/engine -p "test_*.py"

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
  echo "==> E2E pytest (console script, MCP and LSP stdio; the full set's too)"
  uv run pytest tests/ -m "cli_e2e or cli_smoke" -q "${parallel[@]}" --no-cov
  echo "==> Generated GitLab CI lint (glint + gitlab-ci-verify)"
  linters="$ROOT/.cache/gitlab-ci-linters"
  bash scripts/install-gitlab-ci-linters.sh "$linters"
  PATH="$linters:$PATH" OPENTIDE_GITLAB_CI_LINT=1 \
    uv run pytest tests/test_ci/test_gitlab_pipeline_lint.py -m gitlab_ci_lint -q --no-cov
else
  uv run pytest tests/ --no-cov -q "${parallel[@]}" -m "$unit_marker"
fi

if [[ ${#skipped[@]} -gt 0 ]]; then
  echo "==> Skipped (CI runs them): ${skipped[*]}"
fi
echo "==> All checks passed ($mode)"
