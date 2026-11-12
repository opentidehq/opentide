# .github — Agent Guide: CI, CodeQL, releases, Dependabot

What runs on a pull request and a push, and how to reproduce it locally. The root
[`AGENTS.md`](../AGENTS.md) is the map; the [steward](../.agents/skills/steward/SKILL.md) skill
drives a PR to green and [github-actions-templates](../.agents/skills/github-actions-templates/SKILL.md)
covers editing workflows.

## CI (`workflows/ci.yml`): one workflow for the repository

It runs on every pull request, whatever its base (a stacked PR targets the branch below it), on
every push to `development` and to `integration/unified-core` (where the Unified Core PRs merge
first; CodeQL and the oracles run there too), nightly and on Run workflow. Jobs run in parallel;
a new push cancels the stale run.

### What runs where

A pull request runs the **core gates**; everything else is the **full set**
(`tests/test_ci/test_ci_scope.py` holds both):

| Trigger | What runs |
|---------|-----------|
| Every pull request | The core gates (below) and CodeQL: the required checks |
| A pull request with the `full-ci` label | Everything: the core gates and the full set (the label is read at each push, so add it, then push; or Run workflow on the branch) |
| A pull request that changes the engine release's inputs (`engine-release*.yml`, `scripts/engine/release*`; not `Cargo.toml` or `Cargo.lock`, which most pull requests touch) | Also the engine release dry run, its vscode-extension check and the crates' package and licence scan |
| A pull request that changes `grammars/`, `highlights/` or `check-grammars.sh` | Also the grammar regeneration and TextMate checks |
| Push to `development`, `integration/unified-core` (and `main`), nightly, Run workflow | Everything |

A full-set job's `if` is exactly
`github.event_name != 'pull_request' || contains(github.event.pull_request.labels.*.name, 'full-ci')`;
the path-based ones read ci.yml's `changes` job (`CI paths`, a `git diff` of the merge commit,
which fails open: when it does not succeed, they run). A core gate has no `if`, so its check
starts on every pull request and can be required.

**Core gates** (every pull request):

| Job | What it checks |
|-----|----------------|
| `lint` | ruff, ty, `uv build` and `twine check`; the vocabulary drift gate and the model field descriptions (below) when their files change |
| `engine` | rustfmt, clippy `-D warnings`, `cargo xtask check-layers`, `cargo doc --no-deps --workspace` with `RUSTDOCFLAGS=-D warnings`, the engine's invariant scripts (`check-io-free.sh`, `check-names.sh`, `validate-skills.sh`, `generate-highlights --check`), the bundled Tide catalog test and the engine release script's tests |
| `engine-test` | `cargo nextest run --workspace --profile ci` on Linux, macOS and Windows (after `uv sync`: one test runs the Pydantic models); the doctests (`cargo test --doc`) on Linux; fails when the tests leave a file in the checkout that `git status` shows (#931) |
| `deny` | `cargo deny check` against [`deny.toml`](../deny.toml) (licences, RustSec advisories, duplicate versions, OpenSSL, sources) for the workspace and the `publishing/` placeholder crate, and advisories, bans and sources for `fuzz/`; cargo-deny 0.20.2, prebuilt and checksum-checked ([`docs/internal/supply-chain.md`](../docs/internal/supply-chain.md)) |
| `test` | Python **3.10** and **3.14**, the coverage gate on 3.14 (`test-full` adds 3.11–3.13 in the full set) |
| `cli-e2e`, `gitlab-ci-lint` | The sharded E2E suite (4 shards) and the generated GitLab pipelines; neither waits for `test` |
| `golden-compare` | `cargo xtask golden check --engine compare` (UC-0.7): every golden case whose command has a Rust implementation, through this repository's CLI with `OPENTIDE_ENGINE=rust`, against the oracle's recording and `tests/golden/APPROVED_DIFFS.toml`; the `golden-compare` artifact holds the report |
| `corpus` | The corpora of UC-0.6 against opentide 0.23.0 from PyPI, hash-pinned in its own venv: the heavy workspace has no finding, `cargo xtask corpus faults --check` (every fault kind reports exactly its codes), the code inventory and `COVERAGE.md` are current ([`tests/corpora/README.md`](../tests/corpora/README.md)); opentide-schema's object models against the oracle (UC-1.3): `corpus faults --check --engine rust --only objects` and `cargo xtask schema diff --against python` (JSON Schemas, findings on every corpus); `cargo xtask validate diff` (UC-2.2: opentide-workspace's validate against the recordings of `validate --json`, every difference approved, none stale; UC-2.3: its `--fix` and `--fix --dry-run` cases too) and `cargo xtask lint diff` (UC-2.3: its lint against the recordings of `lint --json`) |
| `changes` | `CI paths`: whether the pull request changes the release's inputs or the grammars (above) |

**Full set** (nightly, pushes, Run workflow, the `full-ci` label; some also by path, above):

| Job | What it checks |
|-----|----------------|
| `test-full` | Python **3.11**, **3.12** and **3.13** (`Test (3.x)`), without coverage |
| `cli-windows-smoke` | The console launcher and promotion's line endings on Windows |
| `facade` | The `opentide` facade crate with every feature: its tests and doctests (the binary's `--json commands` against the PyPI CLI's recording and the ledger, `cli::run_json`, the language server), rustdoc as docs.rs builds it, and `cargo semver-checks` (0.51.0) against the first parent; `engine-test` runs its default features on every pull request |
| `node` | The Node package `@opentide/opentide` (`bindings/node`, UC-5.3): the napi-rs addon built for linux-x64-gnu, its generated `index.js` and `index.d.ts` against the committed ones, `npm test` (the SDK, the bin and Ctrl-C, the packages, the TypeScript page's snippets, a `tsc --noEmit` consumer), `npx . --json commands` byte for byte this repository's PyPI CLI's (`duration_ms` zeroed), and `cargo xtask golden check --runner node` (every ported golden case through the Node bin and the comparator, but `--help` and `doctor`, which the PyPI CLI still answers in Python); the `golden-node` artifact holds the report |
| `conformance` | The cross-SDK conformance suite (UC-5.4) on Linux, macOS and Windows: `uv sync`, the Node addon (develop profile, `OPENTIDE_VERSION` the workspace's), then `cargo xtask conformance --runners rust,python,node` (every operation of `tests/conformance/manifest.json` on the tide corpus, the heavy workspace, the fault workspace and each configuration fault, the three SDKs' documents byte for byte; [`tests/conformance/README.md`](../tests/conformance/README.md)) and `--diverge node` on the tide corpus, which passes only when the comparator catches the deliberate divergence; the `conformance-<os>` artifact holds `report.json` |
| `engine-wasm` | `scripts/engine/build-wasm.sh` (both WebAssembly artifacts, and `clippy` for the code only wasm32 compiles), the npm packages (`check-npm-packs.mjs`) and the TypeScript client against the native, worker and WASI servers |
| `engine-package` | Every engine crate packaged as crates.io builds it, and `license-scan.sh` over the packages (no oracle reference ships) |
| `grammars`, `textmate` | Every vendored `parser.c` is what tree-sitter-cli 0.25.10 generates (`check-grammars.sh`); the TextMate grammars as VS Code reads them |
| `elastic-sweep` | Every public Elastic detection rule (a pinned commit) passes the engine |
| `fuzz-smoke` | Each fuzz target of `fuzz/` for 60 s from its seeds and saved regressions (the dated nightly `fuzz/NIGHTLY` pins, up to three targets per runner; cargo-fuzz pinned) |
| `engine-release-dry-run` | The engine release's own asset jobs ([`engine-release-build.yml`](workflows/engine-release-build.yml)) for the workspace version: every asset, the CycloneDX SBOMs (`scripts/engine/sbom.py`, schema-checked), SHA256SUMS, and `release.py check-assets` (language-server v0.11.0's names with the version substituted, plus the SBOMs). No tag, attestation, release or publish; `contents: read` |
| `engine-release-consumers` | opentidehq/vscode-extension's own grammar and engine scripts (a pinned commit) accept the dry run's assets as this repository's release (`scripts/engine/check-vscode-extension.mjs`) |
| `clients`, `bench` | Informational (`continue-on-error`): real LSP clients (pytest-lsp, Neovim) and `cargo bench`; never required |

The other workflows follow the same split: `coverage.yml` (Rust coverage gates), golden.yml's
`Golden determinism`, `parity.yml`, `docs.yml` and `publish-dry-run.yml` run their jobs in the
full set only (their `pull_request` trigger has no path filter, so the label reaches them);
`schema.yml` and `oracle.yml` run on a pull request only when it changes their inputs (a path
filter on the trigger), and on every push; `bench.yml` keeps its `perf` label. Below, "The other
workflows".

Every Rust job installs the release `rust-toolchain.toml` pins (`rustup toolchain install` with no
name, never floating `stable`), then its targets with `rustup target add`: that install drops
`--target` and `--component` silently (`tests/test_ci/test_rust_toolchain.py`). Only the fuzz jobs
name a toolchain, the dated nightly `fuzz/NIGHTLY` pins. Every job that runs cargo sets
`RUSTFLAGS=-Dwarnings` (the nightly fuzz build aside); the test jobs also set
`CARGO_PROFILE_DEV_DEBUG=line-tables-only` and `INSTA_UPDATE=no` (CI never writes a snapshot).

**Rust caches, one strategy** (`tests/test_ci/test_rust_caches.py`): every rust-cache step in
ci.yml names its cache (`shared-key`, plus `key` per OS or target), and each name has one job that
saves it; readers use `save-if: false` and repeat its runner and `CARGO*`/`RUST*` environment,
which rust-cache hashes into the key. The names are split by what is built, because a check
build, a debug test tree, a release binary and the binding `uv sync` builds share no artifacts and
one key would hold only one of them: `engine-dev` (`engine-test` per OS; `clients` and
`elastic-sweep` read Linux's), `python-engine` (the abi3 binding, saved by `test`'s 3.14 cell, read
by the other Python jobs), `engine-check`, `engine-wasm`, `engine-package`, `engine-bench`, `fuzz`,
`python-engine-windows`, and `engine-release` per target for the dry run. A release restores none.

**Coverage:** gate on Python **3.14** only (`COVERAGE_PYTHON`); the Code Quality upload is
best-effort, the HTML report an artifact. **Vocabulary drift gate:** when vocab TOML, schema pins,
`data/specifications.lock.json` or the sync script change, CI checks out `opentidehq/specifications`
(`main`) and runs `cargo xtask vocab sync --check` against it.

**Bundled Tide catalog:** the engine compiles in a Tide catalog (`data/catalogs/tide/`, and the
key lists of `highlights/queries/tide/highlights.scm`) for editors that run `opentide-lsp` on its
own. `scripts/engine/sync_opentide_schemas.py` generates it from `src/opentide`, and
`tests/test_generation/test_bundled_tide_catalog.py` (the `engine` job, `ci-local.sh`) fails
when the committed one differs, until UC-1.8 generates it in Rust.

**Budget:** a pull request's CI (the core gates), first job start to last job end, stays under 15
minutes on a warm cache (the second push of a branch). The long poles are the corpus job, the
Python 3.10 cell, golden compare and nextest on Windows; split what grows past it, or move it to
the full set.

## Required checks

Branch protection on `development` requires every check below: each gating job of ci.yml that
runs on every pull request (every matrix cell), and CodeQL's two (`codeql.yml` runs on every
pull request). `tests/test_ci/test_one_ci.py` fails when this list and the workflows differ. The
full set's jobs, the informational jobs and the path-filtered workflows (`oracle.yml`,
`schema.yml`) are not required: a required check that does not run blocks the merge, and a
matrix job skipped by its `if` reports one check under its unexpanded name.

<!-- required-checks -->
```text
CI paths
Lint
Engine lint (fmt, clippy, doc, layers)
Engine tests (ubuntu-latest)
Engine tests (macos-latest)
Engine tests (windows-latest)
Supply chain (cargo deny)
Corpus (generator, faults, coverage) against opentide 0.23.0
Test (3.10)
Test (3.14)
E2E (3.14, shard 1/4)
E2E (3.14, shard 2/4)
E2E (3.14, shard 3/4)
E2E (3.14, shard 4/4)
GitLab CI lint
Golden compare
Analyze (python)
Analyze (actions)
```

Branch protection on `integration/unified-core` requires every check above and the two of
[`golden.yml`](workflows/golden.yml) below, which run on every pull request into it (#803).
`tests/test_ci/test_golden_workflow.py` fails when this list and golden.yml's jobs differ, or
when golden.yml's `pull_request` trigger gets a path or branch filter back: a required check
that never starts blocks the merge.

<!-- required-checks-integration -->
```text
Golden paths
Golden check (python)
```

`Golden determinism` (recording every case twice, about 26 minutes) is in the full set:
nightly, on every push and Run workflow, and on a pull request only with the `full-ci` label; it
is no longer required. `Golden check (python)` (about 8 minutes) runs on every pull request into
`integration/unified-core`, and on other bases when a golden input changed; `Golden compare`
(ci.yml) on every pull request.
`Golden paths` is the filter, and is required so that it cannot fail unnoticed (its dependants
also run when it fails).

To set it (a repository admin): **Settings → Rules → Rulesets → New ruleset → New branch
ruleset**; name it `development`, Enforcement status **Active**; **Target branches → Add target →
Include by pattern** `development`; tick **Require status checks to pass** (and **Require
branches to be up to date before merging** if wanted), then **Add checks** and add each name
above (each appears once it has run on a pull request; choose the GitHub Actions source);
**Create**. For `integration/unified-core`, the same with the pattern `integration/unified-core`
and both lists. With classic branch protection instead: **Settings → Branches → Add classic branch
protection rule** (or edit the `development` rule) → Branch name pattern `development` → tick
**Require status checks to pass before merging** → search for and add each name → **Save
changes**. When a job is renamed or a matrix changes, update the list here and in the rule
together. A check removed from the lists (the full set's jobs, `Golden determinism`) must be
removed from the rule too, or every pull request that does not run it waits for it.

## The other workflows

- [`engine-release.yml`](workflows/engine-release.yml): the engine's release (below).
- [`engine-fuzz.yml`](workflows/engine-fuzz.yml) fuzzes every target for ten minutes a night with
  the corpus it keeps, and uploads what crashed; a schedule of its own, so not part of ci.yml.
- [`bench.yml`](workflows/bench.yml), nightly on `development`, on demand and on a pull request
  labelled `perf`: `cargo xtask bench` for the `python` (the oracle, opentide 0.23.0 from PyPI)
  and `rust` engines on `ubuntu-24.04`, then `cargo xtask bench --check --require-reference`
  against `tests/bench/budgets.toml` and the last successful `development` run's
  `bench-<engine>` artifact on the same CPU (a command compared with nothing fails). The rules
  (10% over the last development result or the oracle baseline of the runner's CPU, the absolute
  plan section 11 target for `rust`, the noise floor, the ceiling on an unrecorded CPU, the
  waiver) are in [`xtask/AGENTS.md`](../xtask/AGENTS.md), "bench"; the table lands in the job
  summary. Never required: it runs on demand and its numbers depend on the runner's CPU.
- [`rust-audit.yml`](workflows/rust-audit.yml) runs `cargo audit` on every Rust lock file
  (`git ls-files`) every day, with deny.toml's exceptions, and opens or comments on one issue when it finds an advisory.
  Its issue job is the only job in any workflow with `issues: write`, and it never runs on a pull
  request (`tests/test_ci/test_supply_chain.py`).
- [`schema.yml`](workflows/schema.yml), on every push to `main`, `development` and
  `integration/unified-core`, nightly, on demand, and on a pull request that changes
  `crates/opentide-schema*`, `crates/opentide-core`, `src/opentide/_native/`,
  `xtask/src/stubs.rs`, the Cargo manifests, lock or toolchain, `.cargo/` or schema.yml:
  `opentide-schema` (UC-1.1)
  built for the native target, abi3-py310 (feature `python`) and `wasm32-unknown-unknown`
  (feature `wasm`), clippy on the last two (ci.yml's engine jobs build no features), and its tests
  with the Python class on CPython 3.10, the abi3 floor; clippy with feature `stubs`, and
  `cargo xtask stubs --check`, which fails when the generated `src/opentide/_native/models.pyi`
  differs from the extension (UC-1.9). Written before ci.yml became one workflow; not a required
  check.
- [`oracle.yml`](workflows/oracle.yml) checks the query parsers against Kusto.Language, Splunk,
  Elasticsearch, Lucene, Kibana and Falco (`OPENTIDE_ORACLE_REQUIRED`) on every push to
  `development` and `integration/unified-core`, on an `engine-v*` tag, on a pull request that
  changes the query languages' crates (and `opentide-analysis`, `-core`, `-syntax`,
  `-highlight`, `-ecs`, `-lsp`), any crate's `Cargo.toml`, `packages/*/package.json`,
  `grammars/`, `Cargo.lock`, the query catalogs or the oracles, weekly (with the Carbon Black
  Cloud tenant) and on demand. Its own triggers and network-heavy references keep it out of
  ci.yml.
- [`golden.yml`](workflows/golden.yml) runs `cargo xtask golden check --engine python` and
  `golden record --check-determinism` against the committed recordings of the frozen Python CLI
  (`tests/golden/README.md`) on every push to `development` and `integration/unified-core`,
  nightly and on demand. On a pull request its `Golden paths` job reads whether the pull request
  touches `tests/golden/`, `tests/corpora/`, the tide corpus, `xtask/`, `.cargo/`, `Cargo.*`,
  `rust-toolchain.toml`, `.gitattributes` or golden.yml: the check runs when it does, and on
  every pull request into `integration/unified-core`. The determinism run is in the full set
  (the `full-ci` label on a pull request). The trigger itself has no path filter, so
  `integration/unified-core` requires `Golden paths` and the check (Required checks, above).
- [`docs.yml`](workflows/docs.yml) (`scripts/validate-docs.sh`) and
  [`publish-dry-run.yml`](workflows/publish-dry-run.yml) (every publish rehearsed, nothing
  published) are in the full set: nightly, on demand, on a push to `development` or
  `integration/unified-core` (the publish dry run when what is published changes), and on a pull
  request with the `full-ci` label. A pull request that changes `docs/` structure, `publishing/`
  or the packaging should carry the label.
- [`codeql.yml`](workflows/codeql.yml) (every pull request: required),
  [`publish-pypi.yml`](workflows/publish-pypi.yml), [`stack-comment.yml`](workflows/stack-comment.yml),
  [`vocab-upstream.yml`](workflows/vocab-upstream.yml): below and in their own headers.

Where each of language-server's workflow jobs went (or why it was dropped):
[`docs/engine/IMPORT.md`](../docs/engine/IMPORT.md#where-the-workflows-went).

## Test strength (UC-X.2, #844)

[`docs/internal/test-strength.md`](../docs/internal/test-strength.md) explains the three measures;
`tests/test_ci/test_test_strength_workflows.py` holds their permissions and triggers.

- [`coverage.yml`](workflows/coverage.yml), in the full set (nightly, every push to `development`
  and `integration/unified-core`, on demand, the `full-ci` label): job **Rust coverage gates**. One cargo-llvm-cov build measured by the workspace's Rust tests and by the whole Python
  suite, which drives `opentide._native`; `cargo xtask coverage gate` checks each crate against
  `xtask/coverage.toml`. Read-only.
- [`mutants.yml`](workflows/mutants.yml), weekly and on demand: cargo-mutants on the crates of
  `xtask/mutants.toml` in eight shards, a report against `xtask/mutants-baseline.toml`, and on the
  schedule only a job with `issues: write` (no checkout, no repository code) that opens or updates
  one issue per crate above its threshold.
- [`parity.yml`](workflows/parity.yml), on every push, the daily schedule, a manual run and a pull
  request with the `full-ci` label: `cargo xtask parity dashboard` into the job summary and an artifact, read-only. Committing
  `docs/internal/parity.md` is off unless the repository variable `PARITY_COMMIT` is `true`; then
  only on the schedule or a manual run of `development` or `integration/unified-core`, a job with
  `contents: write` (no repository code, one path, never forces) commits it when it changed.

## Releases

**opentide (PyPI):** merge the notes PR, then Run workflow on
[`publish-pypi.yml`](workflows/publish-pypi.yml) on `development` with no inputs: it tags the
changelog's version (`v*`), creates the GitHub Release and publishes, so a cloud session can
release. Steps: [release-management](../.agents/skills/release-management/SKILL.md).
`tests/test_ci/test_one_ci.py` fails if any other workflow can run on a `v*` tag, or if anything
publishes from a trigger that is not a release.

**The engine (crates.io, npm, the GitHub Release editors pin):**
[`engine-release.yml`](workflows/engine-release.yml), on an `engine-vX.Y.Z` tag or Run workflow on
`development` (the workspace version). An `engine-vX.Y.Z-rc.N` tag is a release candidate: a GitHub
pre-release with every asset, SHA256SUMS and provenance, and nothing on crates.io or npm. An
engine release is never marked the repository's latest. The assets keep language-server's names
(`highlights-v0.11.0.zip`, `opentide-lsp-v0.11.0-<target>`); each asset's attestation is signed
by `opentidehq/opentide/.github/workflows/engine-release.yml`. Steps:
[engine-release](../.agents/skills/engine-release/SKILL.md).

## Local parity

```bash
scripts/ci-local.sh --quick    # ruff, ty, cargo fmt + clippy, crate layers, engine checks, uv build
scripts/ci-local.sh            # lint + cargo test + pytest
scripts/ci-local.sh --full     # + nextest ci, doctests, rustdoc, crate packages and licence scan,
                               #   coverage gate, E2E, GitLab CI lint, and WebAssembly, grammars and
                               #   fuzz smoke when their tools are installed: before push
```

`--full` says which optional step it skipped and what to install for it. `FUZZ_SMOKE_SECONDS`
(default 60, as CI) sets the fuzz smoke's time per target; `0` skips it.

## CodeQL, Dependabot, stack comments

**CodeQL:** Python and Actions via [`workflows/codeql.yml`](workflows/codeql.yml)
(`/language:python` + `/language:actions`); Code Quality may also run dynamic Python on push.
Local Python: `scripts/codeql-local.sh`. Skill: [codeql](../.agents/skills/codeql/SKILL.md).

**Dependabot:** weekly PRs for `uv` (test toolchain grouped), `github-actions` (SHA pins) and
`pre-commit`. Merge procedure: [uv skill](../.agents/skills/uv/SKILL.md#dependency-upgrades-and-dependabot).

**Stack comments:** [`workflows/stack-comment.yml`](workflows/stack-comment.yml) posts merge
order **only** on stacked PRs (non-trunk base or child PR exists). Standalone PRs to
`development` are skipped.

## Rules for workflow changes

- Actions are pinned by commit SHA with the version in a comment; Dependabot bumps them.
- Every job states least privilege; checkouts set `persist-credentials: false`.
- Never interpolate `${{ github.event.* }}`, `${{ inputs.* }}` or `github.head_ref` into `run:`;
  pass it through `env:`.
- Nothing publishes from a pull request: the release workflows run on tags and Run workflow only.
- A step that must fail when its tool is missing must not sit in an `if` that reads "missing"
  as "no match" (the drift gate once used `rg`, which runners lack).
- The workflow contracts have tests under `tests/test_ci/` (`test_one_ci.py`,
  `test_own_ci_workflow.py`, `test_rust_caches.py`, `test_rust_toolchain.py`,
  `test_workflow_contexts.py`, ...): run them after a change.
