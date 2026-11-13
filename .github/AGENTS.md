# .github — Agent Guide: CI, CodeQL, releases, Dependabot

What runs on a pull request and a push, and how to reproduce it locally. The root
[`AGENTS.md`](../AGENTS.md) is the map; the [steward](../.agents/skills/steward/SKILL.md) skill
drives a PR to green and [github-actions-templates](../.agents/skills/github-actions-templates/SKILL.md)
covers editing workflows.

## CI (`workflows/ci.yml`): one workflow for the repository

It runs on every pull request, whatever its base (a stacked PR targets the branch below it), on
every push to `development` and to `integration/unified-core` (where the Unified Core PRs merge
first; CodeQL and the oracles run there too), nightly and on Run workflow. Jobs run in parallel.

**Concurrency** (`tests/test_ci/test_concurrency.py`): a pull request's new push cancels its stale
run; every other run (a push to `development`, `integration/unified-core` or `main`, the nightly,
Run workflow) is in a group of its own, `${{ github.run_id }}`, so no run cancels it and every merge
to a base branch gets a complete run. Every workflow with a push trigger and a concurrency group
(`ci.yml`, `codeql.yml`, `coverage.yml`, `docs.yml`, `golden.yml`, `publish-dry-run.yml`,
`schema.yml`) uses the same two lines:

```yaml
group: <name>-${{ github.event_name }}-${{ github.event_name == 'pull_request' && github.ref || github.run_id }}
cancel-in-progress: ${{ github.event_name == 'pull_request' }}
```

A group shared by two pushes would not do, even without `cancel-in-progress`: GitHub keeps one
pending run per group and cancels the older one when a newer one queues.

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
| `lint` | ruff, ty (the dependencies installed without the project), `uv build` (the wheel from the sdist, the `develop` profile, into the cached target directory) and `twine check`; the vocabulary drift gate and the model field descriptions (below) when their files change |
| `engine` | rustfmt, clippy `-D warnings`, `cargo xtask check-layers`, `cargo xtask cassettes check` (#831: one deploy cassette per scenario of `tests/cassettes/scenarios.toml`, recorded and redacted, none edited by hand), `cargo doc --no-deps --workspace` with `RUSTDOCFLAGS=-D warnings`, the engine's invariant scripts (`check-io-free.sh`, `check-names.sh`, `validate-skills.sh`, `generate-highlights --check`), the bundled Tide catalog test and the engine release script's tests |
| `engine-test` | (`engine-test-part`: Linux in two shards, `nextest --partition hash:N/2`, macOS and Windows whole; `engine-test` gathers them under each OS's required check, as `corpus` does, #841) `cargo nextest run --workspace --profile ci` on Linux, macOS and Windows (one test compares with Python's difflib: setup-python's interpreter, `OPENTIDE_PYTHON`; nothing is synced); the doctests (`cargo test --doc`) on Linux; fails when the tests leave a file in the checkout that `git status` shows (#931) |
| `deny` | `cargo deny check` against [`deny.toml`](../deny.toml) (licences, RustSec advisories, duplicate versions, OpenSSL, sources) for the workspace and the `publishing/` placeholder crate, and advisories, bans and sources for `fuzz/`; cargo-deny 0.20.2, prebuilt and checksum-checked ([`docs/internal/supply-chain.md`](../docs/internal/supply-chain.md)) |
| `test` | Python **3.10** and **3.14**, the coverage gate on 3.14 (`test-full` adds 3.11–3.13 in the full set) |
| `cli-e2e`, `gitlab-ci-lint` | The sharded E2E suite (4 shards) and the generated GitLab pipelines; neither waits for `test` |
| `golden-compare` | `cargo xtask golden check --engine rust` (UC-0.7; every case since UC-6.2, #841): every golden case through this repository's CLI, the Rust core, against the oracle's recording and `tests/golden/APPROVED_DIFFS.toml`; then `cargo xtask mcp replay --engine rust` (the recorded Python MCP sessions against the Rust server) and the MCP stdio tests. The check keeps its name, `Golden compare`, a required check's; the `golden-compare` artifact holds the report |
| `corpus` | (`corpus-part` in five parts on five runners: `Corpus (generator)`, `(faults)`, `(diffs)`, `(editor)`, `(vocabulary)`; `corpus` gathers them under the required check's name, with `if: ${{ !cancelled() }}` so that a failed part fails it, #841) The corpora of UC-0.6 against opentide 0.23.0 from PyPI, hash-pinned in its own venv: the heavy workspace has no finding, `cargo xtask corpus faults --check` (every fault kind reports exactly its codes), the code inventory and `COVERAGE.md` are current ([`tests/corpora/README.md`](../tests/corpora/README.md)); opentide-schema's object models against the oracle (UC-1.3): `corpus faults --check --engine rust --only objects` and `cargo xtask schema diff --against python` (JSON Schemas, findings on every corpus); the platform-block and configuration fault kinds through the Rust engine, finding for finding (`corpus faults --check --engine rust --only platforms` and `--only configuration`, UC-1.4 #810 and UC-1.5 #811, the `faults` part, about a minute); every workspace's resolved configuration and its configuration findings against the oracle's (`cargo xtask config diff --against python`, UC-1.5 #811, the `diffs` part, seconds); `cargo xtask validate diff` (UC-2.2: opentide-workspace's validate against the recordings of `validate --json`, every difference approved, none stale; UC-2.3: its `--fix` and `--fix --dry-run` cases too) and `cargo xtask lint diff` (UC-2.3: its lint against the recordings of `lint --json`) |
| `changes` | `CI paths`: whether the pull request changes the release's inputs or the grammars (above) |

**Full set** (nightly, pushes, Run workflow, the `full-ci` label; some also by path, above):

| Job | What it checks |
|-----|----------------|
| `test-full` | Python **3.11**, **3.12** and **3.13** (`Test (3.x)`), without coverage |
| `cli-windows-smoke` | The console launcher and Ctrl-C through it on Windows |
| `cli-e2e-full` | The E2E tests marked `full_set`, too slow for every pull request: a platform plugin on opentide installed from its wheel (`test_wheel_plugin_platform.py`); `cli-e2e` leaves them out |
| `facade` | The `opentide` facade crate with every feature: its tests and doctests (the binary's `--json commands` against the PyPI CLI's recording and the ledger, `cli::run_json`, the language server), rustdoc as docs.rs builds it, and `cargo semver-checks` (0.51.0) against the first parent; `engine-test` runs its default features on every pull request |
| `node` | The Node package `@opentide/opentide` (`bindings/node`, UC-5.3): the napi-rs addon built for linux-x64-gnu, its generated `index.js` and `index.d.ts` against the committed ones, `npm test` (the SDK, the bin and Ctrl-C, the packages, the TypeScript page's snippets, a `tsc --noEmit` consumer), `npx . --json commands` byte for byte this repository's PyPI CLI's (`duration_ms` zeroed), and `cargo xtask golden check --runner node` (every ported golden case through the Node bin and the comparator, but `--help` and `doctor`, which the PyPI CLI still answers in Python); the `golden-node` artifact holds the report |
| `npm-install` | The npm packages installed as a user installs them, as `publish.yml`'s `smoke-npm` does before a release: the tree's packages at the workspace version (`release.py npm-version`), the addon built for linux-x64-gnu (the other five native packages packed as stand-ins without an addon), published to a throwaway local registry (Verdaccio 6.11.1, no uplink), then `npm install @opentide/opentide` in a clean project: exactly the host's native package, `npx opentide --version`, the SDK from `require` and `import`, `runJson(['commands'])`, `tsc` against `index.d.ts`, and the same through the `opentide` alias (`scripts/engine/npm-local-registry/test.mjs`); it reads the `node` job's Rust cache |
| `packages` | Installable builds to test without publishing: [`build-packages.yml`](workflows/build-packages.yml), the wheels and npm tarballs a release builds, at a development version of the workspace's (PyPI `X.Y.Z.devN`, npm `X.Y.Z-dev.N`), kept 14 days as `wheels-<platform>` (`linux-x64`, `linux-arm64`, `macos-x64`, `macos-arm64`, `windows-x64`, `windows-arm64`) and `npm-<platform>` (`@opentide/opentide` and one native package); how to install them: [`docs/internal/publishing.md`](../docs/internal/publishing.md#testing-a-build-without-publishing) |
| `conformance` | The cross-SDK conformance suite (UC-5.4) on Linux, macOS and Windows: `uv sync`, the Node addon (develop profile, `OPENTIDE_VERSION` the workspace's), then `cargo xtask conformance --runners rust,python,node` (every operation of `tests/conformance/manifest.json` on the tide corpus, the heavy workspace, the fault workspace and each configuration fault, the three SDKs' documents byte for byte; [`tests/conformance/README.md`](../tests/conformance/README.md)) and `--diverge node` on the tide corpus, which passes only when the comparator catches the deliberate divergence; the `conformance-<os>` artifact holds `report.json` |
| `corpus-queries` | `Corpus (query fault kinds)`: `cargo xtask corpus faults --check --engine rust --only queries` (UC-2.5 #820, UC-3.5b), the kinds `validate` and `lint` report query findings for, through the Rust engine with the query engines, every finding against the oracle's (opentide 0.23.0 from PyPI, as `corpus`); about eight minutes, so not a corpus part. It reads the corpus parts' Rust and compiler caches and saves none |
| `engine-wasm` | `scripts/engine/build-wasm.sh` (both WebAssembly artifacts, and `clippy` for the code only wasm32 compiles), the npm packages (`check-npm-packs.mjs`) and the TypeScript client against the native, worker and WASI servers |
| `engine-package` | Every crate the release train publishes, the facade and its crates included, packaged and built as crates.io builds it, and `license-scan.sh` over the packages (no oracle reference ships; the opentide-cli crate, which carries opentide's package data, with `--product`) |
| `grammars`, `textmate` | Every vendored `parser.c` is what tree-sitter-cli 0.25.10 generates (`check-grammars.sh`); the TextMate grammars as VS Code reads them |
| `elastic-sweep` | Every public Elastic detection rule (a pinned commit) passes the engine |
| `fuzz-smoke` | Each fuzz target of `fuzz/` for 60 s from its seeds and saved regressions (the dated nightly `fuzz/NIGHTLY` pins, up to three targets per runner; cargo-fuzz pinned) |
| `engine-release-dry-run` | The release train's asset jobs ([`engine-release-build.yml`](workflows/engine-release-build.yml)) for the workspace version: every asset (the `opentide` and `opentide-lsp` binaries for six targets, no musl; the installers), the CycloneDX SBOMs (`scripts/engine/sbom.py`, schema-checked), SHA256SUMS, and `release.py check-assets` (language-server v0.11.0's names with the version substituted, plus the train's). No tag, attestation, release or publish; `contents: read` |
| `engine-release-consumers` | opentidehq/vscode-extension's own grammar and engine scripts (a pinned commit) accept the dry run's assets as this repository's release (`scripts/engine/check-vscode-extension.mjs`) |
| `clients`, `bench` | Informational (`continue-on-error`): real LSP clients (pytest-lsp, Neovim) and `cargo bench`; never required |

The other workflows follow the same split: `coverage.yml` (Rust coverage gates), golden.yml's
`Golden determinism`, `docs.yml` and `publish-dry-run.yml` run their jobs in the
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
one key would hold only one of them: `engine-dev` (`engine-test-part` per OS, its first shard; `clients` and
`elastic-sweep` read Linux's), `python-engine` (the abi3 binding, saved by `test`'s 3.14 cell, read
by the other Python jobs), `engine-check`, `engine-wasm`, `engine-package`, `engine-bench`, `fuzz`,
`python-engine-windows`, and `engine-release` per target for the dry run. A release restores none.

**Compiler caches (sccache, #841):** rust-cache drops the workspace's own crates before saving, so
every job recompiled them from a fresh checkout (two to three minutes a job). The jobs that compile
the most on every pull request also wrap rustc in sccache (`RUSTC_WRAPPER`, 0.19.0 from
taiki-e/install-action), whose directory (`SCCACHE_DIR`, `.sccache/` in the checkout, gitignored: actions/cache refuses a path with `..`) actions/cache keeps
under `sccache-<name>-<hash of the Rust sources>`: by content, so only what a change touches
compiles again. Each name has one job that saves it (`actions/cache/save`, only when the key
missed), as rust-cache's: `python-engine` (`test`'s 3.14 cell; the other Python jobs restore it), `engine-check` (`engine`),
`engine-dev-<os>` (`engine-test-part`), `golden-compare` and `corpus`. Every Python job names the same
interpreter for PyO3 (`PYO3_PYTHON: /usr/bin/python3`): the binding is abi3, and a different
interpreter reruns PyO3's build script and rebuilds every crate above it.
**Caches are saved from pushes only** (`save-if: ${{ github.event_name == 'push' ... }}` on
every rust-cache, `github.event_name == 'push' && ...` on every sccache save, in every workflow a
pull request runs): a pull request restores the caches of its base branch (and of `development`)
and saves none. A pull request's own cache served that pull request alone, and its gigabytes
evicted the base branches' caches within the half hour (#841). uv's cache (setup-uv) is keyed on
`uv.lock` and written only when that file changes; the pinned setup-uv v5 has no restore-only mode.
`tests/test_ci/test_rust_caches.py` holds all three.

**Coverage:** gate on Python **3.14** only (`COVERAGE_PYTHON`); the Code Quality upload is
best-effort, the HTML report an artifact. **Vocabulary drift gate:** when vocab TOML, schema pins,
`data/specifications.lock.json` or the sync script change, CI checks out `opentidehq/specifications`
(`main`) and runs `cargo xtask vocab sync --check` against it.

**Bundled Tide catalog:** the engine compiles in a Tide catalog (`data/catalogs/tide/`, and the
key lists of `highlights/queries/tide/highlights.scm`) for editors that run `opentide-lsp` on its
own. `cargo xtask codegen` generates it from the Rust models, and `cargo xtask codegen --check`
(the `engine` job, `ci-local.sh`) fails when the committed one differs.

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
[`golden.yml`](workflows/golden.yml) below, which start on every pull request into it (#803);
the check's job is skipped, which reports success, unless a golden input changed or the pull
request has the `full-ci` label.
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
is no longer required. `Golden check (python)` (about 20 minutes) runs on a pull request only
when a golden input changed or with the `full-ci` label: since UC-6.2 (#841) its oracle is a frozen
PyPI release, so a pull request that touches none of its inputs cannot change its result.
`Golden compare` (ci.yml) runs on every pull request.
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

- [`publish.yml`](workflows/publish.yml): the release train (below).
- [`build-packages.yml`](workflows/build-packages.yml): the wheels and npm packages, a reusable
  workflow that `publish.yml` and ci.yml's `packages` job call.
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
  `crates/opentide-schema*`, `crates/opentide-core`, `src/opentide/_native/`, `bindings/python/`,
  `xtask/src/stubs.rs`, the Cargo manifests, lock or toolchain, `.cargo/` or schema.yml:
  `opentide-schema` (UC-1.1)
  built for the native target, abi3-py310 (feature `python`) and `wasm32-unknown-unknown`
  (feature `wasm`), clippy on the last two (ci.yml's engine jobs build no features), and its tests
  with the Python class on CPython 3.10, the abi3 floor; clippy with feature `stubs`, and
  `cargo xtask stubs --check`, which fails when the generated `src/opentide/_native/models.pyi`
  or `src/opentide/_native/sdk.pyi` differs from the extension (UC-1.9, UC-5.2b). Written before ci.yml became one workflow; not a required
  check.
- [`oracle.yml`](workflows/oracle.yml) checks the query parsers against Kusto.Language, Splunk,
  Elasticsearch, Lucene, Kibana and Falco (`OPENTIDE_ORACLE_REQUIRED`) on every push to
  `development` and `integration/unified-core`, on an `engine-v*` tag (a series that ended with the release train), on a pull request that
  changes the query languages' crates (and `opentide-analysis`, `-core`, `-syntax`,
  `-highlight`, `-ecs`, `-lsp`), any crate's `Cargo.toml`, `packages/*/package.json`,
  `grammars/`, `Cargo.lock`, the query catalogs or the oracles, weekly (with the Carbon Black
  Cloud tenant) and on demand. Its own triggers and network-heavy references keep it out of
  ci.yml.
- [`golden.yml`](workflows/golden.yml) runs `cargo xtask golden check --engine python` and
  `golden record --check-determinism` against the committed recordings of the frozen Python CLI
  (`tests/golden/README.md`) on every push to `development` and `integration/unified-core`,
  nightly and on demand. On a pull request its `Golden paths` job reads whether the pull request
  touches `tests/golden/`, `tests/corpora/`, the tide corpus, the render tests' inputs,
  `scripts/golden/`, xtask's golden, corpus, compare and parallel code, `crates/opentide-compare/`
  or golden.yml: the check runs when it does, or with the `full-ci` label. The determinism run is in the full set
  (the `full-ci` label on a pull request). The trigger itself has no path filter, so
  `integration/unified-core` requires `Golden paths` and the check (Required checks, above).
- [`docs.yml`](workflows/docs.yml) (`scripts/validate-docs.sh`) and
  [`publish-dry-run.yml`](workflows/publish-dry-run.yml) (every publish rehearsed, nothing
  published) are in the full set: nightly, on demand, on a push to `development` or
  `integration/unified-core` (the publish dry run when what is published changes), and on a pull
  request with the `full-ci` label. A pull request that changes `docs/` structure, `publishing/`
  or the packaging should carry the label.
- [`codeql.yml`](workflows/codeql.yml) (every pull request: required),
  [`stack-comment.yml`](workflows/stack-comment.yml),
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
- The parity dashboard (`parity.yml`) was retired with the Python implementation (UC-6.2, #841): every command runs on Rust, and `Golden compare` holds each against the oracle.

## Releases

**One release train** ([`publish.yml`](workflows/publish.yml), UC-5.5): merge the notes PR, then
Run workflow on `development` with no inputs. It checks (every crate built from its package, the
licence scan), builds (the wheels and npm packages of
[`build-packages.yml`](workflows/build-packages.yml), the sdist, the binaries and engine assets of
[`engine-release-build.yml`](workflows/engine-release-build.yml)), smoke-tests each artifact as a
user installs it, attests every artifact, tags `vX.Y.Z` with the GitHub Release, verifies the
published assets, and publishes to PyPI, crates.io and npm with trusted publishing, so a cloud
session can release. `release_candidate: N`, for the Rust-core transition (it may be retired
after), runs from `integration/unified-core` or `development` and publishes `vX.Y.Z-rc.N` as
pre-releases: a GitHub pre-release, PyPI `X.Y.ZrcN` and the crates at `X.Y.Z-rc.N` on crates.io,
nothing on npm. The Rust core is 1.0.0, held at candidates (`v1.0.0-rc.1`: PyPI `1.0.0rc1`,
crates.io `1.0.0-rc.1`) until the maintainer accepts the final 1.0.0. `dry_run` publishes nothing;
`checkout_ref: vX.Y.Z` resumes a release. Steps:
[release-management](../.agents/skills/release-management/SKILL.md); the registries' settings and
the decisions (no musl, the free-threaded sdist): [`docs/internal/publishing.md`](../docs/internal/publishing.md#the-release-train).
`tests/test_ci/test_one_ci.py` fails if any workflow can run on a `v*` tag, or if anything
publishes from a trigger that is not a release; `scripts/engine/test_release.py` holds the
workflow's shape (which jobs may mint an OIDC token, what runs before what).

`publish-pypi.yml` (PyPI) and `engine-release.yml` (the engine's `engine-v*` releases) retired into
it: no more `engine-v*` tags. The assets keep language-server's names with the product's version
(`highlights-v1.0.0.zip`, `opentide-lsp-v1.0.0-<target>`); each asset's attestation is signed by
`opentidehq/opentide/.github/workflows/publish.yml` on `development` (a candidate's, on the branch it
ran from: `development` or `integration/unified-core`).

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
- Nothing publishes from a pull request or a tag: the release train (`publish.yml`) runs from Run
  workflow (and its resume dispatch) only.
- A step that must fail when its tool is missing must not sit in an `if` that reads "missing"
  as "no match" (the drift gate once used `rg`, which runners lack).
- The workflow contracts have tests under `tests/test_ci/` (`test_one_ci.py`,
  `test_own_ci_workflow.py`, `test_rust_caches.py`, `test_rust_toolchain.py`,
  `test_workflow_contexts.py`, ...): run them after a change.
