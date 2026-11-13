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

A pull request runs a **lean set** on Linux: the core gates, plus the path-scoped jobs whose
inputs it changes. Everything else is the **full set**, which runs on every push to a base branch,
where platform regressions are caught (`tests/test_ci/test_ci_scope.py` holds the scopes). A push's
run is named after its commit's first line, `CI on <branch>: Merge pull request #N ...`, so a
failure in the full set names the pull request that brought it.

| Trigger | What runs |
|---------|-----------|
| Every pull request | The core gates (below) and CodeQL: the required checks. Required checks whose job runs only in the full set still report: `Engine tests (macos-latest)` and `(windows-latest)` gather the Linux shards on a pull request; `Test (3.10)`'s cell starts and skips its steps; `Corpus (...)` passes when its parts were not needed; CodeQL's analysis of a language is skipped when none of its files changed |
| A pull request that changes the corpora's inputs (`xtask/`, `crates/opentide-core`, `-schema`, `-schema-derive`, `-workspace`, `-compile`, `-lsp`, `tests/corpora/`, `tests/golden/cases*`, `tests/golden/vocab/`, `src/opentide/data/`, `Cargo.lock`, `rust-toolchain.toml`, `ci.yml`) | Also the five corpus parts (a change to a query engine alone is held by the Rust tests and golden compare, and by the corpora on merge) |
| A pull request that changes `bindings/node/`, `crates/opentide/`, `scripts/engine/npm-local-registry/` (or `Cargo.lock`, `ci.yml`) | Also the Node package and its install from a local registry; `crates/opentide/` also the facade crate's every-feature tests and semver checks |
| A pull request that changes Python files (`*.py`, `pyproject.toml`, `uv.lock`) or the workflows | CodeQL's analysis of that language |
| A pull request with the `full-ci` label | Everything: the core gates and the full set (the label is read at each push, so add it, then push; or Run workflow on the branch) |
| A pull request that changes the engine release's inputs (`engine-release*.yml`, `scripts/engine/release*`; not `Cargo.toml` or `Cargo.lock`, which most pull requests touch) | Also the engine release dry run, its vscode-extension check and the crates' package and licence scan |
| A pull request that changes `grammars/`, `highlights/` or `check-grammars.sh` | Also the grammar regeneration and TextMate checks |
| Push to `development`, `integration/unified-core`, a catch-up train (`train/catchup-*`) (and `main`), nightly, Run workflow | Everything |

A full-set job's `if` is exactly
`github.event_name != 'pull_request' || contains(github.event.pull_request.labels.*.name, 'full-ci')`;
the path-based ones read ci.yml's `changes` job (`CI paths`, a `git diff` of the merge commit,
which fails open: when it does not succeed, they run). A core gate has no `if`, so its check
starts on every pull request and can be required.

**Before and after the lean set** (a typical pull request: Rust and Python changes, none to the
corpora's, the Node package's or the facade's inputs). Before (#1047's run 43410079432): 25 of
ci.yml's jobs ran, 20 of them building or testing (engine tests on Linux, macOS and Windows,
Python 3.10 and 3.14, 4 E2E shards, 5 corpus parts, lint, engine lint, deny, GitLab CI lint,
golden compare), plus CodeQL's 2, for 11.5 minutes first job to last; Windows's engine tests
(11.4 minutes) were the long pole, then golden compare (8.6) and the vocabulary corpus part
(8.4). After: Linux only, 12 building or testing (lint, engine lint, 2 engine test shards, deny,
Python 3.14, 4 E2E shards, GitLab CI lint, golden compare); the gathering checks, the 3.10 cell
and CodeQL report in seconds. Then golden compare in three parts (#841's next cut), the wheel
from the sdist moved to the full set, the release dry run's and the benchmarks' caches made
per-runner sccache or restore-only, and engine lint building xtask once.

**Core gates** (every pull request):

| Job | What it checks |
|-----|----------------|
| `lint` | ruff, ty (the dependencies installed without the project), actionlint 1.7.7 over the workflows with shellcheck over their scripts (`.github/actionlint.yaml`), `uv build --sdist` and `twine check` (the full set also builds the wheel from the sdist, the `develop` profile, into the cached target directory); the vocabulary drift gate and the model field descriptions (below) when their files change |
| `engine` | rustfmt, clippy `-D warnings`, one `cargo build` of xtask and `opentide-lsp` whose binaries the later steps run: `xtask check-layers`, `xtask cassettes check` (#831: one deploy cassette per scenario of `tests/cassettes/scenarios.toml`, recorded and redacted, none edited by hand), `cargo doc --no-deps --workspace` with `RUSTDOCFLAGS=-D warnings`, the engine's invariant scripts (`check-io-free.sh`, `check-names.sh`, `validate-skills.sh`, `generate-highlights --check`), the bundled Tide catalog test and the engine release script's tests |
| `engine-test` | (`engine-test-part`: Linux in three shards by package, each building and testing only its packages (`matrix.packages`, `-p` per package: a test harness is a binary, which sccache does not cache, so a `--partition` shard compiled every test of the workspace again), on every pull request; `tests/test_ci/test_ci_scope.py` holds the shards to every workspace member exactly once, to even shares, and to the features `--workspace` enables on each member (`cargo tree -e features`: the bindings turn on the facade's `cli`, `python` and the rest and opentide-schema's `python`, which gate tests, so shards 1 and 2 name them with `--features`); opentide-schema's compile-fail cases (`opentide-schema::ui`, trybuild, a minute) run in the full set and on a pull request that changes the derive, the crate, the cases, `Cargo.lock`, the toolchain or ci.yml (the shard reads the merge commit's diff, and runs them when it cannot); macOS and Windows whole in the full set, through a matrix that depends on the scope, `include: ${{ fromJSON(<full set> && '[...]' || '[...]') }}`; `engine-test` gathers them under each OS's required check, as `corpus` does, #841, and on a pull request reports macOS's and Windows's as the Linux shards') `cargo nextest run --profile ci` on Linux (each shard's packages), macOS and Windows (`--workspace`) (one test compares with Python's difflib: setup-python's interpreter, `OPENTIDE_PYTHON`; nothing is synced); the doctests (`cargo test --doc`, each shard its packages') on Linux; fails when the tests leave a file in the checkout that `git status` shows (#931) |
| `deny` | `cargo deny check` against [`deny.toml`](../deny.toml) (licences, RustSec advisories, duplicate versions, OpenSSL, sources) for the workspace and the `publishing/` placeholder crate, and advisories, bans and sources for `fuzz/`; cargo-deny 0.20.2, prebuilt and checksum-checked ([`docs/internal/supply-chain.md`](../docs/internal/supply-chain.md)) |
| `test` | Python **3.14** with the coverage gate; the **3.10** cell runs in the full set (on a pull request it starts and skips its steps, `env.RUNS`, so its required check reports); `test-full` adds 3.11–3.13 in the full set |
| `cli-e2e`, `gitlab-ci-lint` | The sharded E2E suite (4 shards) and the generated GitLab pipelines; neither waits for `test`. The E2E tests that only repeat a golden case through the same console script run in the full set (`full_set`): `test_opentide_console_script_help`, `test_opentide_console_script_json_is_single_document`, `test_opentide_console_script_validates_corpus` and `test_workflow_subprocess_e2e.py` |
| `golden-compare` | `cargo xtask golden check --engine rust` (UC-0.7; every case since UC-6.2, #841): every golden case through this repository's CLI, the Rust core, against the oracle's recording and `tests/golden/APPROVED_DIFFS.toml`; `cargo xtask mcp replay --engine rust` (the recorded Python MCP sessions against the Rust server) and the MCP stdio tests. In three parts (`golden-compare-part`, `Golden compare (part K/3)`): each runs `--partition K/3`, the cases whose id's FNV-1a hash falls in it, and writes the ledger entries it did not apply (`--unused`, the `golden-unused-K` artifact); part 2 replays the MCP sessions, part 3 runs the MCP tests. `golden-compare` gathers them under the required check's name, `Golden compare`, with `if: ${{ !cancelled() }}`: it fails unless every part passed, and on an entry every part lists, a stale one. The `golden-compare-K` artifacts hold the reports |
| `corpus` | On a pull request that changes the corpora's inputs (above), and in the full set. (`corpus-part` in five parts on five runners: `Corpus (generator)`, `(faults)`, `(diffs)`, `(editor)`, `(vocabulary)`; `corpus` gathers them under the required check's name, with `if: ${{ !cancelled() }}` so that a failed part fails it, #841) The corpora of UC-0.6 against opentide 0.23.0 from PyPI, hash-pinned in its own venv: the heavy workspace has no finding, `cargo xtask corpus faults --check` (every fault kind reports exactly its codes), the code inventory and `COVERAGE.md` are current ([`tests/corpora/README.md`](../tests/corpora/README.md)); opentide-schema's object models against the oracle (UC-1.3): `corpus faults --check --engine rust --only objects` and `cargo xtask schema diff --against python` (JSON Schemas, findings on every corpus); the platform-block and configuration fault kinds through the Rust engine, finding for finding (`corpus faults --check --engine rust --only platforms` and `--only configuration`, UC-1.4 #810 and UC-1.5 #811, the `faults` part, about a minute); every workspace's resolved configuration and its configuration findings against the oracle's (`cargo xtask config diff --against python`, UC-1.5 #811, the `diffs` part, seconds); `cargo xtask validate diff` (UC-2.2: opentide-workspace's validate against the recordings of `validate --json`, every difference approved, none stale; UC-2.3: its `--fix` and `--fix --dry-run` cases too) and `cargo xtask lint diff` (UC-2.3: its lint against the recordings of `lint --json`) |
| `changes` | `CI paths`: whether the pull request changes the release's inputs, the grammars, the corpora's inputs, the Node package's or the facade's (above) |

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
name a toolchain, the dated nightly `fuzz/NIGHTLY` pins. The package builds are stricter (`build-packages.yml`: every wheel and
npm native package): `scripts/build/install-rust.sh` installs the pinned release by name with the
minimal profile, without the file's rustfmt and clippy, and names it in `RUSTUP_TOOLCHAIN`, so that
rustup installs nothing in the middle of a build; the Linux wheels' containers do the same in
`pyproject.toml`'s `[tool.cibuildwheel.linux]` `before-all` and `environment`. Every job that runs cargo sets
`RUSTFLAGS=-Dwarnings` (the nightly fuzz build aside); the test jobs also set
`CARGO_PROFILE_DEV_DEBUG=line-tables-only` and `INSTA_UPDATE=no` (CI never writes a snapshot).

**Compiler caches, one strategy** (`tests/test_ci/test_rust_caches.py`, #841, #1047): the Rust
jobs of ci.yml wrap rustc in sccache (`RUSTC_WRAPPER`, 0.19.0 from taiki-e/install-action), whose
directory (`SCCACHE_DIR`, `.sccache/` in the checkout, gitignored: actions/cache refuses a path
with `..`) actions/cache keeps under `sccache-<family>-<hash of rust-toolchain.toml>-<ISO week>`
(the week from a `week` step just before the restore, `date -u +%G-W%V`), restored with the
family and toolchain as `restore-keys`. The key hashes neither the sources nor `Cargo.lock`:
sccache is content-addressed, so a copy a few days old still serves every crate that did not
change, and a family is saved once a week, by the first push of the week. A key on `Cargo.lock`,
which most merges change, saved every family again on each merge, and with the target trees
below that passed the 10 GB GitHub keeps, so the families pull requests restore were evicted
before the next one read them (the engine tests built cold). Each family has one job that saves
it (`actions/cache/save`, from a push, only when the key missed):
`lint`, `engine-check` (`engine`), `engine-dev-<os>-<n>` (each `engine-test-part` shard per OS;
`clients` and `elastic-sweep` restore Linux shard 2's, which tests `opentide-lsp` and `opentide-analysis`), `corpus` (`corpus-part`'s generator; the other
parts and `corpus-queries` restore it), `python-engine` (`test`'s 3.14 cell; the other Linux
Python jobs restore it), `golden-compare` (part 1; the other parts restore it), and `full-set-<OS>` (`conformance` on each OS; the full
set's other Rust jobs restore their OS's: `facade`, `node`, `npm-install`, `engine-wasm`,
`engine-package`, `bench`, `cli-windows-smoke`). No job with a compiler cache restores a
rust-cache target tree too: that tree (about 0.7 GB a family) is what sccache covers, and the
two together, with a key per source tree, saved about 4 GB a push, more than GitHub's 10 GB per
repository keeps once a few pushes land, so the caches pull requests read were evicted within
minutes (#1047). The rust-caches left, target trees: `fuzz` (`fuzz-smoke`: the nightly's
`fuzz/target` and cargo-fuzz in `~/.cargo/bin`), plus coverage.yml's, golden.yml's, schema.yml's
and oracle.yml's own; each saves on the nightly and on pushes to `development` only
(`github.event_name == 'schedule' || github.ref == 'refs/heads/development'`), whose caches every
pull request reads (golden-preview.yml, on the 0.28 train only, saves on that branch's pushes). The release dry run
(`engine-release-build.yml`; a release restores none) keeps sccache families of its own,
`release-<os>-<arch>` per runner for the binaries (one cell per runner saves; the Intel macOS
cross build restores Apple silicon's) and `release-wasm`, saved from a push when the key missed;
its highlights, licences and SBOM jobs build without one. `bench.yml` restores `full-set-Linux`
(with `conformance`'s environment) and saves nothing: its two target trees evicted the pull
requests' families. Every Python job names the same
interpreter for PyO3 (`PYO3_PYTHON: /usr/bin/python3`): the binding is abi3, and a different
interpreter reruns PyO3's build script and rebuilds every crate above it.
**A pull request reads its base branch's caches** and the default branch's (`development`) only,
so every workflow that saves one on a push also runs on a push to a catch-up release train
(`train/catchup-*`), which pull requests target (`tests/test_ci/test_ci_scope.py`); the other
`train/` branches are pull requests' heads.
**Caches are saved from pushes only** (`github.event_name == 'push' && ...` on every sccache save, `save-if:
${{ github.event_name == 'push' ... }}` on every rust-cache, in every workflow a
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

**Budget:** a pull request's CI (the lean set), first job start to last job end, stays under 10
minutes on a warm cache (the second push of a branch). The long poles are golden compare and the
Linux engine test shards; split what grows past it, or move it to the full set.

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
- [`bench.yml`](workflows/bench.yml), on every push to `integration/unified-core`, nightly on
  `development`, on demand and on a pull request labelled `perf`: `cargo xtask bench` for the
  `python` (the oracle, opentide 0.23.0 from PyPI) and `rust` (the `opentide` binary, the
  language server, the workspace load) engines on `ubuntu-24.04`, a strace proof that
  `deploy --dry-run` and `generate docs` open no network connection, then `cargo xtask bench
  --check --require-reference` against `tests/bench/budgets.toml` and the `bench-<engine>`
  artifact of the last successful run on the comparison base, `BASE_BRANCH`
  (`integration/unified-core` until the Unified Core merges into development), on the same CPU
  (a command compared with nothing fails). The rules
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
  ci.yml. On a pull request each reference runs only when its own language's inputs change (its
  `changes` job, `Oracle paths`: the language's crate, grammar, catalog, testdata and oracle
  script; what every language builds on runs them all; the `full-ci` label, a push and a filter
  that fails run everything), so a KQL change pulls no Splunk, Falco or Elasticsearch image and no
  Lucene jar. The pinned Elastic references (Lucene's jars from Maven Central, the EQL and kuery
  grammars) are cached under `oracle.py`'s pins and saved from pushes; `oracle.py` checks each
  file's SHA-256, a restored one too (`tests/test_ci/test_ci_scope.py`).
- [`golden.yml`](workflows/golden.yml) runs `cargo xtask golden check --engine python` and
  `golden record --check-determinism` against the committed recordings of the frozen Python CLI
  (`tests/golden/README.md`) on every push to `development` and `integration/unified-core`,
  nightly and on demand. On a pull request its `Golden paths` job reads whether the pull request
  touches `tests/golden/`, `tests/corpora/`, the tide corpus, the render tests' inputs,
  `scripts/golden/`, xtask's golden, corpus, compare and parallel code, `crates/opentide-compare/`
  or golden.yml: the check runs when it does, or with the `full-ci` label. The determinism run is in the full set
  (the `full-ci` label on a pull request). The trigger itself has no path filter, so
  `integration/unified-core` requires `Golden paths` and the check (Required checks, above).
- [`golden-preview.yml`](workflows/golden-preview.yml), on every push to `train/catchup-0.28`,
  every pull request into it and on demand (no other branch): the preview of the next oracle
  (O1 of `docs/internal/catchup-0.28-plan.md`). It records every case from the release
  `tests/golden/ORACLE.next` names (0.28.1) with `cargo xtask golden record --oracle
  tests/golden/ORACLE.next --out DIR` into an actions cache keyed on the oracle, the cases and
  their inputs (saved from pushes only), then runs `cargo xtask golden check --engine rust
  --recordings DIR` and uploads its report (`golden-preview` artifact) with the summary line in
  the job summary. Report only: a difference from 0.28.1 passes (exit status 1), a check that
  cannot run fails (2). Not a required check (`tests/test_ci/test_golden_preview_workflow.py`).
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
