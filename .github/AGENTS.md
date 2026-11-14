# .github — Agent Guide: CI, CodeQL, releases, Dependabot

What runs on a pull request and a push, and how to reproduce it locally. The root
[`AGENTS.md`](../AGENTS.md) is the map; the [steward](../.agents/skills/steward/SKILL.md) skill
drives a PR to green and [github-actions-templates](../.agents/skills/github-actions-templates/SKILL.md)
covers editing workflows.

## CI (`workflows/ci.yml`): one workflow for the repository

It runs on every pull request, whatever its base (a stacked PR targets the branch below it), on
every push to `development`, `integration/unified-core` (where the Unified Core PRs merge first)
and a catch-up train, nightly and on Run workflow. Jobs run in parallel.

**Concurrency** (`tests/test_ci/test_concurrency.py`): a pull request's new push cancels its stale
run; every other run (a push to `development`, `integration/unified-core` or `main`, the nightly,
Run workflow) is in a group of its own, `${{ github.run_id }}`, so no run cancels it and every merge
to a base branch gets a complete run. Every workflow with a push trigger and a concurrency group
(`ci.yml`, `codeql.yml`) uses the same two lines:

```yaml
group: <name>-${{ github.event_name }}-${{ github.event_name == 'pull_request' && github.ref || github.run_id }}
cancel-in-progress: ${{ github.event_name == 'pull_request' }}
```

A group shared by two pushes would not do, even without `cancel-in-progress`: GitHub keeps one
pending run per group and cancels the older one when a newer one queues.

### What runs where

Two scopes, the maintainer's rules (2026-11-14), held by `tests/test_ci/test_ci_scope.py`:

- **The gate**, on every pull request and every push to a base branch, on Linux: Lint, Engine
  lint, the engine tests in four shards, Python 3.14 with its coverage gate, E2E in four shards,
  cargo deny, and CodeQL (`codeql.yml`). Nothing else runs on a pull request. The gate's jobs carry
  no `if`: they are the required checks. Its target is 5 minutes warm.
- **The nightly set**, nightly and on Run workflow only, never on a pull request or a push, so it
  never blocks a merge: the platform and packaging matrix (below), and the other workflows
  (`coverage.yml`, `bench.yml`, `schema.yml`, `oracle.yml`, `docs.yml`, `publish-dry-run.yml`),
  which have no other trigger. A nightly job's `if` is exactly
  `github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'`. Run workflow on
  a branch runs the gate and the nightly set by hand; there is no `full-ci` label. Each nightly
  job is kept under 15 minutes. The schedule runs on the default branch, `development`, with its
  own copy of the workflows.

The comparisons with the frozen Python oracle (golden compare and check, golden determinism, the
golden preview, the corpora, the MCP replay, the payload, config, validate and lint diffs,
codegen's oracle comparisons) **left CI** once the port was done (2026-11-14): no workflow runs
them, and `tests/golden/APPROVED_DIFFS.toml` gates nothing. Their xtask commands stay, runnable
by hand (`tests/golden/README.md`; `tests/test_ci/test_golden_workflow.py` holds that no workflow
runs them).

A push's run is named after its commit's first line, `CI on <branch>: Merge pull request #N ...`,
so a failure on a base branch names the pull request that brought it.

**The gate** (every pull request and push):

| Job | What it checks |
|-----|----------------|
| `lint` | ruff, ty (the dependencies installed without the project), actionlint 1.7.7 over the workflows with shellcheck over their scripts (`.github/actionlint.yaml`), `uv build --sdist` and `twine check` (the nightly set also builds the wheel from the sdist, the `develop` profile, into the cached target directory); the vocabulary drift gate and the model field descriptions (below) when their files change |
| `engine` | rustfmt, clippy `-D warnings`, one `cargo build` of xtask and `opentide-lsp` whose binaries the later steps run: `xtask check-layers`, `xtask cassettes check` (#831: one deploy cassette per scenario of `tests/cassettes/scenarios.toml`, recorded and redacted, none edited by hand), `xtask codegen --check` (the generated artifacts are the committed ones; `--oracle`, the comparisons with the oracle's recordings, by hand only), `cargo doc --no-deps --workspace` with `RUSTDOCFLAGS=-D warnings`, the engine's invariant scripts (`check-io-free.sh`, `check-names.sh`, `validate-skills.sh`, `generate-highlights --check`), the bundled Tide catalog test and the engine release script's tests |
| `engine-test` | (`engine-test-part`: Linux in four shards: three by package, each building and testing only its packages (`matrix.packages`, `-p` per package: a test harness is a binary, which sccache does not cache, so a `--partition` shard compiled every test of the workspace again), on every pull request; `tests/test_ci/test_ci_scope.py` holds the shards to every workspace member exactly once, to even shares, and to the features `--workspace` enables on each member (`cargo tree -e features`: the bindings turn on the facade's `cli`, `python` and the rest and opentide-schema's `python`, which gate tests, so shards 1 and 2 name them with `--features`); shard 4 builds shard 1's packages with its features but only command_goldens' binary (`--test command_goldens`), and runs that binary's slowest groups (`generate`, `new_*`, `setup`, a minute or more each), which shard 1 leaves out with the complementary nextest filter (`HEAVY_GOLDENS`, `matrix.goldens`), so shard 1 is not the gate's time; opentide-schema's compile-fail cases (`opentide-schema::ui`, trybuild, a minute) run in the nightly set and when a pull request or push changes the derive, the crate, the cases, `Cargo.lock`, the toolchain or ci.yml (the shard reads the merge commit's diff, and runs them when it cannot); macOS and Windows run the same four shards in the nightly set, without a compiler cache, through a matrix that depends on the scope, `include: ${{ fromJSON(<nightly set> && '[...]' || '[...]') }}`; `engine-test` gathers them under each OS's check, #841: on a pull request only Linux's, the required one) `cargo nextest run --profile ci` on every OS (each shard's packages) (one test compares with Python's difflib: setup-python's interpreter, `OPENTIDE_PYTHON`; nothing is synced); the doctests (`cargo test --doc`, each shard its packages', shard 4 none) on Linux; fails when the tests leave a file in the checkout that `git status` shows (#931) |
| `deny` | `cargo deny check` against [`deny.toml`](../deny.toml) (licences, RustSec advisories, duplicate versions, OpenSSL, sources) for the workspace and the `publishing/` placeholder crate, and advisories, bans and sources for `fuzz/`; cargo-deny 0.20.2, prebuilt and checksum-checked ([`docs/internal/supply-chain.md`](../docs/internal/supply-chain.md)) |
| `test` | Python **3.14** with the coverage gate; 3.10 to 3.13 run nightly (`test-full`) |
| `cli-e2e` | The sharded E2E suite (4 shards); the tests marked `full_set` run nightly (`cli-e2e-full`) |

**The nightly set** (nightly and Run workflow only):

| Job | What it checks |
|-----|----------------|
| `test-full` | Python **3.11**, **3.12** and **3.13** (`Test (3.x)`), without coverage |
| `cli-windows-smoke` | The console launcher and Ctrl-C through it on Windows |
| `cli-e2e-full` | The E2E tests marked `full_set`, too slow for every pull request: a platform plugin on opentide installed from its wheel (`test_wheel_plugin_platform.py`); `cli-e2e` leaves them out |
| `facade` | The `opentide` facade crate with every feature: its tests and doctests (the binary's `--json commands` against the PyPI CLI's recording and the ledger, `cli::run_json`, the language server), rustdoc as docs.rs builds it, and `cargo semver-checks` (0.51.0) against the first parent; `engine-test` runs its default features on every pull request (the binary's `--json commands` test reads the oracle's recording: it stays a test of the crate) |
| `node` | The Node package `@opentide/opentide` (`bindings/node`, UC-5.3): the napi-rs addon built for linux-x64-gnu, its generated `index.js` and `index.d.ts` against the committed ones, `npm test` (the SDK, the bin and Ctrl-C, the packages, the TypeScript page's snippets, a `tsc --noEmit` consumer), and `npx . --json commands` byte for byte this repository's console script's (`duration_ms` zeroed); `cargo xtask golden check --runner node` runs by hand only |
| `npm-install` | The npm packages installed as a user installs them, as `publish.yml`'s `smoke-npm` does before a release: the tree's packages at the workspace version (`release.py npm-version`), the addon built for linux-x64-gnu (the other five native packages packed as stand-ins without an addon), published to a throwaway local registry (Verdaccio 6.11.1, no uplink), then `npm install @opentide/opentide` in a clean project: exactly the host's native package, `npx opentide --version`, the SDK from `require` and `import`, `runJson(['commands'])`, `tsc` against `index.d.ts`, and the same through the `opentide` alias (`scripts/engine/npm-local-registry/test.mjs`); it reads the `node` job's Rust cache |
| `packages` | Installable builds to test without publishing: [`build-packages.yml`](workflows/build-packages.yml), the wheels and npm tarballs a release builds, at a development version of the workspace's (PyPI `X.Y.Z.devN`, npm `X.Y.Z-dev.N`), kept 14 days as `wheels-<platform>` (`linux-x64`, `linux-arm64`, `macos-x64`, `macos-arm64`, `windows-x64`, `windows-arm64`) and `npm-<platform>` (`@opentide/opentide` and one native package); how to install them: [`docs/internal/publishing.md`](../docs/internal/publishing.md#testing-a-build-without-publishing) |
| `conformance` | The cross-SDK conformance suite (UC-5.4) on Linux, macOS and Windows: `uv sync`, the Node addon (develop profile, `OPENTIDE_VERSION` the workspace's), then `cargo xtask conformance --runners rust,python,node` (every operation of `tests/conformance/manifest.json` on the tide corpus, the heavy workspace, the fault workspace and each configuration fault, the three SDKs' documents byte for byte; [`tests/conformance/README.md`](../tests/conformance/README.md)) and `--diverge node` on the tide corpus, which passes only when the comparator catches the deliberate divergence; the `conformance-<os>` artifact holds `report.json` |
| `engine-wasm` | `scripts/engine/build-wasm.sh` (both WebAssembly artifacts, and `clippy` for the code only wasm32 compiles), the npm packages (`check-npm-packs.mjs`) and the TypeScript client against the native, worker and WASI servers |
| `engine-package` | Every crate the release train publishes, the facade and its crates included, packaged and built as crates.io builds it, and `license-scan.sh` over the packages (no oracle reference ships; the opentide-cli crate, which carries opentide's package data, with `--product`) |
| `grammars`, `textmate` | Every vendored `parser.c` is what tree-sitter-cli 0.25.10 generates (`check-grammars.sh`); the TextMate grammars as VS Code reads them |
| `elastic-sweep` | Every public Elastic detection rule (a pinned commit) passes the engine |
| `fuzz-smoke` | Each fuzz target of `fuzz/` for 60 s from its seeds and saved regressions (the dated nightly `fuzz/NIGHTLY` pins, up to three targets per runner; cargo-fuzz pinned) |
| `engine-release-dry-run` | The release train's asset jobs ([`engine-release-build.yml`](workflows/engine-release-build.yml)) for the workspace version: every asset (the `opentide` and `opentide-lsp` binaries for six targets, no musl; the installers), the CycloneDX SBOMs (`scripts/engine/sbom.py`, schema-checked), SHA256SUMS, and `release.py check-assets` (language-server v0.11.0's names with the version substituted, plus the train's). No tag, attestation, release or publish; `contents: read` |
| `engine-release-consumers` | opentidehq/vscode-extension's own grammar and engine scripts (a pinned commit) accept the dry run's assets as this repository's release (`scripts/engine/check-vscode-extension.mjs`) |
| `clients`, `bench` | Informational (`continue-on-error`): real LSP clients (pytest-lsp, Neovim) and `cargo bench`; never required |
| `wasi` | The WASI build of the command line the VS Code extension runs (ADR 0007's amendment): `scripts/engine/build-wasm.sh cli`, its deflated size held to the .vsix's 15 MiB, and tenant commands through the module with `@opentide/wasi-host` performing their requests from the cassettes (`cargo xtask golden check --runner wasi` runs by hand) |
| `gitlab-ci-lint` | The pipeline `opentide setup ci gitlab` renders, linted |

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
it (`actions/cache/save`, only when the key missed). The gate's families, which every pull
request's jobs restore, are saved from a push to each base branch, since a pull request reads its
base branch's caches; the nightly set's are saved by the nightly (on `development`) and on
pushes to `development` (`github.event_name == 'schedule' || github.ref == 'refs/heads/development'`),
whose caches every branch reads. The gate's families: `lint`, `engine-check` (`engine`),
`engine-dev-ubuntu-latest-<n>` (each Linux `engine-test-part` shard; `clients` and `elastic-sweep`
restore shard 2's, which tests `opentide-lsp` and `opentide-analysis`) and `python-engine`
(`test`, 3.14; the nightly set's Linux Python jobs restore it). The nightly set's: `wasi` (the
WASI module's crates in the `wasi` profile, which no other job builds), `full-set-Linux`
(`conformance`'s Linux cell, also on pushes to `integration/unified-core`; the nightly set's other
Linux Rust jobs restore it: `facade`, `node`, `npm-install`, `engine-wasm`, `engine-package`,
`bench`) and the release dry run's (below). **Linux only:** macOS and Windows keep no compiler
cache (engine-test's nightly cells, `conformance`'s, `cli-windows-smoke`, the release dry run's
runners: `test_only_linux_keeps_a_compiler_cache`). Theirs, about a gigabyte a family and saved per
base branch, filled the 10 GB with integration's and the train's core families, so those were
evicted between pushes (`cache-report.yml` on integration: 10,020 MB in use, #841); macOS's and
Windows's engine tests run in four shards instead. No job with a compiler cache restores a
rust-cache target tree too: that tree (about 0.7 GB a family) is what sccache covers, and the two
together, with a key per source tree, saved about 4 GB a push (#1047). The rust-caches left, target
trees: `fuzz` (`fuzz-smoke`: the nightly's `fuzz/target` and cargo-fuzz in `~/.cargo/bin`), plus
coverage.yml's, schema.yml's and oracle.yml's own, each saved by the nightly and on pushes to
`development` only. The release dry run (`engine-release-build.yml`; a release restores none)
keeps sccache families of its own, `release-Linux-<arch>` per Linux runner for the binaries (one
cell per runner saves; macOS and Windows build without one) and `release-wasm`, saved on
`development` and by the nightly when the key missed;
its highlights, licences and SBOM jobs build without one. `bench.yml` restores `full-set-Linux`
(with `conformance`'s environment) and saves nothing: its two target trees evicted the pull
requests' families. Every Python job names the same
interpreter for PyO3 (`PYO3_PYTHON: /usr/bin/python3`): the binding is abi3, and a different
interpreter reruns PyO3's build script and rebuilds every crate above it.
**A pull request reads its base branch's caches** and the default branch's (`development`) only,
so ci.yml also runs on a push to a catch-up release train (`train/catchup-*`), which pull requests
target; the other `train/` branches are pull requests' heads.
**No cache is saved from a pull request** (`github.event_name == 'push' && ...`, or the nightly's
condition, on every save): a pull request restores the caches of its base branch (and of
`development`) and saves none. A pull request's own cache served that pull request alone, and its gigabytes
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

**Budget:** the gate, first job start to last job end, stays under 5 minutes on a warm cache (the
second push of a branch); each nightly job under 15. Split what grows past it, or move it to the
nightly set.

## Required checks

Branch protection on `development` and `integration/unified-core` requires every check below:
the gate's jobs, every cell a pull request runs, and CodeQL's two (`codeql.yml` runs on every
pull request). `tests/test_ci/test_one_ci.py` fails when this list and the workflows differ. The
nightly set's jobs and workflows and the informational jobs are not required: they never start
on a pull request, and a required check that never starts blocks the merge.

<!-- required-checks -->
```text
Lint
Engine lint (fmt, clippy, doc, layers)
Engine tests (ubuntu-latest)
Supply chain (cargo deny)
Test (3.14)
E2E (3.14, shard 1/4)
E2E (3.14, shard 2/4)
E2E (3.14, shard 3/4)
E2E (3.14, shard 4/4)
Analyze (python)
Analyze (actions)
```

The checks this list dropped on 2026-11-14 must leave both rules in the same change, or every
pull request waits on them: `CI paths`, `Engine tests (macos-latest)`, `Engine tests
(windows-latest)`, `Corpus (generator, faults, coverage) against opentide 0.23.0`, `Test (3.10)`,
`GitLab CI lint`, `Golden compare`, `WASI command line (size, golden)`, and on
`integration/unified-core` `Golden paths` and `Golden check (python)`.

To set it (a repository admin): **Settings → Rules → Rulesets → New ruleset → New branch
ruleset**; name it `development`, Enforcement status **Active**; **Target branches → Add target →
Include by pattern** `development`; tick **Require status checks to pass** (and **Require
branches to be up to date before merging** if wanted), then **Add checks** and add each name
above (each appears once it has run on a pull request; choose the GitHub Actions source);
**Create**. For `integration/unified-core`, the same with the pattern `integration/unified-core`
and the same list. With classic branch protection instead: **Settings → Branches → Add classic branch
protection rule** (or edit the `development` rule) → Branch name pattern `development` → tick
**Require status checks to pass before merging** → search for and add each name → **Save
changes**. When a job is renamed or a matrix changes, update the list here and in the rule
together. A check removed from the list must be removed from the rule too, or every pull request
that does not run it waits for it.

## The other workflows

- [`publish.yml`](workflows/publish.yml): the release train (below).
- [`build-packages.yml`](workflows/build-packages.yml): the wheels and npm packages, a reusable
  workflow that `publish.yml` and ci.yml's `packages` job call.
- [`engine-fuzz.yml`](workflows/engine-fuzz.yml) fuzzes every target for ten minutes a night with
  the corpus it keeps, and uploads what crashed; a schedule of its own, so not part of ci.yml.
- [`bench.yml`](workflows/bench.yml), nightly on `development` and on demand (the nightly set;
  Run workflow on a branch measures a change): `cargo xtask bench` for the
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
- [`cache-report.yml`](workflows/cache-report.yml), weekly, on Run workflow (both from
  `development`'s copy only) and on a push to a base branch that changes it: every Actions
  cache with its ref, key family (the key without its hashes and week), size and last use,
  summed per ref and per family against the 10 GB GitHub keeps, in the job summary and the log
  (`scripts/cache_report.py`). It shows what crowds out the families pull requests restore
  (#841). Read-only (`actions: read`), never on a pull request; not a required check.
- [`rust-audit.yml`](workflows/rust-audit.yml) runs `cargo audit` on every Rust lock file
  (`git ls-files`) every day, with deny.toml's exceptions, and opens or comments on one issue when it finds an advisory.
  Its issue job is the only job in any workflow with `issues: write`, and it never runs on a pull
  request (`tests/test_ci/test_supply_chain.py`).
- [`schema.yml`](workflows/schema.yml), nightly and on demand (the nightly set):
  `opentide-schema` (UC-1.1)
  built for the native target, abi3-py310 (feature `python`) and `wasm32-unknown-unknown`
  (feature `wasm`), clippy on the last two (ci.yml's engine jobs build no features), and its tests
  with the Python class on CPython 3.10, the abi3 floor; clippy with feature `stubs`, and
  `cargo xtask stubs --check`, which fails when the generated `src/opentide/_native/models.pyi`
  or `src/opentide/_native/sdk.pyi` differs from the extension (UC-1.9, UC-5.2b). Written before ci.yml became one workflow; not a required
  check.
- [`oracle.yml`](workflows/oracle.yml) checks the query parsers against Kusto.Language, Splunk,
  Elasticsearch, Lucene, Kibana and Falco (`OPENTIDE_ORACLE_REQUIRED`), the vendors' own parsers
  (not the Python oracle), weekly (with the Carbon Black Cloud tenant) and on demand: every
  reference on each run. Its network-heavy references keep it out of ci.yml. The pinned Elastic
  references (Lucene's jars from Maven Central, the EQL and kuery grammars) are cached under
  `oracle.py`'s pins and saved by the scheduled run; `oracle.py` checks each file's SHA-256, a
  restored one too (`tests/test_ci/test_ci_scope.py`).
- [`docs.yml`](workflows/docs.yml) (`scripts/validate-docs.sh`) and
  [`publish-dry-run.yml`](workflows/publish-dry-run.yml) (every publish rehearsed, nothing
  published) are in the nightly set: nightly and on demand. A pull request that changes `docs/`
  structure, `publishing/` or the packaging is checked by Run workflow on its branch.
- golden.yml (`Golden check (python)`, `Golden determinism`) and golden-preview.yml were deleted
  with the rest of the oracle policing (2026-11-14): `cargo xtask golden check --engine python`
  and `golden record --check-determinism` run by hand (`tests/golden/README.md`).
- [`codeql.yml`](workflows/codeql.yml) (every pull request: required),
  [`stack-comment.yml`](workflows/stack-comment.yml),
  [`vocab-upstream.yml`](workflows/vocab-upstream.yml): below and in their own headers.

Where each of language-server's workflow jobs went (or why it was dropped):
[`docs/engine/IMPORT.md`](../docs/engine/IMPORT.md#where-the-workflows-went).

## Test strength (UC-X.2, #844)

[`docs/internal/test-strength.md`](../docs/internal/test-strength.md) explains the three measures;
`tests/test_ci/test_test_strength_workflows.py` holds their permissions and triggers.

- [`coverage.yml`](workflows/coverage.yml), in the nightly set (nightly and on demand): job **Rust coverage gates**. One cargo-llvm-cov build measured by the workspace's Rust tests and by the whole Python
  suite, which drives `opentide._native`; `cargo xtask coverage gate` checks each crate against
  `xtask/coverage.toml`. Read-only.
- [`mutants.yml`](workflows/mutants.yml), weekly and on demand: cargo-mutants on the crates of
  `xtask/mutants.toml` in eight shards, a report against `xtask/mutants-baseline.toml`, and on the
  schedule only a job with `issues: write` (no checkout, no repository code) that opens or updates
  one issue per crate above its threshold.
- The parity dashboard (`parity.yml`) was retired with the Python implementation (UC-6.2, #841): every command runs on Rust.

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
