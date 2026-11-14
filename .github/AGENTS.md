# .github — Agent Guide: CI, CodeQL, releases, Dependabot

What runs on a pull request and a push, and how to reproduce it locally. The root
[`AGENTS.md`](../AGENTS.md) is the map; the [steward](../.agents/skills/steward/SKILL.md) skill
drives a PR to green and [github-actions-templates](../.agents/skills/github-actions-templates/SKILL.md)
covers editing workflows.

## CI (`workflows/ci.yml`): one workflow for the repository

The maintainer's rules (2026-11-14): fast and efficient; a pull request checks integration and
correctness **of what it changed**, not everything; a push to a base branch checks everything; a
deeper nightly never gates; a release pull request also proves the packages on every OS. No
workflow compares with the frozen Python CLI byte for byte (below). `tests/test_ci/` holds every
rule here.

**Concurrency** (`tests/test_ci/test_concurrency.py`): a pull request's new push cancels its stale
run; every other run (a push to a base branch, the nightly, Run workflow) is in a group of its
own, `${{ github.run_id }}`, so no run cancels it and every merge to a base branch gets a complete
run. Every workflow with a push trigger and a concurrency group (`ci.yml`, `codeql.yml`) uses the
same two lines:

```yaml
group: <name>-${{ github.event_name }}-${{ github.event_name == 'pull_request' && github.ref || github.run_id }}
cancel-in-progress: ${{ github.event_name == 'pull_request' }}
```

A group shared by two pushes would not do, even without `cancel-in-progress`: GitHub keeps one
pending run per group and cancels the older one when a newer one queues.

A push's run is named after its commit's first line, `CI on <branch>: Merge pull request #N ...`,
so a failure on a base branch names the pull request that brought it.

### What runs where

`changes` decides the tier and what the run checks
([`scripts/ci/changes.py`](../scripts/ci/changes.py), `tests/test_ci/test_changes.py`):

| Tier | Trigger | What runs |
|------|---------|-----------|
| **PR gate** | `pull_request` into `integration/unified-core`, `development`, `train/*`, or the branch below a stacked pull request | Linux only; only the jobs the change needs (below). Target: 5 min warm, 8 cold |
| **Full** | `push` to `main`, `development`, `integration/unified-core`, `train/*`; Run workflow `scope: full` | The gate's jobs with every path filter on, Linux only. Target: 10 min |
| **Release** | A pull request into `development` from `integration/unified-core` or `release/*`, or labelled `release`; Run workflow `scope: release` | Everything, plus every package on every target, an install smoke test of each on its OS, the publish dry run and the docs. The only pull requests that run macOS and Windows |
| **Nightly** | `schedule` (on `development`'s copy); Run workflow `scope: nightly` | Everything, plus the nightly set (below). Never gates; a failure opens or updates one issue labelled `nightly-failure` |

**What a pull request's change affects.** The files it changes (`git diff base...head`) map to
areas, first match wins; a file in a workspace crate marks that crate, and the **affected crates**
are the marked ones and every crate that depends on them, by any kind of dependency (`cargo
metadata --no-deps`). A change to `Cargo.lock`, `Cargo.toml`, `rust-toolchain.toml`, `.cargo/`,
`.config/`, `clippy.toml`, `rustfmt.toml`, a workflow, `.github/actionlint.yaml` or
`scripts/ci/` marks everything, and so does a path no rule knows (the filter fails open, never
closed). Then:

- the Rust jobs (`engine-lint`, `build`, `rust-tests`) run when a crate is affected, and test only
  the affected crates;
- the Python jobs (`python`, `e2e`) run when Python changes (`src/opentide`, `tests/`,
  `pyproject.toml`, `uv.lock`, `hatch_build.py`, the scripts) or the affected crates reach
  `opentide-native`, the binding that holds the command line (in practice most Rust changes; a
  docs-only, skills-only or Node-only change does not);
- each specialised job runs only when its own paths change: `node` (`bindings/node/`), `wasi`
  (`crates/opentide-wasm/`, the WASI shims: `crates/*wasi*`, `vendor/`, `packages/`,
  `build-wasm.sh`), `grammars` (`grammars/`), `textmate` (`highlights/`, `editors/`),
  `gitlab-ci-lint` (opentide-cli's CI renderer and `setup` commands, the linters' installer, its
  test), `facade` (`crates/opentide/`: the public API), `deny` (`Cargo.lock`, `deny.toml`, a
  manifest, `vendor/`, `fuzz/`, `publishing/`), `docs` (`docs/`, the root guides);
- a docs-only pull request runs `docs` alone; a skills-only one, `lint` alone.

The push to the base branch runs everything, so what a pull request's filter leaves out is still
checked before the next pull request builds on it.

**The PR gate's jobs** (the full tier runs all of them):

| Job | What it checks |
|-----|----------------|
| `changes` | The plan: the tier, the affected crates (`packages`: `--workspace` or `-p` per crate, with the facade's and opentide-schema's test features), the Rust test partitions, the areas. Seconds: the runner's stable cargo reads the manifests |
| `lint` | ruff, ty over `src/opentide` on the checked-in stubs of `_native` (`src/opentide/_native/*.pyi`: nothing compiles), actionlint 1.7.7 with shellcheck (`.github/actionlint.yaml`), `uv build --sdist` and `twine check`, the engine's invariant scripts (`check-io-free.sh`, `check-names.sh`, `validate-skills.sh`) and the engine release script's tests. About a minute |
| `engine-lint` | rustfmt, clippy `-D warnings` and `cargo doc --no-deps` with `RUSTDOCFLAGS=-D warnings`, **workspace-wide** whatever changed (a warm cache re-checks only what changed) |
| `build` | **The gate's one build** (the only gate job that compiles the workspace): the affected crates' tests as a `cargo nextest archive` (their binaries, the binaries their tests run, build-script output), and the `_native` extension (`cargo build -p opentide-native --lib`, `PYO3_BUILD_EXTENSION_MODULE=1`, in the profile the tests used, so their dependencies are compiled once), linked with mold, one sccache family; both uploaded at once. Then, while the test jobs run: `xtask check-layers`, `xtask cassettes check`, `xtask codegen --check` (never `--oracle`), `opentide-lsp generate-highlights --check`, `xtask vocab sync --check` and `xtask spec-fields` against `opentidehq/specifications` when their inputs change (and on every push and nightly), the doctests (nextest runs none), and opentide-schema's compile-fail cases (trybuild, which compiles at test time) when the derive, the crate, the cases, `Cargo.lock` or the toolchain change |
| `rust-tests` | The archive's tests, `cargo nextest run --archive-file ... --partition count:k/N --profile ci`: two partitions when the heavy crates (`opentide-cli`, `opentide-analysis`, `opentide-lsp`, `xtask`, the facade) are affected, one otherwise; nothing compiles. Fails when a test leaves a file in the checkout (#931) |
| `python` | Python **3.14** with the coverage gate, on the build's extension (`OPENTIDE_ENGINE_PREBUILT`: `hatch_build.py` installs it instead of compiling) |
| `e2e` | The E2E suite (CLI, MCP and LSP over stdio) in two shards (`--splits 2`, balanced by `.test_durations_e2e`), on the build's extension; the tests marked `full_set` run nightly |
| `gitlab-ci-lint` | The pipeline `opentide setup ci gitlab` renders, linted (glint, gitlab-ci-verify) |
| `docs` | `scripts/validate-docs.sh` (the site builds in opentidehq/website) |
| `facade` | The `opentide` facade with every feature: tests and doctests, rustdoc as docs.rs builds it, `cargo semver-checks` (0.51.0) against the first parent |
| `node` | `@opentide/opentide` (`bindings/node`): the napi-rs addon for linux-x64-gnu, the generated `index.js` and `index.d.ts` against the committed ones, `npm test`, and `npx . --json commands` byte for byte the console script's (on the build's extension) |
| `wasi` | The WASI command line the VS Code extension runs: `build-wasm.sh cli`, its size held to the .vsix's 15 MiB, tenant commands through `@opentide/wasi-host` |
| `grammars`, `textmate` | Every vendored `parser.c` is what tree-sitter-cli 0.25.10 generates; the TextMate grammars as VS Code reads them |
| `deny` | `cargo deny check` against [`deny.toml`](../deny.toml) for the workspace, `fuzz/` and the `publishing/` placeholder crate ([`docs/internal/supply-chain.md`](../docs/internal/supply-chain.md)) |
| `gate` (**`PR gate`**) | The one required check (below) |

**The release tier** (a release pull request, `scope: release`; the packaging jobs nightly too):
`sdist` and `smoke-sdist` (a build from the sdist with the runner's stable Rust); `packages`
([`build-packages.yml`](workflows/build-packages.yml): every wheel, each installed and run on its
platform by cibuildwheel, and every npm tarball, at `X.Y.Z.devN` / `X.Y.Z-dev.N`, kept 14 days:
[`docs/internal/publishing.md`](../docs/internal/publishing.md#testing-a-build-without-publishing));
`smoke-wheel` (pip install on Linux x64 and arm64, macOS, Windows); `smoke-npm` (a throwaway local
registry, Linux, macOS, Windows); `engine-release-dry-run`
([`engine-release-build.yml`](workflows/engine-release-build.yml): every binary, installer,
WebAssembly build, SBOM and SHA256SUMS); `smoke-installer` (the installers on Linux x64 and
arm64, macOS, Windows); `engine-package` (every crate packaged and built as crates.io builds it,
and the licence scan) and `smoke-cargo` (`cargo install opentide --features cli` from those
packages); `publish-dry-run` ([`publish-dry-run.yml`](workflows/publish-dry-run.yml)); and `docs`.
The smoke tests are publish.yml's own.

**The nightly set** (`mode == 'nightly'`): `engine-test-os` (the workspace's tests on macOS and
Windows, built there), `test-full` (Python 3.10 to 3.13 on the build's abi3 extension), `e2e-full`
(the `full_set` E2E tests), `coverage` ([`coverage.yml`](workflows/coverage.yml)), `benchmarks`
([`bench.yml`](workflows/bench.yml)), `oracle` ([`oracle.yml`](workflows/oracle.yml): the
vendor-parser oracles), `schema` ([`schema.yml`](workflows/schema.yml)), `conformance` (the
cross-SDK suite on three OSes), `engine-wasm`, `npm-install`, `elastic-sweep`, `fuzz-smoke`,
`clients` and `bench` (informational), `cli-windows-smoke`, `engine-release-consumers`, plus the
packaging jobs above; `nightly-report` opens or comments on the one open issue labelled
`nightly-failure` with the failing jobs. coverage.yml, bench.yml, oracle.yml, schema.yml and
publish-dry-run.yml have `workflow_call` and `workflow_dispatch` only: ci.yml runs them. The
schedule runs `development`'s copy of the workflows: test a change to the nightly with Run
workflow (`scope: nightly`) on its branch.

**No byte-for-byte comparison with the Python CLI** (the maintainer's decision, 2026-11-14): golden
compare and check, golden determinism, the corpora's diffs against the oracle, the MCP replay, the
payload, config, validate, lint, registry, schema and vocab diffs left every workflow, with
`golden.yml` and `golden-preview.yml`. `cargo xtask golden`, `compare` and `corpus` stay, run by
hand; the Rust tests that replay the oracle's recordings are
`#[ignore = "byte-level replay against the Python oracle: run by hand with --run-ignored only"]`
(`cargo nextest run --run-ignored only`); `tests/golden/APPROVED_DIFFS.toml` gates nothing
([`tests/golden/README.md`](../tests/golden/README.md)). The vendor-parser oracles (Kusto.Language,
Splunk, Elasticsearch, Lucene, Falco) are real products' parsers: they run nightly.

Every Rust job installs the release `rust-toolchain.toml` pins (`rustup toolchain install` with no
name, never floating `stable`), then its targets with `rustup target add`: that install drops
`--target` and `--component` silently (`tests/test_ci/test_rust_toolchain.py`). `changes` alone
uses the runner's stable cargo, for `cargo metadata --no-deps`. Only the fuzz jobs name a
toolchain, the dated nightly `fuzz/NIGHTLY` pins. The package builds are stricter
(`build-packages.yml`): `scripts/build/install-rust.sh` installs the pinned release by name with
the minimal profile and names it in `RUSTUP_TOOLCHAIN`; the Linux wheels' containers do the same
in `pyproject.toml`'s `[tool.cibuildwheel.linux]`. Every job that runs cargo sets
`RUSTFLAGS=-Dwarnings` (the nightly fuzz build aside); the test jobs also set
`CARGO_PROFILE_DEV_DEBUG=line-tables-only` and `INSTA_UPDATE=no` (CI never writes a snapshot).

**Compiler caches** (`tests/test_ci/test_rust_caches.py`, #841, #1047): sccache (`RUSTC_WRAPPER`,
0.19.0) in `.sccache/`, kept by actions/cache under
`sccache-<family>-<hash of rust-toolchain.toml>-<ISO week>`, restored with the family and
toolchain as `restore-keys`, saved by exactly one job when the key missed: once a week. sccache is
content-addressed, so a copy a few days old still serves every crate that did not change; a key
on the sources or `Cargo.lock` saved every family on each merge and evicted what pull requests
restore. The families: `build` (the gate's one build) and `engine-check` (`engine-lint`), saved
from a push to each base branch and from Run workflow (a pull request reads its base branch's
caches and `development`'s), and from a pull request only when it restored no copy of the family
at all (`cache-matched-key` empty: its base has none yet, after a new family or a toolchain bump),
so its next push is warm; `wasi`; `full-set-Linux` (`conformance` saves it, by the nightly; `node`,
`facade` and the nightly's Linux Rust jobs restore it); the release dry run's own
(`release-Linux-<arch>`, `release-wasm`). **Linux only**: macOS and Windows build cold (their
caches crowded the Linux families out of the 10 GB GitHub keeps). **A pull request saves no
cache** but that bootstrap copy. The one rust-cache left: `fuzz` (`fuzz-smoke`), plus coverage.yml's, schema.yml's and
oracle.yml's own. uv's cache (setup-uv) is keyed on `uv.lock`.

**Coverage:** gate on Python **3.14** only (`COVERAGE_PYTHON`); the Code Quality upload is
best-effort, the HTML report an artifact.

**Budget:** the PR gate, first job start to last job end, under 5 minutes warm and 8 cold; the
full tier under 10; no gate job over about 3 minutes after the build. Split what grows past it,
narrow its filter, or move it to the nightly.

## Required checks

Branch protection on `development` and `integration/unified-core` requires **one** check, the
`gate` job: it passes when `changes` succeeded and every job it needs succeeded or was skipped
(a job is skipped exactly when the change does not need it), and fails on any failure or
cancellation (`if: always()`: a failed job must not skip it, since a skipped required check
passes). `tests/test_ci/test_one_ci.py` fails when this list and the workflows differ. CodeQL is
path-scoped on pull requests, so it is not a required check: a path-filtered workflow does not
report when it does not run, and a required check that never starts blocks the merge.

<!-- required-checks -->
```text
PR gate
```

Every check the earlier lists named (`Lint`, `Engine lint (fmt, clippy, doc, layers)`, `Engine
tests (ubuntu-latest)`, `Supply chain (cargo deny)`, `Test (3.14)`, `E2E (3.14, shard N/4)`,
`Analyze (python)`, `Analyze (actions)`, and before them `CI paths`, `Golden compare`, `Golden
check (python)`, the corpus and the macOS and Windows engine tests) must leave both rules in the
same change that adds `PR gate`, or every pull request waits on them.

To set it (a repository admin): **Settings → Rules → Rulesets → New ruleset → New branch
ruleset**; name it `development`, Enforcement status **Active**; **Target branches → Add target →
Include by pattern** `development`; tick **Require status checks to pass**, then **Add checks**
and add `PR gate` (it appears once it has run on a pull request; choose the GitHub Actions
source); **Create**. For `integration/unified-core`, the same with that pattern. With classic
branch protection: **Settings → Branches** → the rule → **Require status checks to pass before
merging** → add `PR gate`, remove the others → **Save changes**.

## The other workflows

- [`publish.yml`](workflows/publish.yml): the release train (below).
- [`build-packages.yml`](workflows/build-packages.yml) and [`engine-release-build.yml`](workflows/engine-release-build.yml):
  the packages and the release assets, reusable workflows that `publish.yml` and ci.yml's release
  tier call.
- [`engine-fuzz.yml`](workflows/engine-fuzz.yml) fuzzes every target for ten minutes a night with
  the corpus it keeps, and uploads what crashed; a schedule of its own, so not part of ci.yml.
- [`bench.yml`](workflows/bench.yml), in the nightly (ci.yml calls it) and on demand (Run
  workflow on a branch measures a change): `cargo xtask bench` for the
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
- [`schema.yml`](workflows/schema.yml), in the nightly (ci.yml calls it) and on demand:
  `opentide-schema` (UC-1.1)
  built for the native target, abi3-py310 (feature `python`) and `wasm32-unknown-unknown`
  (feature `wasm`), clippy on the last two (ci.yml's engine jobs build no features), and its tests
  with the Python class on CPython 3.10, the abi3 floor; clippy with feature `stubs`, and
  `cargo xtask stubs --check`, which fails when the generated `src/opentide/_native/models.pyi`
  or `src/opentide/_native/sdk.pyi` differs from the extension (UC-1.9, UC-5.2b). Written before ci.yml became one workflow; not a required
  check.
- [`oracle.yml`](workflows/oracle.yml) checks the query parsers against Kusto.Language, Splunk,
  Elasticsearch, Lucene, Kibana and Falco (`OPENTIDE_ORACLE_REQUIRED`), the vendors' own parsers
  (not the Python oracle), in the nightly (ci.yml calls it, with the Carbon Black Cloud tenant)
  and on demand: every reference on each run. Its network-heavy references keep it out of ci.yml. The pinned Elastic
  references (Lucene's jars from Maven Central, the EQL and kuery grammars) are cached under
  `oracle.py`'s pins and saved by the scheduled run; `oracle.py` checks each file's SHA-256, a
  restored one too (`tests/test_ci/test_ci_scope.py`).
- [`publish-dry-run.yml`](workflows/publish-dry-run.yml) (every publish rehearsed, nothing
  published): in a release pull request's checks and the nightly (ci.yml calls it), and on demand.
- Deleted (2026-11-14): `docs.yml` (now ci.yml's `docs` job), `stack-comment.yml`, `golden.yml`
  and `golden-preview.yml` (`cargo xtask golden check --engine python` and `golden record
  --check-determinism` run by hand: `tests/golden/README.md`).
- [`codeql.yml`](workflows/codeql.yml) (below) and [`vocab-upstream.yml`](workflows/vocab-upstream.yml)
  (its own header).

Where each of language-server's workflow jobs went (or why it was dropped):
[`docs/engine/IMPORT.md`](../docs/engine/IMPORT.md#where-the-workflows-went).

## Test strength (UC-X.2, #844)

[`docs/internal/test-strength.md`](../docs/internal/test-strength.md) explains the three measures;
`tests/test_ci/test_test_strength_workflows.py` holds their permissions and triggers.

- [`coverage.yml`](workflows/coverage.yml), in the nightly (ci.yml calls it) and on demand: job **Rust coverage gates**. One cargo-llvm-cov build measured by the workspace's Rust tests and by the whole Python
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
session can release. **Release candidates are internal**: `internal_candidate: N`, from
`integration/unified-core` or `development`, builds and smoke-tests everything the same way,
pushes the tag `vX.Y.Z-rc.N` and creates a **draft** GitHub pre-release with every binary, wheel,
sdist, crate and npm tarball (SHA256SUMS, PACKAGES-SHA256SUMS, the SBOMs); it publishes nothing to
PyPI, crates.io or npm and mints no OIDC token, so the maintainer tests a candidate before
anything reaches a package manager (`v1.0.0-rc.N` until the final 1.0.0). The public
`release_candidate` path is refused while the internal channel exists (a `dry_run` rehearsal
aside), and resuming an `-rc` tag is refused. `dry_run` publishes nothing;
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

## CodeQL, Dependabot

**CodeQL:** Python and Actions via [`workflows/codeql.yml`](workflows/codeql.yml)
(`/language:python` + `/language:actions`): on a pull request that changes a Python file or a
workflow, on every push to a base branch, and nightly; not a required check. Code Quality may
also run dynamic Python on push. Local Python: `scripts/codeql-local.sh`. Skill:
[codeql](../.agents/skills/codeql/SKILL.md).

**Dependabot:** weekly PRs for `uv` (test toolchain grouped), `github-actions` (SHA pins) and
`pre-commit`. Merge procedure: [uv skill](../.agents/skills/uv/SKILL.md#dependency-upgrades-and-dependabot).

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
