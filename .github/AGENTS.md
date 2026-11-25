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

**Concurrency** (`tests/test_ci/test_workflows.py`): a pull request's new push cancels its stale
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

- the Rust jobs (`engine-lint`, `engine-lint-variants`, `build`) run when a crate is affected, and test only
  the affected crates;
- the Python job (`python`: the opentide wheel built by `native`, then one pytest run of the
  package and the E2E suite) runs **only when the Python surface changes**: `src/opentide/`,
  `bindings/python/`, the facade's API (`crates/opentide/src/`), `pyproject.toml`,
  `uv.lock`, `tests/` (but `tests/test_ci` and the docs tests that need no
  wheel). A Rust-only change to an engine, schema, compile or CLI crate builds no wheel and runs
  no pytest: the Rust tests cover it (the maintainer's rule). Every push runs it; a release pull
  request and the nightly run Python 3.10 to 3.14 and the `full_set` E2E tests;
- `lint`'s steps run on their own inputs: ruff and ty when a Python file
  changes; actionlint and `tests/test_ci` when a workflow, `scripts/ci/` or those tests change;
  the skills' validation; the engine's invariant scripts when a crate changes. `docs` validates
  the pages and runs the docs tests that need no wheel;
- each specialised job runs only when its own paths change: `node` (`bindings/node/`), `wasm`
  (`crates/opentide-wasm/`, the WASI shims: `crates/*wasi*`, `vendor/`, `packages/`,
  `build-wasm.sh`; the parser layer, where a C dependency and a parse's stack show only in
  WebAssembly: `crates/opentide-parse/`, the eleven query-language crates (`PARSER_CRATES` in
  `scripts/ci/changes.py`), `highlights/`; its native TypeScript-client tests only when
  `packages/` or `crates/opentide-wasm/` changes, `ts_packages`), `textmate` (`highlights/`,
  `editors/`),
  `gitlab-ci-lint` (opentide-cli's CI renderer and `setup` commands, the linters' installer, its
  test), `facade` (`crates/opentide/`: the public API), `deny` (`Cargo.lock`, `deny.toml`, a
  manifest, `vendor/`, `fuzz/`, `publishing/`), `docs` (`docs/`, the root guides), `website` (`docs/`),
  `throughput` (any crate opentide-analysis is built from, the throughput bench,
  `tests/bench/instructions.toml`, `xtask throughput`);
- a docs-only pull request runs `docs` and `website` alone; a skills-only one, `lint`'s skills step alone.

The push to the base branch runs everything, so what a pull request's filter leaves out is still
checked before the next pull request builds on it.

**The PR gate's jobs** (the full tier runs all of them):

| Job | What it checks |
|-----|----------------|
| `changes` | The plan: the tier, the affected crates, what `build` compiles (`packages`: `--workspace`, or `-p` per affected crate and per anchor, with the facade's and opentide-schema's test features) and the tests it runs (`filter`: a nextest filterset of the affected crates), the areas. Seconds: the runner's stable cargo reads the manifests |
| `lint` | ruff, ty over `src/opentide` on the checked-in stubs of `_native` (`src/opentide/_native/*.pyi`: nothing compiles), actionlint 1.7.7 with shellcheck (`.github/actionlint.yaml`), `uv build --sdist` and `twine check`, the engine's invariant scripts (`check-io-free.sh`, `check-names.sh`, `validate-skills.sh`), the engine release script's tests and the CI contracts (`tests/test_ci`). About a minute |
| `engine-lint` | rustfmt, clippy `-D warnings` and `cargo doc --no-deps` with `RUSTDOCFLAGS=-D warnings`, **workspace-wide** whatever changed (a warm cache re-checks only what changed) |
| `engine-lint-variants` | Beside `engine-lint`, sccache family `engine-variants`: opentide-cli's clippy and its `no_terminal_prompts` test without the `terminal` feature; clippy on the WebAssembly targets (`build-wasm.sh clippy`) when `wasm` runs (alone when only `wasm` is on, e.g. a `build-wasm.sh`-only change); when opentide-schema is affected, clippy on it with its `stubs` feature and for `wasm32-unknown-unknown` (UC-1.1; the `python` feature is unified on workspace-wide). One job until 2026-11: 10 to 13.5 min, the gate's longest |
| `native` | opentide's wheel as a release builds it (`maturin build --locked --profile dev --compatibility linux`: a `linux` tag, installed on this runner image only), linked with mold, its own sccache family, uploaded for the Python jobs: when the Python surface or GitLab CI lint's inputs change, every push and the nightly. A job of its own so that the Python jobs start after it, not after the tests (#1141: a push's `python` waited 8.4 min for the build). |
| `stubs` | `cargo xtask stubs --check` on Python 3.10 (the abi3 floor): the committed `src/opentide/_native/models.pyi` and `sdk.pyi`, which `lint`'s ty reads, against the extension built with PyO3's introspection (UC-1.9, UC-5.2b). When the binding, opentide-schema, the facade, the stubs or `xtask stubs` change (`stubs`) and on every push and nightly. Its own job and sccache family `stubs`: inside `native` it held the Python jobs back 8 minutes (#1141) |
| `wiring` | `cargo nextest run -p xtask --test language_wiring --test platform_docs`: every query language in every table it must be in (the add-language skill), and the platform tables and lists of `AGENTS.md`, `docs/cli/new.md`, `docs/cli/query.md`, `docs/cli/setup.md`, `docs/cli/validate.md`, `docs/usage/installation.md` and `docs/usage/concepts/platforms.md` as the registry has them. When a file outside a crate that the test reads changes (`wiring` in `scripts/ci/changes.py`: the WASM smoke samples, `fuzz.sh`, `check-io-free.sh`, the npm client, `fuzz/`, the editors, the Python stub, the budgets, the corpora, and the seven pages above) and on every push and nightly; a crate's change runs it in `build`. Sccache family `wiring` |
| `build` | **The gate's one build of the tests, and the Rust tests** (with `native`, the only gate jobs that compile the workspace): the affected crates' tests, the binaries their tests run, xtask and the language server, linked with mold, one sccache family; then `xtask check-layers`, `xtask cassettes check`, `xtask codegen --check`, `opentide-lsp generate-highlights --check`, `xtask vocab sync --check` and `xtask spec-fields` against `opentidehq/specifications` when their inputs change (`changes`' `vocab` and `fields` outputs; on every push and nightly); then the tests, `cargo nextest run --profile ci -E <filter>`, where they were built, on eight threads (`NEXTEST_TEST_THREADS`: many wait on the processes they start); the doctests (nextest runs none); and opentide-schema's compile-fail cases (trybuild, which compiles at test time) when the derive, the crate, the cases, `Cargo.lock` or the toolchain change (`schema_ui`). Every path filter is `changes.py`'s (`CHECKS`, tested in `test_changes.py`): no job diffs the tree itself. Fails when a test leaves a file in the checkout (#931). On a pull request it also builds the **anchors** (`opentide-connectors`, `opentide-workspace`, `ANCHORS` in `changes.py`), whose tests run only when affected: their dev-dependencies turn on third-party features (tokio's `test-util`, getrandom's `std`) that the push's `--workspace` build resolves with, so every unit a pull request builds is one the push's cache holds (without them a leaf change missed it for every crate above tokio and getrandom). Its `RUSTC_WRAPPER` is [`scripts/ci/rustc-wrapper/sccache`](../scripts/ci/rustc-wrapper/sccache), sccache without `CARGO_PRIMARY_PACKAGE`: sccache keys a compile on every `CARGO_*` variable, and cargo sets that one only for the packages a command names, so a pull request missed the cache for every unaffected crate it compiled (opentide-schema, 48 s). Named `sccache`, so that the cc crate sends the build scripts' C compiles through it too; Python, not `sh`: a shell drops the variables whose names are no identifiers (`CARGO_BIN_EXE_opentide-lsp`). No test archive and no test partitions: shipping the archive (1.5 GB, 18 s to pack, 15-33 s to download and 41 s to extract per partition) cost more than the partitions saved (#1141). `--timings`: the `cargo-timings` artifact shows where the build went |
| `python` | Python is the packaging layer: **one** job, one pytest run (`-n 4`) of the package's surface (the SDK, the models, the plugin API, the console script) and the E2E suite (CLI, MCP and LSP over stdio), Python **3.14** with the coverage gate, on `native`'s wheel (`uv sync --no-install-project`, then `uv pip install` of the wheel, its `_native` module copied into `src/opentide/` for the tests, which import from `src/`; `UV_NO_SYNC=1`: nothing compiles). No shards; the tests marked `full_set` run nightly; `tests/test_ci` runs in `lint` |
| `gitlab-ci-lint` | The pipeline `opentide setup ci gitlab` renders, linted (glint, gitlab-ci-verify) |
| `docs` | `scripts/validate-docs.sh` (the site builds in opentidehq/website) and the docs tests that need no wheel (`tests/test_docs` but `test_docs_commands_golden.py` and `test_sdk_snippets.py`, the Python job's) |
| `website` | **The website sync guard**: opentidehq/website's `main` with this run's own `docs/` at `vendor/opentide` (sparse; this tree, not the branch the website's `.gitmodules` names, so the check holds on `integration/unified-core` too) and opentidehq/specifications' `main` at `vendor/specifications`; then the site's own `pnpm install --frozen-lockfile` (the pnpm store cached by its lockfile, saved by pushes), `pnpm sync:content` (its MDX safety check), `pnpm test` (all but "workspace committed docs match vendor gitlinks", which compares the site's own committed content), `next build` (fumadocs-mdx: frontmatter, components, types) and `pnpm verify:docs`, each through [`scripts/ci/website-sync.sh`](../scripts/ci/website-sync.sh), which puts the website's error in an annotation and the job summary. A page the site refuses or cannot build stops its hourly "Sync docs and deploy" silently; this fails the pull request instead. When `docs/` changes (`website` in `changes.py`'s `CHECKS`) and on every push and nightly. Run it locally: check out the website, put `docs/` at `vendor/opentide/docs` and the specifications at `vendor/specifications`, `pnpm install`, then `scripts/ci/website-sync.sh <sync|test|build|verify> <website-dir>`. opentidehq/specifications has the same guard (`website-sync.yml`) |
| `facade` | The `opentide` facade with every feature: tests and doctests, rustdoc as docs.rs builds it, `cargo semver-checks` (0.51.0) against the first parent |
| `node` | `@opentide/opentide` (`bindings/node`): the napi-rs addon for linux-x64-gnu, the generated `index.js` and `index.d.ts` against the committed ones, and `npm test`; it compiles its own addon, so it starts beside `build`. Node's parity with the Python and Rust SDKs, byte for byte, is the conformance suite's (nightly and release pull requests) |
| `wasm` | Every WebAssembly artifact, one compiler cache (`wasm`): `build-wasm.sh browser wasi cli` (the browser module and the WASI language server, pure Rust, smoke-tested; wasi-sdk only for the command line's C, `ring`; the WASI command line the VS Code extension runs, its size held to the .vsix's 15 MiB), tenant commands through `@opentide/wasi-host` in the WASI module, the npm packs; when `packages/` changes (`ts_packages`) and on every push and nightly also the native language server and command line and the TypeScript client against the native, worker and WASI servers. The WebAssembly targets' clippy is `engine-lint-variants`'s |
| `throughput` | `cargo xtask throughput --check`: each language's parse and full analysis, counted with callgrind (valgrind from apt) on the bench profile in the bench binary's own instructions (within 3%) and its allocator calls (within 2), held to `tests/bench/instructions.toml` (#1571, ADR 0014, `docs/engine/THROUGHPUT.md`). When a crate the analysis is built from is affected, or the bench, the budgets or the command change; every push. Uploads the callgrind profiles when it fails. Sccache family `throughput`. Counts the bench binary's own code (glibc and the loader left out). Pinned to `ubuntu-24.04`, the image its budgets are recorded on |
| `textmate` | The TextMate grammars as VS Code reads them |
| `deny` | `cargo deny check` against [`deny.toml`](../deny.toml) for the workspace, `fuzz/` and the `publishing/` placeholder crate ([`docs/internal/supply-chain.md`](../docs/internal/supply-chain.md)) |
| `gate` (**`PR gate`**) | The one required check (below) |

**The release tier** (a release pull request, `scope: release`, and the nightly): one job,
`release` ([`release-build.yml`](workflows/release-build.yml), which publish.yml calls too, so
each build and smoke test exists once): `packages` ([`build-packages.yml`](workflows/build-packages.yml):
every wheel, built by maturin (PyO3/maturin-action), each installed and run on its own platform
(`wheel-smoke`), and every npm tarball, one `npm-packages` artifact), `engine-assets`
([`engine-release-build.yml`](workflows/engine-release-build.yml): every binary (Linux and macOS:
no standalone Windows executable ships), the installer, every WebAssembly build, SBOM and
SHA256SUMS), `sdist` (`maturin sdist`, twine's check) and
`crate-packages` (every crate packaged and built as crates.io builds it, and the licence scan),
at `X.Y.Z.devN` / `X.Y.Z-dev.N`, kept 14 days
([`docs/internal/publishing.md`](../docs/internal/publishing.md#testing-a-build-without-publishing));
then two smoke jobs running [`scripts/build/smoke_release.sh`](../scripts/build/smoke_release.sh):
`smoke`, the binary installer on Linux and macOS, `npm install` from a throwaway local registry on
each of the six platforms (Linux x64 and arm64, macOS arm64 and x64, Windows x64 and arm64) and the
PyPI dist's shape (one version, six cp310-abi3 wheels, one sdist); and `smoke-sources`, which starts
as soon as its packages exist (not after the slowest binary): a build from the sdist with the
runner's stable Rust, and `cargo install opentide --features cli` from the crate packages. In a release pull request or
`scope: release` run (not the nightly), the **antivirus gate** ([`av-gate.yml`](workflows/av-gate.yml),
#1743) scans every artifact with ClamAV, YARA (signature-base and protections-artifacts at pinned
commits, a reviewed allow-list) and Microsoft Defender (`windows-latest`), checks that no marker
string sits in plain text in any of them, and holds each to its size budget: `release-build.yml`'s
`av-gate` job the wheels, npm packages, sdist and crates, `engine-release-build.yml`'s the Release's
assets ([`docs/internal/publishing.md`](../docs/internal/publishing.md#the-antivirus-gate)). It
is off for every other pull request. Also `publish-dry-run`
([`publish-dry-run.yml`](workflows/publish-dry-run.yml): the registry placeholders) and `docs`.

**Python 3.10 to 3.13 and the full E2E set** (a release pull request and the nightly):
`python-matrix`, one job in `PR gate`'s needs, runs the suite on each of 3.10 to 3.13, one after
another (a uv environment each, on `native`'s abi3 wheel; each Python a log group, a failed one an
error annotation naming it), then the `full_set` E2E tests on 3.14.

**The nightly set** (`mode == 'nightly'`): one job, `nightly`, calls
[`nightly.yml`](workflows/nightly.yml), which holds every nightly job that needs nothing from the
run: `engine-test-os` (the workspace's tests on macOS and Windows, built there), `conformance`
(the cross-SDK suite on three OSes), `elastic-sweep`, `lsp-parity` (`cargo xtask lsp parity --corpus faults`: every fault kind
through `validate` and the language server, ~4 min of debug binary, so not in `build`), `clients`
(informational), `coverage`
([`coverage.yml`](workflows/coverage.yml)), `benchmarks` ([`bench.yml`](workflows/bench.yml), the
budgeted Rust benchmarks and the language server's cold start, native and WASI, held to
`tests/bench/lsp-cold-start.toml`), `oracle` ([`oracle.yml`](workflows/oracle.yml): the vendor-parser
oracles, with the Carbon Black Cloud tenant: `secrets: inherit` on both calls) and `fuzz`
([`engine-fuzz.yml`](workflows/engine-fuzz.yml): every target for ten minutes, the nightly's one
fuzz pass). ci.yml keeps the two nightly jobs that need this run's `release`: `cli-windows-smoke`
(the console launcher and Ctrl-C on the `wheels-windows-x64` wheel `release` built; nothing
compiles) and `engine-release-consumers` (the engine assets in vscode-extension), each
`always() &&` so an unrelated release failure does not skip it. With the release tier above,
every artifact is smoke-tested nightly (`release`'s `smoke` runs the npm local-registry test on
the real tarballs). `nightly-report` waits for all of them and opens or comments on the one open
issue labelled `nightly-failure` with the run's failing jobs, nested ones included (`Nightly /
...`). nightly.yml, coverage.yml, bench.yml, oracle.yml, engine-fuzz.yml and publish-dry-run.yml
have `workflow_call` and `workflow_dispatch` only: ci.yml runs them (ci.yml → nightly.yml →
coverage.yml is three levels, within GitHub's limit; the `nightly` job's permissions, `contents`
and `actions: read`, cap every job below it). The schedule runs `development`'s copy of the
workflows: test a change to the nightly with Run workflow on ci.yml (`scope: nightly`) on its
branch.

**No byte-for-byte comparison with the Python CLI** (the maintainer's decision, 2026-11-14): golden
compare and check, golden determinism, the corpora's diffs against the oracle, the MCP replay, the
payload, config, validate, lint, registry, schema and vocab diffs left every workflow, with
`golden.yml` and `golden-preview.yml`; the recordings, the replays and that tooling were then
deleted (#1139, #1142). The command line's behaviour is held by Rust-owned snapshots
([`tests/golden/README.md`](../tests/golden/README.md)); `cargo xtask corpus` runs by hand. The vendor-parser oracles (Kusto.Language,
Splunk, Elasticsearch, Lucene, Falco) are real products' parsers: they run nightly.

Every Rust job in `ci.yml` sets Rust up with one composite action,
[`actions/rust-setup`](actions/rust-setup/action.yml): the release `rust-toolchain.toml` pins
(`rustup toolchain install` with no name, never floating `stable`), then its `targets` with
`rustup target add` (that install drops `--target` and `--component` silently), its prebuilt
`tools` (taiki-e/install-action) and, given a `cache` family, the compiler cache restored (below). `changes` alone
uses the runner's stable cargo, for `cargo metadata --no-deps`. Only the fuzz jobs name a
toolchain, the dated nightly `fuzz/NIGHTLY` pins. The npm addons are stricter
(`build-packages.yml`): `scripts/build/install-rust.sh` installs the pinned release by name with
the minimal profile and names it in `RUSTUP_TOOLCHAIN`; the wheels' maturin-action installs
`rust-toolchain.toml`'s release (in the manylinux container on Linux) and sets it as the
directory's override, so rustup installs nothing mid-build either. Every job that runs cargo sets
`RUSTFLAGS=-Dwarnings` (the nightly fuzz build aside); the test jobs also set
`CARGO_PROFILE_DEV_DEBUG=line-tables-only` and `INSTA_UPDATE=no` (CI never writes a snapshot).

**Compiler caches** (#841, #1047): sccache (`RUSTC_WRAPPER`,
0.19.0) in `.sccache/`, kept by actions/cache under
`sccache-<family>-<hash of rust-toolchain.toml>-<ISO week>`, restored with the family and
toolchain as `restore-keys` (by `rust-setup`, whose step has the id `sccache`), saved by exactly
one job when the key missed: once a week. The save is
[`actions/sccache-save`](actions/sccache-save/action.yml) (the statistics, then the save), called
with `if: ${{ !cancelled() }}` and the job's policy in `save`, `job.status == 'success'` first: a
composite cannot see whether the job's steps passed; `rust-setup`'s `save` output is the base-branch
policy below. sccache is
content-addressed, so a copy a few days old still serves every crate that did not change; a key
on the sources or `Cargo.lock` saved every family on each merge and evicted what pull requests
restore. The families: `build` (the tests' build), `native` (the extension), `stubs` (the `stubs` job), `throughput` (the `throughput` job), `wiring` (the `wiring` job), `engine-check` (`engine-lint`) and `engine-variants` (`engine-lint-variants`), saved
from a push to each base branch and from Run workflow (a pull request reads its base branch's
caches and `development`'s), and from a pull request only when it restored no copy of the family
at all (`cache-matched-key` empty: its base has none yet, after a new family or a toolchain bump),
so its next push is warm; `wasm` (the `wasm` job's wasm32 compiles) under the same rule; `full-set-Linux` (`conformance` saves it, by the nightly; `node`,
`facade` and the nightly's Linux Rust jobs restore it); the release dry run's own
(`release-Linux-<arch>-<binary>`, one per binary, and `release-wasm`). **Linux only**: macOS and Windows build cold (their
caches crowded the Linux families out of the 10 GB GitHub keeps). **A pull request saves no
cache** but that bootstrap copy. The one rust-cache left: `fuzz` (engine-fuzz.yml, saved by one cell of the scheduled run), plus coverage.yml's and
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
passes). `tests/test_ci/test_workflows.py` fails when this list and the workflows differ. CodeQL is
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
- [`nightly.yml`](workflows/nightly.yml): the nightly set (above), which ci.yml's `nightly` job
  calls; Run workflow runs it alone (its `features` input is changes.py's, which ci.yml passes).
- [`engine-fuzz.yml`](workflows/engine-fuzz.yml) fuzzes every target (`seconds`, ten minutes by
  default) with the corpus it keeps, and uploads what crashed; in the nightly (nightly.yml calls
  it) and on demand, no schedule of its own.
- [`bench.yml`](workflows/bench.yml), in the nightly (nightly.yml calls it) and on demand (Run
  workflow on a branch measures a change): `cargo xtask bench` for the `rust` engine (the
  `opentide` binary, the language server, the workspace load; the `python` engine, the frozen
  oracle, is no longer measured: its baselines in `budgets.toml` stay) on `ubuntu-24.04`, a strace proof that
  `deploy --dry-run` and `generate docs` open no network connection, then `cargo xtask bench
  --check --require-reference` against `tests/bench/budgets.toml` and the `bench-<engine>`
  artifact of the last successful run on the comparison base, `BASE_BRANCH`
  (`integration/unified-core` until the Unified Core merges into development), on the same CPU
  (a command compared with nothing fails). The rules
  (10% over the base branch's last result or the oracle baseline of the runner's CPU, the absolute
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
  request (`tests/test_ci/test_workflows.py`).
- [`oracle.yml`](workflows/oracle.yml) checks the query parsers against Kusto.Language, Splunk,
  Elasticsearch, Lucene, Kibana and Falco (`OPENTIDE_ORACLE_REQUIRED`), the vendors' own parsers
  (not the Python oracle), in the nightly (nightly.yml calls it, with the Carbon Black Cloud tenant)
  and on demand: every reference on each run. Its network-heavy references keep it out of ci.yml. The pinned Elastic
  references (Lucene's jars from Maven Central, the EQL and kuery grammars) are cached under
  `oracle.py`'s pins and saved by the scheduled run; `oracle.py` checks each file's SHA-256, a
  restored one too.
- [`publish-dry-run.yml`](workflows/publish-dry-run.yml) (the registry placeholders rehearsed,
  nothing published): in a release pull request's checks and the nightly (ci.yml calls it), and on
  demand. The PyPI dist's shape is `release-build.yml`'s (`smoke_release.sh sdist`).
- [`release-build.yml`](workflows/release-build.yml): every artifact a release ships, built and
  smoke-tested once; ci.yml's `release` and publish.yml's `build` call it (above).
- [`av-gate.yml`](workflows/av-gate.yml): the antivirus gate (ClamAV, YARA, Microsoft Defender, the
  marker and size checks), a reusable workflow that `release-build.yml` and
  `engine-release-build.yml` call with `av-gate: true` from the release tier and the release train
  (its scripts are [`scripts/av/`](../scripts/av/)). It holds no token and uploads nothing to a scanner.
- Deleted (2026-11-14): `docs.yml` (now ci.yml's `docs` job), `stack-comment.yml`, `golden.yml`
  and `golden-preview.yml` (their `cargo xtask golden` commands were deleted too, #1142).
- [`codeql.yml`](workflows/codeql.yml) (below) and [`vocab-upstream.yml`](workflows/vocab-upstream.yml)
  (its own header).

Where each of language-server's workflow jobs went (or why it was dropped):
[`docs/engine/IMPORT.md`](../docs/engine/IMPORT.md#where-the-workflows-went).

## Test strength (UC-X.2, #844)

[`docs/internal/test-strength.md`](../docs/internal/test-strength.md) explains the three measures;
`tests/test_ci/test_workflows.py` holds their permissions and triggers.

- [`coverage.yml`](workflows/coverage.yml), in the nightly (nightly.yml calls it) and on demand: job **Rust coverage gates**. One cargo-llvm-cov build measured by the workspace's Rust tests and by the whole Python
  suite, which drives `opentide._native`; `cargo xtask coverage gate` checks each crate against
  `xtask/coverage.toml`. Read-only.
- The parity dashboard (`parity.yml`) was retired with the Python implementation (UC-6.2, #841): every command runs on Rust.

## Releases

**One release train** ([`publish.yml`](workflows/publish.yml), UC-5.5): merge the notes PR, then
Run workflow on `development` with no inputs. It checks (every crate built from its package, the
licence scan), builds (the wheels and npm packages of
[`build-packages.yml`](workflows/build-packages.yml), the sdist, the binaries and engine assets of
[`engine-release-build.yml`](workflows/engine-release-build.yml)), smoke-tests each artifact as a
user installs it, scans every artifact with the antivirus gate ([`av-gate.yml`](workflows/av-gate.yml)),
attests every artifact, tags `vX.Y.Z` with the GitHub Release, verifies the
published assets, and publishes to PyPI, crates.io and npm with trusted publishing, so a cloud
session can release. **Release candidates are internal**: `internal_candidate: N`, from
`integration/unified-core` or `development`, builds and smoke-tests everything the same way,
pushes the tag `vX.Y.Z-rc.N` and creates a **draft** GitHub pre-release with every binary, wheel,
sdist, crate and npm tarball (SHA256SUMS, PACKAGES-SHA256SUMS, the SBOMs); it publishes nothing to
PyPI, crates.io or npm and mints no OIDC token, so the maintainer tests a candidate before
anything reaches a package manager (`v1.0.0-rc.N` until the final 1.0.0). The public
`release_candidate` path (pre-releases on PyPI, crates.io and npm: the eleven npm packages at
`1.0.0-rc.N` under the dist-tag `next`, never `latest`) is enabled for 1.0.0-rc.N
(`public_candidates=true` in the guard), and `checkout_ref` resumes an `-rc` tag. For a release or
a public candidate the guard also checks, before anything is built, that every npm package already
exists on npm (the registry's JSON, no login: `docs/internal/publishing.md`, "The npm pre-flight
check"; trusted-publisher configuration cannot be read without one and is not checked), and refuses a
resume of a candidate before `v1.0.0-rc.3`. The `npm` job never moves `next` backwards, checks every
package's dist-tags, and names the packages a maintainer must move with `npm dist-tag add` after a
final release (trusted publishing covers `npm publish` only). The
GitHub Release carries `opentide-wasm32-wasip1.wasm`, the command line as one WASI module for the VS
Code extension (built by `engine-release-build.yml`'s `wasm` job with the release's
`OPENTIDE_BUILD_VERSION`, run under wasmtime before it is an asset, a *product* asset for the licence scan). `dry_run` publishes nothing;
`checkout_ref: vX.Y.Z` resumes a release. Steps:
[release-management](../.agents/skills/release-management/SKILL.md); the registries' settings and
the decisions (no musl, the free-threaded sdist): [`docs/internal/publishing.md`](../docs/internal/publishing.md#the-release-train).
`tests/test_ci/test_workflows.py` fails if any workflow can run on a `v*` tag, or if anything
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
                               #   coverage gate, E2E, GitLab CI lint, and WebAssembly and fuzz
                               #   smoke when their tools are installed: before push
```

`--full` says which optional step it skipped and what to install for it. `FUZZ_SMOKE_SECONDS`
(default 60; the nightly's engine-fuzz.yml runs 600) sets the fuzz smoke's time per target; `0` skips it.

## CodeQL, Dependabot

**CodeQL:** Python, Rust and Actions via [`workflows/codeql.yml`](workflows/codeql.yml)
(`/language:python`, `/language:rust`, `/language:actions`, `security-extended`; Rust with
`build-mode: none`, no cargo build): each language on a pull request that changes its files
(Python sources; `crates/`, `bindings/`, `xtask/`, `vendor/`, `fuzz/`, `Cargo.toml`, `Cargo.lock`,
`rust-toolchain.toml`, `.cargo/`; the workflows and actions; every language when `codeql.yml` changes), every language on every push to a base branch and nightly; not a required check. Code Quality may
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
- actionlint (in `lint`) checks the workflows' syntax, expressions and shell. `tests/test_ci/`
  holds only what it cannot, in about 25 tests (the maintainer's rule: no test restates a
  workflow's YAML): `test_workflows.py` (every job feeds `PR gate`, no workflow runs a Python
  oracle comparison, pinned actions, least-privilege permissions, concurrency, only the release
  train publishes, OIDC in publish.yml's publish jobs only, the internal channel reaches no
  registry) and `test_changes.py` (scripts/ci/changes.py). `lint` runs them.
