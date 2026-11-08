# .github — Agent Guide: CI, CodeQL, releases, Dependabot

What runs on a pull request and a push, and how to reproduce it locally. The root
[`AGENTS.md`](../AGENTS.md) is the map; the [steward](../.agents/skills/steward/SKILL.md) skill
drives a PR to green and [github-actions-templates](../.agents/skills/github-actions-templates/SKILL.md)
covers editing workflows.

## CI (`workflows/ci.yml`): one workflow for the repository

Every pull request runs it, whatever its base (a stacked PR targets the branch below it), and so
does every push to `development`. Jobs run in parallel; a new push cancels the stale run.

| Job | What it checks |
|-----|----------------|
| `lint` | ruff, ty, `uv build` and `twine check`; the vocabulary drift gate and the model field descriptions (below) when their files change |
| `engine` | rustfmt, clippy `-D warnings`, `cargo xtask check-layers`, `cargo doc --no-deps --workspace` with `RUSTDOCFLAGS=-D warnings`, the engine's invariant scripts (`check-io-free.sh`, `check-names.sh`, `validate-skills.sh`, `generate-highlights --check`), the bundled Tide catalog test and the engine release script's tests |
| `engine-test` | `cargo nextest run --workspace --profile ci` on Linux, macOS and Windows (after `uv sync`: one test runs the Pydantic models); the doctests (`cargo test --doc`) on Linux |
| `engine-wasm` | `scripts/engine/build-wasm.sh` (both WebAssembly artifacts, and `clippy` for the code only wasm32 compiles), the npm packages (`check-npm-packs.mjs`) and the TypeScript client against the native, worker and WASI servers |
| `engine-package` | Every engine crate packaged as crates.io builds it, and `license-scan.sh` over the packages (no oracle reference ships) |
| `grammars`, `textmate` | Every vendored `parser.c` is what tree-sitter-cli 0.25.10 generates (`check-grammars.sh`); the TextMate grammars as VS Code reads them |
| `elastic-sweep` | Every public Elastic detection rule (a pinned commit) passes the engine |
| `fuzz-smoke` | Each fuzz target of `fuzz/` for 60 s from its seeds and saved regressions (nightly, three targets per runner) |
| `engine-release-dry-run` | The engine release's own asset jobs ([`engine-release-build.yml`](workflows/engine-release-build.yml)) for the workspace version: every asset, SHA256SUMS, and `release.py check-assets` (language-server v0.11.0's names with the version substituted). No tag, attestation, release or publish; `contents: read` |
| `engine-release-consumers` | opentidehq/vscode-extension's own grammar and engine scripts (a pinned commit) accept the dry run's assets as this repository's release (`scripts/engine/check-vscode-extension.mjs`) |
| `test` | The Python matrix, **3.10–3.14**, coverage gate on 3.14 |
| `cli-e2e`, `cli-windows-smoke`, `gitlab-ci-lint` | The sharded E2E suite, a Windows smoke run, the generated GitLab pipelines; none waits for `test` |
| `clients`, `bench` | Informational (`continue-on-error`): real LSP clients (pytest-lsp, Neovim) and `cargo bench`; never required |

Every Rust job installs the one release `rust-toolchain.toml` pins (`rustup toolchain install`
with no name), never floating `stable`: cargo in a checkout runs that release whatever else is
installed (`tests/test_ci/test_rust_toolchain.py`). That install takes the file's components and
drops `--target` and `--component` without an error, so a job adds the targets it builds with
`rustup target add`, which with no toolchain named adds them to the pinned release. Only the fuzz jobs
name a toolchain, nightly, which cargo-fuzz needs. The Rust jobs set `RUSTFLAGS=-Dwarnings`,
`CARGO_PROFILE_DEV_DEBUG=line-tables-only` and `INSTA_UPDATE=no` (a snapshot that differs fails;
CI never writes one). Every Python job builds the engine through `uv sync`.

**Rust caches, one strategy** (`tests/test_ci/test_rust_caches.py`): every
`Swatinem/rust-cache` step in ci.yml names its cache with `shared-key` (and `key` where one job
builds a tree per OS or per target), and each name has exactly one job that saves it; the others
read it with `save-if: false` and repeat its runner and `CARGO*`/`RUST*` environment, which
rust-cache hashes into the key. `engine-dev` is `engine-test`'s debug tree per OS (`clients` and
`elastic-sweep` read the Linux one); `python-engine` is the binding `uv sync` builds (abi3, one
build for every Python), saved by `test`'s 3.14 cell; `engine-check`, `engine-wasm`,
`engine-package`, `engine-bench`, `fuzz` and `python-engine-windows` belong to one job each;
`engine-release` keys the dry run per target. A release restores no cache: the asset build
restores one only under `inputs.dry-run`.

**Coverage:** gate on Python **3.14** only (`COVERAGE_PYTHON` in ci.yml). Cobertura upload to
GitHub Code Quality is best-effort (`fail-on-error: false` if Code Quality is disabled). HTML
report uploaded as artifact.

**Vocabulary drift gate:** when bundled vocab TOML files, schema pins
(`src/opentide/data/pins/`), `data/specifications.lock.json` or the sync script change, CI also
checks out `opentidehq/specifications` (`main`) and runs
`uv run python scripts/build/sync_vocabularies.py --check` against it
(`OPENTIDE_SPECIFICATIONS_ROOT`).

**Bundled Tide catalog:** the engine compiles in a Tide catalog (`data/catalogs/tide/`, and the
key lists of `highlights/queries/tide/highlights.scm`) for editors that run `opentide-lsp` on its
own. `scripts/engine/sync_opentide_schemas.py` generates it from `src/opentide`, and
`tests/test_generation/test_bundled_tide_catalog.py` (the `engine` job, `ci-local.sh`) fails
when the committed one differs, until UC-1.8 generates it in Rust.

**Budget:** a pull request's CI, first job start to last job end, stays under 15 minutes on a warm
cache (the second push of a branch). The long poles are the Python 3.10 cell, the release dry
run's native builds and nextest on Windows; split what grows past it.

## Required checks

Branch protection on `development` requires every check below: each gating job of ci.yml (every
matrix cell; the reusable workflow's jobs as `Engine release (dry run) / <job>`) and CodeQL's
two. `tests/test_ci/test_one_ci.py` fails when this list and the workflows differ. The
informational jobs and the path-filtered workflows (`oracle.yml`, `docs.yml`) are not required:
a check that does not run would block the merge.

<!-- required-checks -->
```text
Lint
Engine lint (fmt, clippy, doc, layers)
Engine tests (ubuntu-latest)
Engine tests (macos-latest)
Engine tests (windows-latest)
Engine WebAssembly and npm packages
Engine crates package and licence scan
Grammars regenerate
TextMate grammars (vscode-textmate)
Elastic detection-rules sweep
Fuzz smoke (kql spl esql)
Fuzz smoke (eql kuery lucene)
Fuzz smoke (falco tide protocol)
Engine release (dry run) / Release tag
Engine release (dry run) / opentide-lsp x86_64-unknown-linux-gnu
Engine release (dry run) / opentide-lsp x86_64-unknown-linux-musl
Engine release (dry run) / opentide-lsp aarch64-unknown-linux-gnu
Engine release (dry run) / opentide-lsp aarch64-unknown-linux-musl
Engine release (dry run) / opentide-lsp aarch64-apple-darwin
Engine release (dry run) / opentide-lsp x86_64-apple-darwin
Engine release (dry run) / opentide-lsp x86_64-pc-windows-msvc
Engine release (dry run) / opentide-lsp aarch64-pc-windows-msvc
Engine release (dry run) / WebAssembly builds
Engine release (dry run) / Highlights zip
Engine release (dry run) / Licences and notices
Engine release (dry run) / Release assets
Engine release assets in vscode-extension
Test (3.10)
Test (3.11)
Test (3.12)
Test (3.13)
Test (3.14)
E2E (3.14, shard 1/4)
E2E (3.14, shard 2/4)
E2E (3.14, shard 3/4)
E2E (3.14, shard 4/4)
GitLab CI lint
CLI Windows smoke
Analyze (python)
Analyze (actions)
```

To set it (a repository admin): **Settings → Rules → Rulesets → New ruleset → New branch
ruleset**; name it `development`, Enforcement status **Active**; **Target branches → Add target →
Include by pattern** `development`; tick **Require status checks to pass** (and **Require
branches to be up to date before merging** if wanted), then **Add checks** and add each name
above (each appears once it has run on a pull request; choose the GitHub Actions source);
**Create**. With classic branch protection instead: **Settings → Branches → Add classic branch
protection rule** (or edit the `development` rule) → Branch name pattern `development` → tick
**Require status checks to pass before merging** → search for and add each name → **Save
changes**. When a job is renamed or a matrix changes, update the list here and in the rule
together.

## The other workflows

- [`engine-release.yml`](workflows/engine-release.yml): the engine's release (below).
- [`engine-fuzz.yml`](workflows/engine-fuzz.yml) fuzzes each target for five minutes a night with
  the corpus it keeps; a schedule of its own, so not part of ci.yml.
- [`oracle.yml`](workflows/oracle.yml) checks the query parsers against Kusto.Language, Splunk,
  Elasticsearch, Lucene, Kibana and Falco (`OPENTIDE_ORACLE_REQUIRED`) on every push to
  `development`, on an `engine-v*` tag, on a pull request that changes `crates/`, `grammars/`,
  `Cargo.lock`, the query catalogs or the oracles, weekly (with the Carbon Black Cloud tenant) and
  on demand. Its own triggers and network-heavy references keep it out of ci.yml.
- [`codeql.yml`](workflows/codeql.yml), [`docs.yml`](workflows/docs.yml),
  [`publish-pypi.yml`](workflows/publish-pypi.yml), [`stack-comment.yml`](workflows/stack-comment.yml),
  [`vocab-upstream.yml`](workflows/vocab-upstream.yml): below and in their own headers.

### Where language-server's workflows went

| language-server | Job | Here |
| --- | --- | --- |
| `ci.yml` | `test` | ci.yml `engine` (rustfmt, clippy, layers, rustdoc, invariants, schemas test), `engine-test` (tests, doctests), `engine-wasm` (npm packs, lsp-client stdio), `textmate` |
| `ci.yml` | `windows` | ci.yml `engine-test` (windows-latest), now the whole workspace |
| `ci.yml` | `clients`, `bench` | ci.yml `clients`, `bench`, still informational |
| `ci.yml` | `package` | ci.yml `engine-package` (packaging and licence scan); its `release.py` tests run in `engine` |
| `ci.yml` | `grammars` | ci.yml `grammars` |
| `ci.yml` | `wasm` | ci.yml `engine-wasm` |
| `ci.yml` | `elastic-sweep` | ci.yml `elastic-sweep` |
| `fuzz.yml` | `fuzz` | `engine-fuzz.yml` (nightly, five minutes), and ci.yml `fuzz-smoke` (60 s per target, every PR) |
| `oracle.yml` | every job | `oracle.yml`, its tag trigger `engine-v*` instead of `v*.*.*` |
| `release.yml` | every job | `engine-release.yml` (`git mv`); `native`, `wasm`, `highlights` and the licences of `assets` moved to `engine-release-build.yml`, which ci.yml also runs as a dry run |
| `backfill-releases.yml` | `backfill` | dropped: a one-off for language-server's tags before 0.5 |
| `opentide-canary.yml` | `canary` | dropped: `tests/test_generation/test_bundled_tide_catalog.py` checks the bundled Tide catalog against this checkout's models |

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
