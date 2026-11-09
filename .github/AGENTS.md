# .github — Agent Guide: CI, CodeQL, releases, Dependabot

What runs on a pull request and a push, and how to reproduce it locally. The root
[`AGENTS.md`](../AGENTS.md) is the map; the [steward](../.agents/skills/steward/SKILL.md) skill
drives a PR to green and [github-actions-templates](../.agents/skills/github-actions-templates/SKILL.md)
covers editing workflows.

## CI (`workflows/ci.yml`): one workflow for the repository

Every pull request runs it, whatever its base (a stacked PR targets the branch below it), and so
does every push to `development` and to `integration/unified-core` (where the Unified Core PRs
merge first; CodeQL and the oracles run there too). Jobs run in parallel; a new push cancels the stale run.

| Job | What it checks |
|-----|----------------|
| `lint` | ruff, ty, `uv build` and `twine check`; the vocabulary drift gate and the model field descriptions (below) when their files change |
| `engine` | rustfmt, clippy `-D warnings`, `cargo xtask check-layers`, `cargo doc --no-deps --workspace` with `RUSTDOCFLAGS=-D warnings`, the engine's invariant scripts (`check-io-free.sh`, `check-names.sh`, `validate-skills.sh`, `generate-highlights --check`), the bundled Tide catalog test and the engine release script's tests |
| `engine-test` | `cargo nextest run --workspace --profile ci` on Linux, macOS and Windows (after `uv sync`: one test runs the Pydantic models); the doctests (`cargo test --doc`) on Linux |
| `engine-wasm` | `scripts/engine/build-wasm.sh` (both WebAssembly artifacts, and `clippy` for the code only wasm32 compiles), the npm packages (`check-npm-packs.mjs`) and the TypeScript client against the native, worker and WASI servers |
| `engine-package` | Every engine crate packaged as crates.io builds it, and `license-scan.sh` over the packages (no oracle reference ships) |
| `grammars`, `textmate` | Every vendored `parser.c` is what tree-sitter-cli 0.25.10 generates (`check-grammars.sh`); the TextMate grammars as VS Code reads them |
| `elastic-sweep` | Every public Elastic detection rule (a pinned commit) passes the engine |
| `fuzz-smoke` | Each fuzz target of `fuzz/` for 60 s from its seeds and saved regressions (the dated nightly `fuzz/NIGHTLY` pins, up to three targets per runner; cargo-fuzz pinned) |
| `deny` | `cargo deny check` against [`deny.toml`](../deny.toml) (licences, RustSec advisories, duplicate versions, OpenSSL, sources) for the workspace and the `publishing/` placeholder crate, and advisories, bans and sources for `fuzz/`; cargo-deny 0.20.2, prebuilt and checksum-checked ([`docs/internal/supply-chain.md`](../docs/internal/supply-chain.md)) |
| `engine-release-dry-run` | The engine release's own asset jobs ([`engine-release-build.yml`](workflows/engine-release-build.yml)) for the workspace version: every asset, the CycloneDX SBOMs (`scripts/engine/sbom.py`, schema-checked), SHA256SUMS, and `release.py check-assets` (language-server v0.11.0's names with the version substituted, plus the SBOMs). No tag, attestation, release or publish; `contents: read` |
| `engine-release-consumers` | opentidehq/vscode-extension's own grammar and engine scripts (a pinned commit) accept the dry run's assets as this repository's release (`scripts/engine/check-vscode-extension.mjs`) |
| `test` | The Python matrix, **3.10–3.14**, coverage gate on 3.14 |
| `cli-e2e`, `cli-windows-smoke`, `gitlab-ci-lint` | The sharded E2E suite, a Windows smoke run, the generated GitLab pipelines; none waits for `test` |
| `corpus` | The corpora of UC-0.6 against opentide 0.23.0 from PyPI, hash-pinned in its own venv: the heavy workspace has no finding, `cargo xtask corpus faults --check` (every fault kind reports exactly its codes), the code inventory and `COVERAGE.md` are current ([`tests/corpora/README.md`](../tests/corpora/README.md)) |
| `clients`, `bench` | Informational (`continue-on-error`): real LSP clients (pytest-lsp, Neovim) and `cargo bench`; never required |

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
(`main`) and runs `scripts/build/sync_vocabularies.py --check` against it.

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
Fuzz smoke (config framing)
Supply chain (cargo deny)
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
Engine release (dry run) / SBOMs
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
Corpus (generator, faults, coverage) against opentide 0.23.0
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
- [`engine-fuzz.yml`](workflows/engine-fuzz.yml) fuzzes every target for ten minutes a night with
  the corpus it keeps, and uploads what crashed; a schedule of its own, so not part of ci.yml.
- [`rust-audit.yml`](workflows/rust-audit.yml) runs `cargo audit` on every Rust lock file
  (`git ls-files`) every day, with deny.toml's exceptions, and opens or comments on one issue when it finds an advisory.
  Its issue job is the only job in any workflow with `issues: write`, and it never runs on a pull
  request (`tests/test_ci/test_supply_chain.py`).
- [`oracle.yml`](workflows/oracle.yml) checks the query parsers against Kusto.Language, Splunk,
  Elasticsearch, Lucene, Kibana and Falco (`OPENTIDE_ORACLE_REQUIRED`) on every push to
  `development`, on an `engine-v*` tag, on a pull request that changes `crates/`, `grammars/`,
  `Cargo.lock`, the query catalogs or the oracles, weekly (with the Carbon Black Cloud tenant) and
  on demand. Its own triggers and network-heavy references keep it out of ci.yml.
- [`golden.yml`](workflows/golden.yml) runs `cargo xtask golden check --engine python` and
  `golden record --check-determinism` against the committed recordings of the frozen Python CLI
  (`tests/golden/README.md`): on a pull request that touches `tests/golden/`, `tests/corpora/`,
  the tide corpus, `xtask/`, `.cargo/`, `Cargo.*` or `.gitattributes`, on every push to
  `development`, weekly and on demand. Path-filtered, so not required; whether it becomes required
  is the maintainer's call.
- [`codeql.yml`](workflows/codeql.yml), [`docs.yml`](workflows/docs.yml),
  [`publish-pypi.yml`](workflows/publish-pypi.yml), [`stack-comment.yml`](workflows/stack-comment.yml),
  [`vocab-upstream.yml`](workflows/vocab-upstream.yml): below and in their own headers.

Where each of language-server's workflow jobs went (or why it was dropped):
[`docs/engine/IMPORT.md`](../docs/engine/IMPORT.md#where-the-workflows-went).

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
