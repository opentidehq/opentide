# .github — Agent Guide: CI, CodeQL, releases, Dependabot

What runs on a pull request and a push, and how to reproduce it locally. The root
[`AGENTS.md`](../AGENTS.md) is the map; the [steward](../.agents/skills/steward/SKILL.md) skill
drives a PR to green and [github-actions-templates](../.agents/skills/github-actions-templates/SKILL.md)
covers editing workflows. UC-0.3 ([#801](https://github.com/opentidehq/opentide/issues/801)) is
bringing these workflows together; until it lands, the layout below is the truth.

## CI (`workflows/ci.yml`)

Jobs run in parallel; stale runs are cancelled on new pushes. Every pull request runs it,
whatever its base: a stacked PR targets the branch below it, not `development`.

| Job | What it checks |
|-----|----------------|
| `lint` | ruff, ty, `uv build` and `twine check`; the vocabulary drift gate and the model field descriptions (below) when their files change |
| `engine` | The Cargo workspace: rustfmt, clippy `-D warnings`, `cargo xtask check-layers`, `cargo test --workspace` (doctests included), the engine's invariant scripts (`scripts/engine/check-io-free.sh`, `check-names.sh`, `validate-skills.sh`, `generate-highlights --check`), the bundled Tide catalog test and the engine release script's tests |
| `engine-wasm` | `scripts/engine/build-wasm.sh` (both WebAssembly artifacts, and `clippy` for the code only wasm32 compiles), the npm packages and the TypeScript client against the native, worker and WASI servers |
| `test` | The Python matrix, **3.10–3.14** |
| `cli-e2e`, `cli-windows-smoke`, `gitlab-ci-lint` | The sharded E2E suite, a Windows smoke run, the generated GitLab pipelines; none waits for `test` |

The Rust jobs of `ci.yml`, `engine-ci.yml`, `oracle.yml` and the parked `release.yml` (below)
install the one release `rust-toolchain.toml` pins (`rustup toolchain install` with no name),
never floating `stable`: cargo in a checkout runs that release whatever else is installed
(`tests/test_ci/test_rust_toolchain.py`). That install takes the file's components and drops
`--target` and `--component` without an error, so a job adds the targets it builds with
`rustup target add`, which with no toolchain named adds them to the pinned release.
`rust-toolchain.toml` says how to move the pin (`engine-fuzz.yml` runs nightly, by name). Every
Python job builds the engine through `uv sync`, with a Rust cache. The `engine` job sets
`RUSTFLAGS=-Dwarnings` (a warning fails the build), `CARGO_PROFILE_DEV_DEBUG=line-tables-only`
and `INSTA_UPDATE=no` (a snapshot that differs fails; CI never writes one). Its Rust cache is
shared with `engine-ci.yml`'s `clients` and `elastic-sweep`, which read it and save none
(`tests/test_ci/test_rust_caches.py`): their `CARGO*`/`RUST*` environment must match the job's.

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

## The engine's other workflows

- [`engine-ci.yml`](workflows/engine-ci.yml), on every pull request and push: the language
  server's tests on Windows (`cargo nextest run -p opentide-lsp -p opentide-core --profile ci`),
  the crates packaged and licence-scanned as crates.io builds them, every grammar regenerated
  against its vendored `parser.c`, the TextMate grammars, the Elastic detection-rules sweep, and
  two informational jobs (real LSP clients, benchmarks).
- [`engine-fuzz.yml`](workflows/engine-fuzz.yml) fuzzes each engine nightly.
- [`oracle.yml`](workflows/oracle.yml) checks the query parsers against Kusto.Language,
  Splunk, Elasticsearch, Lucene, Kibana and Falco on every push to `development`, on a pull
  request that changes `crates/`, `grammars/`, `Cargo.lock`, the query catalogs or the oracles,
  weekly (with the Carbon Black Cloud tenant) and on demand.
- language-server's release workflow waits in `engine-workflows/`, which GitHub does not run,
  for UC-0.3. Its jobs install the pinned release as above, which needs rustup on the runner: UC-0.3
  checks each image of its `native` matrix when it restores the workflow (`publish-pypi.yml`
  installs Rust on `windows-11-arm`, whose image may lack it).

## Test strength (UC-X.2, #844)

[`docs/internal/test-strength.md`](../docs/internal/test-strength.md) explains the three measures;
`tests/test_ci/test_test_strength_workflows.py` holds their permissions and triggers.

- [`coverage.yml`](workflows/coverage.yml), on every pull request and push: job **Rust coverage
  gates**. One cargo-llvm-cov build measured by the workspace's Rust tests and by the whole Python
  suite, which drives `opentide._native`; `cargo xtask coverage gate` checks each crate against
  `xtask/coverage.toml`. Read-only.
- [`mutants.yml`](workflows/mutants.yml), weekly and on demand: cargo-mutants on the crates of
  `xtask/mutants.toml` in eight shards, a report against `xtask/mutants-baseline.toml`, and on the
  schedule only a job with `issues: write` (no checkout, no repository code) that opens or updates
  one issue per crate above its threshold.
- [`parity.yml`](workflows/parity.yml), on every pull request and push: `cargo xtask parity
  dashboard` into the job summary; on a push to `development` or `integration/unified-core` only, a job with `contents: write`
  (no repository code, never forces) commits `docs/internal/parity.md` when it changed.

The nextest profiles CI and agents use are in [`.config/nextest.toml`](../.config/nextest.toml):
`ci` (everything, no retries, no fail-fast, JUnit at `target/nextest/ci/junit.xml`) and `fast`
(the agent loop).

## Local parity

```bash
scripts/ci-local.sh --quick    # ruff, ty, cargo fmt + clippy, crate layers, engine checks, uv build
scripts/ci-local.sh            # lint + cargo test + pytest
scripts/ci-local.sh --full     # + coverage gate (pyproject.toml), E2E, GitLab CI lint: before push
```

## CodeQL, releases, Dependabot, stack comments

**CodeQL:** Python and Actions via [`workflows/codeql.yml`](workflows/codeql.yml)
(`/language:python` + `/language:actions`); Code Quality may also run dynamic Python on push.
Local Python: `scripts/codeql-local.sh`. Skill: [codeql](../.agents/skills/codeql/SKILL.md).

**Release:** merge the notes PR, then Run workflow on
[`publish-pypi.yml`](workflows/publish-pypi.yml) on `development` with no inputs: it tags the
changelog's version, creates the GitHub Release and publishes, so a cloud session can release.
Steps: [release-management](../.agents/skills/release-management/SKILL.md). The engine crates'
release is parked: [engine-release](../.agents/skills/engine-release/SKILL.md).

**Dependabot:** weekly PRs for `uv` (test toolchain grouped), `github-actions` (SHA pins) and
`pre-commit`. Merge procedure: [uv skill](../.agents/skills/uv/SKILL.md#dependency-upgrades-and-dependabot).

**Stack comments:** [`workflows/stack-comment.yml`](workflows/stack-comment.yml) posts merge
order **only** on stacked PRs (non-trunk base or child PR exists). Standalone PRs to
`development` are skipped.

## Rules for workflow changes

- Actions are pinned by commit SHA with the version in a comment; Dependabot bumps them.
- Never interpolate `${{ github.event.* }}` into `run:`; pass it through `env:`.
- A step that must fail when its tool is missing must not sit in an `if` that reads "missing"
  as "no match" (the drift gate once used `rg`, which runners lack).
- The workflow contracts have tests under `tests/test_ci/` (`test_own_ci_workflow.py`,
  `test_rust_caches.py`, `test_workflow_contexts.py`, ...): run them after a change.
