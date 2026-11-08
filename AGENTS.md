# opentide — Agent Guide

**opentide** (`opentide`) — spec-driven development for agentic detection engineering. A versioned Python package on PyPI for detection-as-code: validate, index, generate schemas, deploy, and document rules across nine security platforms.

**Entry point:** this file, then a domain skill from [`.agents/skills/`](.agents/skills/) when the task matches.

**Repository:** [opentidehq/opentide](https://github.com/opentidehq/opentide). Trunk: `development`.

## Skills — when to read which

| Task | Skill |
|------|-------|
| Writing or reviewing any change; definition of done | [`.agents/skills/review-checklist/SKILL.md`](.agents/skills/review-checklist/SKILL.md) |
| Driving a PR to green: CI failures, review threads, merge state | [`.agents/skills/steward/SKILL.md`](.agents/skills/steward/SKILL.md) |
| Dependencies, Dependabot, `uv run`, pre-commit, local CI | [`.agents/skills/uv/SKILL.md`](.agents/skills/uv/SKILL.md) |
| Ruff lint / format failures | [`.agents/skills/ruff/SKILL.md`](.agents/skills/ruff/SKILL.md) |
| ty type-check failures, annotations | [`.agents/skills/python-typing/SKILL.md`](.agents/skills/python-typing/SKILL.md) |
| CodeQL alerts or security workflows | [`.agents/skills/codeql/SKILL.md`](.agents/skills/codeql/SKILL.md) |
| pytest fixtures, mocks, test design | [`.agents/skills/python-testing-patterns/SKILL.md`](.agents/skills/python-testing-patterns/SKILL.md) |
| Coverage gaps, `--cov-fail-under` | [`.agents/skills/pytest-coverage/SKILL.md`](.agents/skills/pytest-coverage/SKILL.md) |
| GitHub Actions workflows | [`.agents/skills/github-actions-templates/SKILL.md`](.agents/skills/github-actions-templates/SKILL.md) |
| CLI E2E tests, tide_corpus, deploy payloads | [`.agents/skills/cli-e2e-testing/SKILL.md`](.agents/skills/cli-e2e-testing/SKILL.md) |
| MCP server tools, resources, stdio | [`.agents/skills/mcp-server/SKILL.md`](.agents/skills/mcp-server/SKILL.md) |
| Documentation pages, Fumadocs structure, doc/code sync | [`.agents/skills/docs-maintenance/SKILL.md`](.agents/skills/docs-maintenance/SKILL.md) |
| Changelog entries and release notes: summary, Upgrade, Breaking, categories | [`.agents/skills/release-notes/SKILL.md`](.agents/skills/release-notes/SKILL.md) |
| PyPI release, `v*` tag, install pins | [`.agents/skills/release-management/SKILL.md`](.agents/skills/release-management/SKILL.md) |
| The engine's Rust crates, `Cargo.toml`, `Cargo.lock` | [`.agents/skills/rust-engine/SKILL.md`](.agents/skills/rust-engine/SKILL.md) |
| Grammars, `crates/opentide-syntax`, highlight queries | [`.agents/skills/tree-sitter/SKILL.md`](.agents/skills/tree-sitter/SKILL.md) |
| The language server host (`crates/opentide-lsp`), `editors/` | [`.agents/skills/lsp-host/SKILL.md`](.agents/skills/lsp-host/SKILL.md) |
| WebAssembly (`crates/opentide-wasm`), npm `packages/` | [`.agents/skills/wasm-hosts/SKILL.md`](.agents/skills/wasm-hosts/SKILL.md) |
| `data/catalogs/`, HighlightSpec, conformance corpora, the vendor-parser oracles | [`.agents/skills/catalogs/SKILL.md`](.agents/skills/catalogs/SKILL.md) |
| A new query language in the engine | [`.agents/skills/add-language/SKILL.md`](.agents/skills/add-language/SKILL.md) |
| `crates/CHANGELOG.md`, the engine crates' release notes | [`.agents/skills/engine-release-notes/SKILL.md`](.agents/skills/engine-release-notes/SKILL.md) |
| Releasing the engine crates (parked until UC-0.3) | [`.agents/skills/engine-release/SKILL.md`](.agents/skills/engine-release/SKILL.md) |

The engine's skills (the last eight rows) came from opentidehq/language-server; their own index,
with the engine's hard rules, is [`crates/AGENTS.md`](crates/AGENTS.md): read it before changing
`crates/`, `grammars/`, `highlights/`, `data/catalogs/`, `editors/`, `packages/`, `fuzz/` or
`scripts/engine/`. Claude Code discovers these through `.claude/skills` (a symlink to
`.agents/skills`); cloud sessions run `.claude/hooks/session-start.sh`, which syncs the dev
environment.

## Ground rules

| Rule | Detail |
|------|--------|
| VCS | git, one branch per change, cut from `origin/development` |
| PRs | `gh pr create --base development`; a stacked PR targets the branch below it |
| Trunk | `development` |
| Scope | One concern per change / PR |
| Commits | Conventional Commits (`feat`, `fix`, `refactor`, `docs`, `chore`, `test`, `ci`) |

Branch naming: `<type>/<short-slug>` (e.g. `feat/sentinel-query-cache`).

Never push to `development` directly, force-push a branch someone else is working on, or rewrite history that is already on `origin`.

## Daily workflow

```bash
uv sync --group dev
uv run pre-commit install --install-hooks   # once per clone

git fetch origin
git switch -c feat/slug origin/development
# … edit files …
git add <paths>
git commit -m "feat(scope): …"
scripts/ci-local.sh --full
git push -u origin feat/slug                  # triggers pre-push hooks
gh pr create --base development --fill
```

| Step | Command |
|------|---------|
| Status | `git status`, `git log --oneline origin/development..` |
| Update from trunk | `git fetch origin && git rebase origin/development` (or merge, once the branch is shared) |
| Stacked PR | branch from the PR below, then `gh pr create --base <that-branch>` |
| After merge | `git switch development && git pull` → `git branch -d feat/slug` |

## CI, coverage, CodeQL, stack comments

**CI** (`.github/workflows/ci.yml`): lint (ruff + ty, `uv build` and `twine check`), `engine` (the Cargo workspace: rustfmt, clippy `-D warnings`, `cargo test`, the engine's invariant scripts and the bundled Tide catalog test), `engine-wasm` (`scripts/engine/build-wasm.sh`, the npm packages and the TypeScript client) and the test matrix Python **3.10–3.14**, in parallel; stale runs cancelled on new pushes. Every Python job builds the engine through `uv sync`, with a Rust cache. The engine's other gates, imported from language-server, run in [`engine-ci.yml`](.github/workflows/engine-ci.yml) on every pull request and push: the language server's tests on Windows, the crates packaged and licence-scanned as crates.io builds them, every grammar regenerated against its vendored `parser.c`, the TextMate grammars, the Elastic detection-rules sweep, and two informational jobs (real LSP clients, benchmarks). [`engine-fuzz.yml`](.github/workflows/engine-fuzz.yml) fuzzes each engine nightly. [`oracle.yml`](.github/workflows/oracle.yml) checks the query parsers against Kusto.Language, Splunk, Elasticsearch, Lucene, Kibana and Falco on every push to `development`, on a pull request that changes `crates/`, `grammars/`, `Cargo.lock`, the query catalogs or the oracles, weekly (with the Carbon Black Cloud tenant) and on demand. language-server's release workflow waits in `.github/engine-workflows/`, which GitHub does not run, for UC-0.3.

**Local parity:**

```bash
scripts/ci-local.sh --quick    # ruff, ty, cargo fmt + clippy, engine checks, uv build
scripts/ci-local.sh              # lint + pytest
scripts/ci-local.sh --full       # + coverage gate (pyproject.toml) — use before push
```

**Coverage:** gate on Python **3.14** only (`COVERAGE_PYTHON` in ci.yml). Cobertura upload to GitHub Code Quality is best-effort (`fail-on-error: false` if Code Quality is disabled). HTML report uploaded as artifact.

**Vocabulary drift gate:** when bundled vocab TOML files, schema pins (`src/opentide/data/pins/`), `data/specifications.lock.json` or the sync script change, CI also checks out `opentidehq/specifications` (`main`) and runs `uv run python scripts/build/sync_vocabularies.py --check` against it (`OPENTIDE_SPECIFICATIONS_ROOT`).

**Bundled Tide catalog:** the engine compiles in a Tide catalog (`data/catalogs/tide/`, and the key lists of `highlights/queries/tide/highlights.scm`) for editors that run `opentide-lsp` on its own. `scripts/engine/sync_opentide_schemas.py` generates it from `src/opentide`, and `tests/test_generation/test_bundled_tide_catalog.py` (the `engine` job, `ci-local.sh`) fails when the committed one differs, until UC-1.8 generates it in Rust.

**CodeQL:** Python and Actions via [`.github/workflows/codeql.yml`](.github/workflows/codeql.yml) (`/language:python` + `/language:actions`); Code Quality may also run dynamic Python on push. Local Python: `scripts/codeql-local.sh`.

**Release:** merge the notes PR, then Run workflow on [`publish-pypi.yml`](.github/workflows/publish-pypi.yml) on `development` with no inputs: it tags the changelog's version, creates the GitHub Release and publishes, so a cloud session can release. Steps: [release-management](.agents/skills/release-management/SKILL.md).

**Dependabot:** weekly PRs for `uv` (test toolchain grouped), `github-actions` (SHA pins) and `pre-commit`. Merge procedure: [uv skill](.agents/skills/uv/SKILL.md#dependency-upgrades-and-dependabot).

**Stack comments:** [`.github/workflows/stack-comment.yml`](.github/workflows/stack-comment.yml) posts merge order **only** on stacked PRs (non-trunk base or child PR exists). Standalone PRs to `development` are skipped.

## Platform capability matrix

| Platform | Deploy | Query validate (`--live`) | Offline (engine) | `opentide query` |
|----------|:------:|:--------------:|:----------------:|:----------------:|
| Sentinel | ✅ | ✅ KQL | ✅ KQL | ✅ KQL |
| Defender | ✅ | ✅ KQL | ✅ KQL | ✅ KQL |
| Elastic | ✅ | ✅ Kuery, Lucene, EQL, ES\|QL | ✅ Kuery, Lucene, EQL, ES\|QL | ✅ ES\|QL, EQL, Lucene; Kuery via rule preview |
| Splunk | ✅ | ✅ SPL | ✅ SPL | ✅ SPL |
| SentinelOne | ✅ | ✅ S1QL | ❌ | ✅ PowerQuery |
| Carbon Black | ✅ | ✅ Lucene | ✅ Lucene | ✅ Lucene |
| CrowdStrike | ✅ | ❌ | ❌ | ✅ CQL (Next-Gen SIEM) |
| HarfangLab | ✅ | ❌ | ❌ | ✅ telemetry filters (no `--rule`) |
| Sysdig Secure (Falco) | ✅ | ❌ | ✅ Falco | ❌ |

CrowdStrike, HarfangLab and Sysdig: `can_validate is False` — return `supported: False`, never fake validation.
Sysdig (`src/opentide/platforms/sysdig/`) deploys through the Sysdig Secure runtime API only, with the rule
id in deployment state; block macros and lists are expanded into the condition.
`opentide query` runners live in `src/opentide/platforms/<pkg>/runner.py` (`opentide.query`): they save no
search or rule, and stop an asynchronous search they stop waiting for where the API can (CrowdStrike). Elastic
`kuery` is the one write: its rule preview's alerts, in the preview index.

## Analysis engine (`crates/`, `analysis/`)

The offline query checks (`validate`'s and `lint`'s `queries` checks, `validate query`),
`opentide lsp start`, `opentide tui` and MCP `validate_query` run the Rust engine in
[`crates/`](crates/): fifteen crates, imported from opentidehq/language-server with their
history ([`docs/engine/IMPORT.md`](docs/engine/IMPORT.md)), with the grammars, catalogs and
test data they read. [`analysis/`](analysis/) binds `opentide-analysis` and `opentide-lsp` with
PyO3, by path, and [`hatch_build.py`](hatch_build.py) compiles it into the opentide package as
`opentide._native`: there is no separate engine distribution and no engine pin. All of them are
members of one Cargo workspace ([`Cargo.toml`](Cargo.toml), one `Cargo.lock`; `fuzz/` keeps its
own). `uv sync` builds `_native` (develop profile) and needs a Rust toolchain (stable, 1.85+);
release wheels are one `cp310-abi3` wheel per platform, and the sdist carries the workspace.
Python reaches the engine only through `src/opentide/analysis.py`; a missing engine is
`engine_unavailable`, never a skipped check.

| Change | Do |
|--------|----|
| Engine crates, grammars, catalogs (`crates/`, `grammars/`, `highlights/`, `data/catalogs/`) | Follow [`crates/AGENTS.md`](crates/AGENTS.md) and its skills. `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings` and `cargo test --workspace` after `uv sync --group dev`: the engine's tests compare it with this checkout's models. A change opentide users see gets an entry in `CHANGELOG.md`, beside `crates/CHANGELOG.md` |
| Rust binding (`analysis/src/lib.rs`) | Update `src/opentide/_native.pyi`, then the same three cargo commands |
| Object models, vocabulary or pins | Regenerate the engine's bundled Tide catalog in the same change: `uv run python scripts/engine/sync_opentide_schemas.py`. `tests/test_generation/test_bundled_tide_catalog.py` fails otherwise |
| Dependencies of the workspace | One `Cargo.lock` for the engine and the binding; never commit a lock cargo re-resolved for an unrelated change |

## Code quality bar

- **One bar for the whole package.** ruff covers every module under `src/opentide`, `tests`
  and `scripts` (the engine's `scripts/engine/` too), and ty covers all of `src/opentide`;
  neither has an exclude list. Never add one: fix the code or, where a tool is wrong, suppress
  the single site with a reason (`# noqa: RULE -- why`, `# ty: ignore[rule]  # why`). The Cargo
  workspace passes rustfmt and `clippy -D warnings`.
- **Typed.** New and touched functions are fully annotated and ty-clean.
- **Correctness over style.** [`review-checklist`](.agents/skills/review-checklist/SKILL.md)
  lists the defect classes that have shipped here before; check every diff against it.

Configuration: `pyproject.toml` → `[tool.ruff]`, `[tool.ty]`. Skills:
[ruff](.agents/skills/ruff/SKILL.md), [python-typing](.agents/skills/python-typing/SKILL.md).

## Definition of done

1. Each fix has a regression test that fails without it; each feature has tests at the
   level it is used (unit, CLI E2E, MCP).
2. `scripts/ci-local.sh --full` passes.
3. User-visible change → `## [Unreleased]` in `CHANGELOG.md`, written to
   [release-notes](.agents/skills/release-notes/SKILL.md); CLI/MCP/SDK surface change →
   `docs/` ([docs-maintenance](.agents/skills/docs-maintenance/SKILL.md)).
4. Mechanical refactors are proven behaviour-preserving with
   `uv run python scripts/ast_equivalence.py <base-rev>`.

## Repository layout

```
src/opentide/     # PyPI package (models, CLI, MCP, platforms, bundled data)
Cargo.toml        # the Cargo workspace: crates/*, analysis/ (one Cargo.lock)
crates/           # the engine and language server crates, crates/testdata/, crates/AGENTS.md
analysis/         # PyO3 binding of the engine, compiled into opentide as _native (hatch_build.py)
grammars/         # tree-sitter grammars (vendored parser.c) the engine compiles
highlights/       # HighlightSpec, highlight queries and generated editor grammars
data/catalogs/    # catalogs the engine compiles in (KQL, SPL, ES|QL, EQL, ECS, Falco, Tide)
editors/          # Helix, Neovim and Zed samples
packages/         # npm: @opentide/lsp-client, @opentide/lsp-worker
fuzz/             # cargo-fuzz targets (own workspace)
tests/
docs/             # the site's four tabs; docs/internal/, docs/engine/ for maintainers
scripts/          # ci-local.sh, codeql-local.sh, validate-docs.sh; scripts/engine/ for the engine
.agents/skills/
```

Bundled data: `src/opentide/data/`. Logging: `opentide.core.logging` (structlog + Rich) — no operational `print()`.

Client repos: `opentide setup` or `opentide setup ci`.

## Docs

Fumadocs-ready content under [`docs/`](docs/) — four tabs: Usage, CLI, MCP, SDK. Authoring guide: [`docs/README.md`](docs/README.md). Agent skill: [`.agents/skills/docs-maintenance/SKILL.md`](.agents/skills/docs-maintenance/SKILL.md). The engine's design notes are in [`docs/engine/`](docs/engine/), outside the site.

- [`docs/internal/test-plan.md`](docs/internal/test-plan.md)
- [`docs/usage/migration/index.md`](docs/usage/migration/index.md)
