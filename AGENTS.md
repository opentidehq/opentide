# opentide — Agent Guide

**opentide** (`opentide`) — spec-driven development for agentic detection engineering. A versioned Python package on PyPI for detection-as-code: validate, index, generate schemas, deploy, and document rules across nine security platforms, with a Rust engine (query languages, Tide YAML, the language server) compiled in.

**Entry point:** this file is the map; people start at [`CONTRIBUTING.md`](CONTRIBUTING.md). Read the guide of the area you change (below), then the skill that matches the task.

**Repository:** [opentidehq/opentide](https://github.com/opentidehq/opentide). Trunk: `development`. The plan that is moving every implementation into one Rust workspace: [`docs/internal/unified-core.md`](https://github.com/opentidehq/opentide/blob/docs/unified-core-plan/docs/internal/unified-core.md) (epic [#790](https://github.com/opentidehq/opentide/issues/790)).

## Map

| Path | What it is | Read first |
|------|------------|------------|
| `src/opentide/` | The PyPI package: models, CLI, MCP, platforms, bundled data (`src/opentide/data/`) | [`src/AGENTS.md`](src/AGENTS.md) |
| `tests/` | The Python suite: unit, CLI E2E (sharded), MCP, docs and CI contracts | the testing skills below |
| `tests/golden/` | The goldens of the frozen Python CLI (the oracle): `cargo xtask golden record\|check` | [`tests/golden/README.md`](tests/golden/README.md) |
| `Cargo.toml`, `Cargo.lock` | One Cargo workspace: lints, shared dependencies, profiles | [`crates/AGENTS.md`](crates/AGENTS.md) |
| `crates/opentide-*/` | The engine and language server crates, one guide each | `crates/<crate>/AGENTS.md` |
| `analysis/` | The PyO3 binding compiled into the package as `opentide._native` | [`analysis/AGENTS.md`](analysis/AGENTS.md) |
| `xtask/` | `cargo xtask`: the layer check (`xtask/layers.toml`), codegen, golden and bench to come | [`xtask/AGENTS.md`](xtask/AGENTS.md) |
| `grammars/`, `highlights/`, `data/catalogs/`, `editors/`, `packages/`, `fuzz/`, `crates/testdata/`, `scripts/engine/` | What the engine compiles in, its hosts, fuzzing and tooling | [`crates/AGENTS.md`](crates/AGENTS.md) |
| `docs/` | The site's four tabs (Usage, CLI, MCP, SDK); `docs/internal/` (with the ADRs, `docs/internal/adr/`) and `docs/engine/` for maintainers | [`docs/README.md`](docs/README.md) |
| `.github/` | CI, CodeQL, release and Dependabot workflows | [`.github/AGENTS.md`](.github/AGENTS.md) |
| `scripts/` | `ci-local.sh`, `codeql-local.sh`, `validate-docs.sh`, `ast_equivalence.py`, `build/` | this file, "Checks" |
| `.agents/skills/` | The skills below; `.claude/skills` links to them | the table below |
| `publishing/` | Name placeholders for crates.io and npm, rehearsed by `publish-dry-run.yml` | [`docs/internal/publishing.md`](docs/internal/publishing.md) |

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
| Building, linting, testing any Rust crate: toolchain, clippy, nextest, insta, trycmd, xtask, worktrees and target pools | [`.agents/skills/rust/SKILL.md`](.agents/skills/rust/SKILL.md) |
| Porting to Rust against the Python oracle: goldens, `OPENTIDE_ENGINE=compare`, the approved-diffs ledger | [`.agents/skills/golden/SKILL.md`](.agents/skills/golden/SKILL.md) |
| The engine's Rust crates, `Cargo.toml`, `Cargo.lock` | [`.agents/skills/rust-engine/SKILL.md`](.agents/skills/rust-engine/SKILL.md) |
| Grammars, `crates/opentide-syntax`, highlight queries | [`.agents/skills/tree-sitter/SKILL.md`](.agents/skills/tree-sitter/SKILL.md) |
| The language server host (`crates/opentide-lsp`), `editors/` | [`.agents/skills/lsp-host/SKILL.md`](.agents/skills/lsp-host/SKILL.md) |
| WebAssembly (`crates/opentide-wasm`), npm `packages/` | [`.agents/skills/wasm-hosts/SKILL.md`](.agents/skills/wasm-hosts/SKILL.md) |
| `data/catalogs/`, HighlightSpec, conformance corpora, the vendor-parser oracles | [`.agents/skills/catalogs/SKILL.md`](.agents/skills/catalogs/SKILL.md) |
| A new query language in the engine | [`.agents/skills/add-language/SKILL.md`](.agents/skills/add-language/SKILL.md) |
| `crates/CHANGELOG.md`, the engine crates' release notes | [`.agents/skills/engine-release-notes/SKILL.md`](.agents/skills/engine-release-notes/SKILL.md) |
| Releasing the engine crates (`engine-v*` tags, `engine-release.yml`) | [`.agents/skills/engine-release/SKILL.md`](.agents/skills/engine-release/SKILL.md) |

The engine's skills (the last eight rows) came from opentidehq/language-server; their own index, with
the engine's hard rules, is [`crates/AGENTS.md`](crates/AGENTS.md). Claude Code discovers the skills
through `.claude/skills` (a symlink to `.agents/skills`); cloud sessions run
`.claude/hooks/session-start.sh`, which syncs the dev environment.

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

## Parallel agents: worktrees and target pools

Agents that work at once each take a git worktree and a target pool of their own: a Cargo target
directory outside the worktree. Two worktrees never use one pool at the same time. A pool outlives
its worktree, so the next worktree it serves, one after another, finds the dependencies compiled:

```bash
git fetch origin
git worktree add -b feat/slug ../wt/slug origin/development
cd ../wt/slug
# POOL names a pool no other worktree uses now (ls ../.target): the next line fails without it
export CARGO_TARGET_DIR="$(cd .. && pwd)/.target/${POOL:?name a pool no other worktree uses now}"
export CARGO_INCREMENTAL=0                      # one-shot runs: no incremental cache to grow
git ls-files -z | xargs -0 touch -c             # the pool served another worktree: rebuild this one's crates
uv sync --group dev                             # this worktree's .venv; _native builds in the pool
```

- `CARGO_TARGET_DIR` must be absolute: cargo resolves a relative one against each command's working
  directory, so a run from a subdirectory would start a new multi-GB target there.
- One pool per worktree in use. Cargo judges a workspace crate fresh by modification times, not
  content, and every worktree's crates build to the same artifacts in a pool: after another
  worktree's build, an older file here counts as built, so cargo runs the other worktree's code
  (and its `env!("CARGO_MANIFEST_DIR")` paths) without a word. Cargo's lock on the target
  directory only makes two builds wait for each other. Touch the tracked files when a pool passes
  to another worktree, as above; agents working at once cannot know when to, so they never share a
  pool, and whoever starts them gives each its `POOL`. CI is not affected: every run starts from a
  fresh checkout.
- `touch -c` only updates the modification times of files that exist: a tracked file deleted in
  the worktree stays deleted (plain `touch` recreates it empty, and `git commit -a` commits that).
- A compiler cache does not bridge pools as this recipe stands: sccache (0.19) keys each crate on
  every `CARGO_*` variable, `CARGO_TARGET_DIR` included, so two pools never share an entry.
- Size pools to the disk (a warm pool is several GB). Keep each pool's environment the same
  (`RUSTFLAGS`, `CARGO_PROFILE_*`): a change rebuilds the workspace crates. CI's Rust jobs set
  `CARGO_PROFILE_DEV_DEBUG=line-tables-only`.
- nextest keeps its JUnit report under the worktree's own `target/nextest/` (gitignored), whatever
  `CARGO_TARGET_DIR` says.
- Done with a worktree: `git worktree remove ../wt/slug`; delete a pool nothing uses any more.

## Checks

| Loop | Command |
|------|---------|
| Rust, while editing | `cargo check -p <crate>`; `cargo nextest run --profile fast` (whole workspace, about 15 s warm; `-p <crate>` for one) |
| Rust, before a commit | `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo xtask check-layers` |
| Rust, everything | `cargo nextest run --workspace --profile ci` and `cargo test --workspace --doc` (nextest runs no doctests), or `cargo test --workspace` |
| Python, while editing | `uv run pytest tests/<area> -q --no-cov` |
| Lint and types | `scripts/ci-local.sh --quick` (ruff, ty, cargo fmt, clippy, layers, engine checks, `uv build`) |
| Before a push | `scripts/ci-local.sh --full` (adds nextest `ci`, doctests, rustdoc, the crates' package and licence scan, pytest with the coverage gate, the E2E suite, GitLab CI lint; WebAssembly, grammars and fuzz smoke when their tools are installed) |

The test profiles are in [`.config/nextest.toml`](.config/nextest.toml); CI's jobs are in
[`.github/AGENTS.md`](.github/AGENTS.md).

## Code quality bar

- **One bar for the whole package.** ruff covers every module under `src/opentide`, `tests`
  and `scripts` (the engine's `scripts/engine/` too), and ty covers all of `src/opentide`;
  neither has an exclude list. Never add one: fix the code or, where a tool is wrong, suppress
  the single site with a reason (`# noqa: RULE -- why`, `# ty: ignore[rule]  # why`).
- **The Rust workspace** passes rustfmt and `clippy -D warnings` under the lints in the root
  [`Cargo.toml`](Cargo.toml) (`[workspace.lints]`: `unsafe_code` forbidden outside two crates,
  `clippy::pedantic`, no `unwrap`/`expect`/`dbg!`/`todo!`/`unimplemented!` outside tests,
  `missing_docs`). Fix what a lint reports, or put `#[expect(lint, reason = "...")]` on the
  narrowest item where it fires; growing the workspace's allow-list is a decision of its own.
  Crates depend only downward ([`xtask/layers.toml`](xtask/layers.toml)). Details:
  [`crates/AGENTS.md`](crates/AGENTS.md).
- **Typed.** New and touched Python functions are fully annotated and ty-clean.
- **Correctness over style.** [`review-checklist`](.agents/skills/review-checklist/SKILL.md)
  lists the defect classes that have shipped here before; check every diff against it.

Configuration: `pyproject.toml` → `[tool.ruff]`, `[tool.ty]`; `Cargo.toml`, `clippy.toml`,
`rustfmt.toml`. Skills: [ruff](.agents/skills/ruff/SKILL.md),
[python-typing](.agents/skills/python-typing/SKILL.md),
[rust-engine](.agents/skills/rust-engine/SKILL.md).

## Definition of done

1. Each fix has a regression test that fails without it; each feature has tests at the
   level it is used (unit, CLI E2E, MCP).
2. `scripts/ci-local.sh --full` passes.
3. User-visible change → `## [Unreleased]` in `CHANGELOG.md`, written to
   [release-notes](.agents/skills/release-notes/SKILL.md); CLI/MCP/SDK surface change →
   `docs/` ([docs-maintenance](.agents/skills/docs-maintenance/SKILL.md)).
4. Mechanical refactors are proven behaviour-preserving with
   `uv run python scripts/ast_equivalence.py <base-rev>`.

## Docs

Fumadocs-ready content under [`docs/`](docs/), four tabs: Usage, CLI, MCP, SDK. Authoring guide: [`docs/README.md`](docs/README.md). Agent skill: [`.agents/skills/docs-maintenance/SKILL.md`](.agents/skills/docs-maintenance/SKILL.md). The engine's design notes are in [`docs/engine/`](docs/engine/), outside the site.

- [`docs/internal/test-plan.md`](docs/internal/test-plan.md)
- [`docs/cli/migrate.md`](docs/cli/migrate.md): `opentide migrate`, objects from an earlier model
