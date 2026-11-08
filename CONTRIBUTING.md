# Contributing to opentide

opentide is a Python package with a Rust engine compiled in, and the unified core
([#790](https://github.com/opentidehq/opentide/issues/790)) is moving the rest of the logic into the
same Cargo workspace. This page gets you from a fresh clone to a pull request.
[`AGENTS.md`](AGENTS.md) is the map of the repository and holds the rules. This page points into it
and does not repeat it, so when the two disagree, `AGENTS.md` is right.

## Setup

You need [uv](https://docs.astral.sh/uv/) and [rustup](https://rustup.rs/). rustup installs the
Rust release that [`rust-toolchain.toml`](rust-toolchain.toml) pins the first time you run cargo in
the checkout.

```bash
git clone https://github.com/opentidehq/opentide.git
cd opentide
uv sync --group dev                         # the .venv, with the engine compiled in (opentide._native)
uv run pre-commit install --install-hooks   # once per clone: pre-commit and pre-push hooks
cargo install cargo-nextest --locked        # the Rust test runner
cargo install cargo-insta --locked          # snapshot review
```

`uv sync` compiles the Rust engine into the package, so it runs cargo with the pinned toolchain.
Dependencies, the lock file and the hooks are covered by the [`uv`](.agents/skills/uv/SKILL.md)
skill.

## The Python loop

```bash
uv run pytest tests/test_validation -q --no-cov   # one area while you work
scripts/ci-local.sh --quick                       # ruff, ty, cargo fmt, clippy, layers, engine checks, uv build
scripts/ci-local.sh --full                        # adds cargo test, pytest with the coverage gate, the E2E suite
```

Run `scripts/ci-local.sh --full` before you push. The pre-push hook runs it too, when the push
touches code or CI configuration. Its last step
lints the generated GitLab CI pipelines with prebuilt binaries it downloads. If your network does
not allow that, say so in the pull request, and CI's `gitlab-ci-lint` job runs it.

The quality bar: ruff and ty cover the whole package with no exclude list, and new and touched
functions are fully annotated. See the [`ruff`](.agents/skills/ruff/SKILL.md) and
[`python-typing`](.agents/skills/python-typing/SKILL.md) skills, and
[`python-testing-patterns`](.agents/skills/python-testing-patterns/SKILL.md) for tests.

## The Rust loop

```bash
cargo check -p opentide-core                                 # while editing
cargo nextest run --profile fast                             # the fast tests, about 15 s warm
cargo fmt --all --check                                      # before a commit
cargo clippy --workspace --all-targets -- -D warnings
cargo xtask check-layers
cargo nextest run --workspace --profile ci                   # everything, as CI runs it
cargo test --workspace --doc                                 # doctests (nextest skips them)
```

The [`rust`](.agents/skills/rust/SKILL.md) skill explains each of these: the lint policy,
the nextest profiles, insta snapshots, trycmd cases, `cargo xtask` and how to add a crate.
[`crates/AGENTS.md`](crates/AGENTS.md) holds the engine's rules, and each crate has its own
`AGENTS.md`. Lint with the pinned toolchain: CI does, and denies warnings.

## Porting to Rust

The Python CLI at a frozen tag is the oracle. A Rust implementation of a command must match it
byte for byte, and every intended difference goes in the approved-diffs ledger with a reason, an
issue and a changelog entry. Goldens are generated, never edited by hand. The
[`golden`](.agents/skills/golden/SKILL.md) skill has the rules and the tools, which UC-0.5
([#803](https://github.com/opentidehq/opentide/issues/803)) and UC-0.7
([#805](https://github.com/opentidehq/opentide/issues/805)) are building. Architecture decisions
are recorded in [`docs/internal/adr/`](docs/internal/adr/index.md).

## Parallel work: worktrees and target directories

To work on several changes at once, or to run several agents, give each one a git worktree and a
Cargo target directory (a pool) of its own, outside the worktree. The recipe is in `AGENTS.md`,
["Parallel agents: worktrees and target pools"](AGENTS.md#parallel-agents-worktrees-and-target-pools).
In short:

- `CARGO_TARGET_DIR` is an absolute path, one per pool. A relative one starts a new multi-GB target
  wherever a command runs.
- Two worktrees never use one pool at the same time. cargo judges freshness by modification times,
  so it can run the other worktree's code without a word. When a pool passes to another worktree,
  run `git ls-files -z | xargs -0 touch -c` in the new one first.
- `CARGO_INCREMENTAL=0` for one-shot runs: no incremental cache to grow.

## Commits and pull requests

- **One concern per change**, on a branch named `<type>/<short-slug>` (for example
  `feat/sentinel-query-cache`), cut from `origin/development`.
- **Conventional Commits** with a scope: `feat`, `fix`, `refactor`, `docs`, `chore`, `test`, `ci`.
- **Open the pull request against `development`.** A stacked pull request targets the branch below
  it. Fill in [the template](.github/pull_request_template.md): what and why, how you verified it,
  and the checklist.
- **Definition of done:** a regression test that fails without the fix; `scripts/ci-local.sh --full`
  green; a `CHANGELOG.md` entry under `## [Unreleased]` for a user-visible change
  ([`release-notes`](.agents/skills/release-notes/SKILL.md)); docs for a CLI, MCP or SDK change
  ([`docs-maintenance`](.agents/skills/docs-maintenance/SKILL.md)). The full list is in
  `AGENTS.md`, "Definition of done".
- **Review** against the [`review-checklist`](.agents/skills/review-checklist/SKILL.md): the
  defect classes that have shipped here before. The [`steward`](.agents/skills/steward/SKILL.md)
  skill drives a pull request to green.
- Never push to `development` directly, force-push a branch someone else works on, or rewrite
  history that is already on `origin`.

## Where agents read

Coding agents start at [`AGENTS.md`](AGENTS.md) (`CLAUDE.md` includes it). It maps every directory
to its guide and every kind of task to a skill under [`.agents/skills/`](.agents/skills/); Claude
Code finds the skills through the `.claude/skills` link. The area guides are
[`src/AGENTS.md`](src/AGENTS.md), [`crates/AGENTS.md`](crates/AGENTS.md) and one per crate,
[`xtask/AGENTS.md`](xtask/AGENTS.md), [`analysis/AGENTS.md`](analysis/AGENTS.md) and
[`.github/AGENTS.md`](.github/AGENTS.md). If you change how something is done, change the guide or
skill that describes it in the same pull request.

## Documentation

User and reference docs are under [`docs/`](docs/), in four tabs (Usage, CLI, MCP, SDK); the
authoring guide is [`docs/README.md`](docs/README.md). Run `scripts/validate-docs.sh` and
`uv run pytest tests/test_docs -q` after changing a page.

## Licence

opentide is licensed under the [EUPL-1.2](LICENSE).
