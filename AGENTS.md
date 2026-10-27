# opentide — Agent Guide

**opentide** (`opentide`) — spec-driven development for agentic detection engineering. A versioned Python package on PyPI for detection-as-code: validate, index, generate schemas, deploy, and document rules across eight security platforms.

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
| PyPI release, changelog, `v*` tag, install pins | [`.agents/skills/release-management/SKILL.md`](.agents/skills/release-management/SKILL.md) |

Claude Code discovers these through `.claude/skills` (a symlink to `.agents/skills`); cloud
sessions run `.claude/hooks/session-start.sh`, which syncs the dev environment.

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

**CI** (`.github/workflows/ci.yml`): lint (ruff + ty) and test matrix Python **3.10–3.14** in parallel; stale runs cancelled on new pushes.

**Local parity:**

```bash
scripts/ci-local.sh --quick    # ruff + ty (~seconds)
scripts/ci-local.sh              # lint + pytest
scripts/ci-local.sh --full       # + coverage gate (pyproject.toml) — use before push
```

**Coverage:** gate on Python **3.14** only (`COVERAGE_PYTHON` in ci.yml). Cobertura upload to GitHub Code Quality is best-effort (`fail-on-error: false` if Code Quality is disabled). HTML report uploaded as artifact.

**Vocabulary drift gate:** when bundled vocab TOML files, schema pins (`src/opentide/data/pins/`), `data/specifications.lock.json` or the sync script change, CI also checks out `opentidehq/specifications` (`main`) and runs `uv run python scripts/build/sync_vocabularies.py --check` against it (`OPENTIDE_SPECIFICATIONS_ROOT`).

**CodeQL:** Python and Actions via [`.github/workflows/codeql.yml`](.github/workflows/codeql.yml) (`/language:python` + `/language:actions`); Code Quality may also run dynamic Python on push. Local Python: `scripts/codeql-local.sh`.

**Dependabot:** weekly PRs for `uv` (test toolchain grouped), `github-actions` (SHA pins) and `pre-commit`. Merge procedure: [uv skill](.agents/skills/uv/SKILL.md#dependency-upgrades-and-dependabot).

**Stack comments:** [`.github/workflows/stack-comment.yml`](.github/workflows/stack-comment.yml) posts merge order **only** on stacked PRs (non-trunk base or child PR exists). Standalone PRs to `development` are skipped.

## Platform capability matrix

| Platform | Deploy | Query validate | `opentide query` |
|----------|:------:|:--------------:|:----------------:|
| Sentinel | ✅ | ✅ KQL | ✅ KQL |
| Defender | ✅ | ✅ KQL | ✅ KQL |
| Elastic | ✅ | ✅ Kuery, Lucene, EQL, ES\|QL | ✅ ES\|QL, EQL, Lucene; Kuery via rule preview |
| Splunk | ✅ | ✅ SPL | ✅ SPL |
| SentinelOne | ✅ | ✅ S1QL | ✅ PowerQuery |
| Carbon Black | ✅ | ✅ Lucene | ✅ Lucene |
| CrowdStrike | ✅ | ❌ | ✅ CQL (Next-Gen SIEM) |
| HarfangLab | ✅ | ❌ | ✅ telemetry filters (no `--rule`) |

CrowdStrike and HarfangLab: `can_validate is False` — return `supported: False`, never fake validation.
`opentide query` runners live in `src/opentide/platforms/<pkg>/runner.py` (`opentide.query`): they save no
search or rule, and stop an asynchronous search they stop waiting for where the API can (CrowdStrike). Elastic
`kuery` is the one write: its rule preview's alerts, in the preview index.

## Code quality bar

- **One bar for the whole package.** ruff covers every module under `src/opentide`, `tests`
  and `scripts`, and ty covers all of `src/opentide`; neither has an exclude list. Never add
  one: fix the code or, where a tool is wrong, suppress the single site with a reason
  (`# noqa: RULE -- why`, `# ty: ignore[rule]  # why`).
- **Typed.** New and touched functions are fully annotated and ty-clean.
- **Correctness over style.** [`review-checklist`](.agents/skills/review-checklist/SKILL.md)
  lists the defect classes that have shipped here before; check every diff against it.

Configuration: `pyproject.toml` → `[tool.ruff]`, `[tool.ty]`. Skills:
[ruff](.agents/skills/ruff/SKILL.md), [python-typing](.agents/skills/python-typing/SKILL.md).

## Definition of done

1. Each fix has a regression test that fails without it; each feature has tests at the
   level it is used (unit, CLI E2E, MCP).
2. `scripts/ci-local.sh --full` passes.
3. User-visible change → `## [Unreleased]` in `CHANGELOG.md`; CLI/MCP/SDK surface change →
   `docs/` ([docs-maintenance](.agents/skills/docs-maintenance/SKILL.md)).
4. Mechanical refactors are proven behaviour-preserving with
   `uv run python scripts/ast_equivalence.py <base-rev>`.

## Repository layout

```
src/opentide/     # PyPI package (models, CLI, MCP, platforms, bundled data)
tests/
docs/
scripts/          # ci-local.sh, codeql-local.sh, validate-docs.sh
.agents/skills/
```

Bundled data: `src/opentide/data/`. Logging: `opentide.core.logging` (structlog + Rich) — no operational `print()`.

Client repos: `opentide setup` or `opentide setup ci`.

## Docs

Fumadocs-ready content under [`docs/`](docs/) — four tabs: Usage, CLI, MCP, SDK. Authoring guide: [`docs/README.md`](docs/README.md). Agent skill: [`.agents/skills/docs-maintenance/SKILL.md`](.agents/skills/docs-maintenance/SKILL.md).

- [`docs/internal/test-plan.md`](docs/internal/test-plan.md)
- [`docs/usage/migration/index.md`](docs/usage/migration/index.md)
