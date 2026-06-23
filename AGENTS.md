# OpenTide — Agent Guide

**OpenTide** (`opentide`) is the DetectionOps engine — a versioned Python package on PyPI for detection-as-code: validate, index, generate schemas, deploy, and document rules across seven security platforms.

**Agent entry point:** This file (`AGENTS.md`), then domain skills in [`.agents/skills/`](.agents/skills/) when a task matches an installed skill.

**Version control:** [Jujutsu (`jj`)](https://github.com/jj-vcs/jj) with **stacked PRs** — not Graphite (`gt`), not ad-hoc git branches. Skill: [`.agents/skills/jujutsu-stacked-prs/`](.agents/skills/jujutsu-stacked-prs/SKILL.md).

**Repository:** [OpenTideHQ/opentide](https://github.com/OpenTideHQ/opentide) — all implementation work lands here. Trunk: `development` (`development@origin` in jj).

## Ground rules

| Rule | Detail |
|------|--------|
| Repo | [OpenTideHQ/opentide](https://github.com/OpenTideHQ/opentide) only |
| Trunk | `development` / `development@origin` |
| VCS | **jj** bookmarks + stacked PRs via `scripts/jj-stack-submit.sh` |
| PRs | Stacked: bottom → `development`, each upper PR targets bookmark below |
| Scope | One concern per change / PR — no drive-by refactors |
| Commits | Conventional Commits on each jj change (`feat`, `fix`, `refactor`, `docs`, `chore`, `test`, `ci`) |

Bookmark naming: `<type>/<short-slug>` (e.g. `feat/sentinel-query-cache`).

## Jujutsu stacked PRs (first-class)

### One-time setup

```bash
scripts/jj-setup.sh --remove-graphite   # installs jj; removes Graphite; links worktrees
uv sync --group dev
uv run pre-commit install --install-hooks
```

**Git worktrees:** jj colocates in the primary checkout; `scripts/jj-common.sh` routes `jj -R` so stack scripts work from Cursor worktrees.

### Agent workflow

1. Read the issue / task and confirm acceptance criteria
2. `jj git fetch` — sync `development@origin`
3. `jj new development@origin -m "type(scope): …"` — start bottom of stack (or `jj new` on parent bookmark)
4. Implement → `jj bookmark create <type>/<slug>`
5. Stack more changes: `jj new -m "…"` + bookmark per layer
6. `scripts/jj-stack-status.sh` — verify stack order
7. `scripts/ci-local.sh --full`
8. `scripts/jj-stack-submit.sh <top-bookmark>` — push + create stacked GitHub PRs
9. Read **Stack navigation** comment on each PR (posted by CI)
10. After review: `jj new <bookmark>`, edit, `jj squash`, re-submit
11. After merge (bottom first): `jj git fetch` → `jj abandon <merged>` → `jj rebase -d development@origin` → re-submit

**Never** use `gt`, Graphite, or single PRs targeting `development` when work should be stacked.

### Stack on GitHub

- Each PR's **base** is the bookmark below (only the stack bottom targets `development`)
- [`.github/workflows/stack-comment.yml`](.github/workflows/stack-comment.yml) posts merge order + links on every PR
- [`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs CI on **all** PRs (stacked bases included)

### Quick reference

| Task | Command |
|------|---------|
| View stack | `scripts/jj-stack-status.sh` |
| Submit stack | `scripts/jj-stack-submit.sh <top-bookmark>` |
| Dry run | `scripts/jj-stack-submit.sh <top> --dry-run` |
| Local CI | `scripts/ci-local.sh --full` |
| Describe change | `jj describe -m "feat(scope): …"` |
| Rebase on trunk | `jj rebase -d development@origin` |

## Platform capability matrix (7 deployers / 5 validators)

| Platform | Deploy | Query validate |
|----------|:------:|:--------------:|
| Sentinel | ✅ | ✅ KQL |
| Defender | ✅ | ✅ KQL |
| Splunk | ✅ | ✅ SPL |
| SentinelOne | ✅ | ✅ S1QL |
| Carbon Black | ✅ | ✅ Lucene |
| CrowdStrike | ✅ | ❌ |
| HarfangLab | ✅ | ❌ |

CrowdStrike and HarfangLab: `can_validate is False` — return `supported: False` for query validation, never fake results.

## Developer toolchain (uv + ruff + ty)

```bash
uv sync --group dev
uv run pytest tests/ -v
uv run ruff check tests src/opentide
uv run ruff format tests src/opentide
uv run ty check src/opentide
```

CI runs `uv sync --group dev` on Python **3.10–3.14** (full matrix on every PR and push).

### Fast feedback — avoid waiting on CI

```bash
uv run pre-commit install --install-hooks   # once: pre-commit + pre-push hooks
scripts/ci-local.sh --quick                 # lint + ty (~seconds)
scripts/ci-local.sh                           # lint + pytest
scripts/ci-local.sh --full                    # lint + pytest + coverage gate (pyproject.toml)
```

| Hook | Runs |
|------|------|
| **pre-commit** | whitespace/YAML/TOML, ruff, ruff-format, ty (staged files) |
| **pre-push** | `scripts/ci-local.sh --full` when code or CI config changes — **includes coverage gate**; mkdocs `--strict` when `docs/` changes |

`--no-cov` is for fast iteration only (`ci-local.sh` default / matrix cells other than 3.14). Never use it in pre-push hooks.

Targeted iteration:

```bash
uv run pytest tests/test_core/ -x -q
uv run pytest -k "test_sentinel" -x -q
```

Remote CI: lint and test matrix run **in parallel**; stale runs are cancelled on new pushes. Coverage runs on Python **3.14** (`COVERAGE_PYTHON` in `ci.yml`) in one matrix cell; Cobertura XML uploads to **GitHub Code Quality** (`github-code-quality[bot]` comments on PRs with per-file deltas vs `development`). Local `fail_under` in `pyproject.toml` still gates merges via pre-push and CI.

**CodeQL:** Python security scanning is handled by **GitHub Code Quality** (dynamic `CodeQL - Code Quality` workflow). [`.github/workflows/codeql.yml`](.github/workflows/codeql.yml) scans **GitHub Actions workflows only** (`actions` language) so Python is not analyzed twice. Optional local Python deep-scan: `scripts/codeql-local.sh` (~40–60s; not a pre-commit hook).

### Agent skills (npx skills)

| Skill | Use when |
|-------|----------|
| **`jujutsu-stacked-prs`** | **Stacked PRs, jj bookmarks, submit/rebase** |
| `uv` | Dependency groups, `uv run`, lockfile |
| `uv-package-manager` | Advanced uv workflows |
| `python-testing-patterns` | pytest fixtures, parametrisation, mocks |
| `pytest-coverage` | Coverage gaps, `--cov-fail-under` |
| `ruff-recursive-fix` | Ruff lint failures |
| `github-actions-templates` | `.github/workflows/` |
| `python-mcp-server-generator` | `opentide.mcp_server` |

```bash
npx skills find python
npx skills add <owner/repo> --skill <name> --agent cursor -y
npx skills list
```

### Code quality scope

Ruff and ty **exclude** large ported platform/deployer modules until those areas are actively cleaned up. Do not expand lint scope in unrelated PRs. When touching excluded paths, still run `scripts/ci-local.sh` — tests cover behaviour.

## Repository layout

```
src/opentide/     # PyPI package (models, CLI, MCP, platforms, bundled data)
tests/
docs/
scripts/          # ci-local.sh, jj-stack-*.sh, jj-setup.sh
.agents/skills/   # Shared agent skills (incl. jujutsu-stacked-prs)
```

Bundled data: `src/opentide/data/`. No legacy root folders (`Configurations/`, `Engines/`, etc.).

Client detection repos use **`opentide init --ci github|gitlab|azure`** or **`opentide ci generate`** — pipelines call the PyPI package, not submodule workflows.

Logging: `opentide.core.logging` (structlog + Rich). New code must not use legacy `print()` for operational output.

## Docs

- [`docs/TEST_PLAN.md`](docs/TEST_PLAN.md) — test strategy and coverage
- [`docs/migration/MIGRATION.md`](docs/migration/MIGRATION.md) — client repo migration

TideKit programme history (CoreTide → OpenTide migration) is archived in migration docs — not part of day-to-day agent workflow.
