# OpenTide — Agent Guide

**OpenTide** (`opentide`) is the DetectionOps engine — a versioned Python package on PyPI for detection-as-code: validate, index, generate schemas, deploy, and document rules across seven security platforms.

**Entry point:** this file, then a domain skill from [`.agents/skills/`](.agents/skills/) when the task matches.

**Repository:** [OpenTideHQ/opentide](https://github.com/OpenTideHQ/opentide). Trunk: `development` (`development@origin` in jj).

## Skills — when to read which

| Task | Skill |
|------|-------|
| Any VCS work (commit, push, rebase, stacked PRs) | [`.agents/skills/jujutsu/SKILL.md`](.agents/skills/jujutsu/SKILL.md) |
| Dependencies, `uv run`, pre-commit, local CI | [`.agents/skills/uv/SKILL.md`](.agents/skills/uv/SKILL.md) |
| Ruff lint / format failures | [`.agents/skills/ruff/SKILL.md`](.agents/skills/ruff/SKILL.md) |
| ty type-check failures | [`.agents/skills/python-typing/SKILL.md`](.agents/skills/python-typing/SKILL.md) |
| CodeQL alerts or security workflows | [`.agents/skills/codeql/SKILL.md`](.agents/skills/codeql/SKILL.md) |
| pytest fixtures, mocks, test design | [`.agents/skills/python-testing-patterns/SKILL.md`](.agents/skills/python-testing-patterns/SKILL.md) |
| Coverage gaps, `--cov-fail-under` | [`.agents/skills/pytest-coverage/SKILL.md`](.agents/skills/pytest-coverage/SKILL.md) |
| GitHub Actions workflows | [`.agents/skills/github-actions-templates/SKILL.md`](.agents/skills/github-actions-templates/SKILL.md) |
| CLI E2E tests, tide_corpus, deploy payloads | [`.agents/skills/cli-e2e-testing/SKILL.md`](.agents/skills/cli-e2e-testing/SKILL.md) |

Stub pointers (content merged above): `jujutsu-stacked-prs`, `uv-package-manager`, `ruff-recursive-fix`.

## Ground rules

| Rule | Detail |
|------|--------|
| VCS | **jj** only — `jj describe`, `jj bookmark`, `jj git push --bookmark` |
| PRs | Single: `scripts/jj-submit.sh`; stacked: `scripts/jj-stack-submit.sh` |
| Trunk | `development@origin` |
| Scope | One concern per change / PR |
| Commits | Conventional Commits (`feat`, `fix`, `refactor`, `docs`, `chore`, `test`, `ci`) |

Bookmark naming: `<type>/<short-slug>` (e.g. `feat/sentinel-query-cache`).

**Forbidden for local coding agents:** `git commit`, `git add`, `git checkout -b`, `git merge`, `git rebase`, `git push`, Graphite (`gt`). Use **jj** instead (see above).

**Cloud agents** (Cursor Cloud, GitHub Copilot Workspace, etc.): follow the platform git workflow when jj is unavailable; still use Conventional Commits and open PRs against `development`.

## Daily workflow

```bash
scripts/jj-setup.sh                         # once per machine
uv sync --group dev
uv run pre-commit install --install-hooks   # once per clone

jj git fetch
jj new development@origin -m "feat(scope): …"   # or continue on @
# … edit files (jj snapshots @ automatically) …
jj describe -m "feat(scope): …"
jj bookmark create feat/slug                  # if new
scripts/ci-local.sh --full
jj git push --bookmark feat/slug              # triggers pre-push hooks
scripts/jj-submit.sh feat/slug                # or jj-stack-submit.sh for stacks
```

| Step | Command |
|------|---------|
| Status | `jj status`, `jj log` |
| Rebase on trunk | `jj rebase -d development@origin` |
| View stack | `scripts/jj-stack-status.sh` |
| After merge | `jj git fetch` → `jj abandon <bookmark>` → `jj rebase -d development@origin` |

Full jj reference: [`.agents/skills/jujutsu/SKILL.md`](.agents/skills/jujutsu/SKILL.md).

## CI, coverage, CodeQL, stack comments

**CI** (`.github/workflows/ci.yml`): lint (ruff + ty) and test matrix Python **3.10–3.14** in parallel; stale runs cancelled on new pushes.

**Local parity:**

```bash
scripts/ci-local.sh --quick    # ruff + ty (~seconds)
scripts/ci-local.sh              # lint + pytest
scripts/ci-local.sh --full       # + coverage gate (pyproject.toml) — use before push
```

**Coverage:** gate on Python **3.14** only (`COVERAGE_PYTHON` in ci.yml). Cobertura upload to GitHub Code Quality is best-effort (`fail-on-error: false` if Code Quality is disabled). HTML report uploaded as artifact.

**CodeQL:** Python and Actions via [`.github/workflows/codeql.yml`](.github/workflows/codeql.yml) (`/language:python` + `/language:actions`); Code Quality may also run dynamic Python on push. Local Python: `scripts/codeql-local.sh`.

**Stack comments:** [`.github/workflows/stack-comment.yml`](.github/workflows/stack-comment.yml) posts merge order **only** on stacked PRs (non-trunk base or child PR exists). Standalone PRs to `development` are skipped.

## Platform capability matrix

| Platform | Deploy | Query validate |
|----------|:------:|:--------------:|
| Sentinel | ✅ | ✅ KQL |
| Defender | ✅ | ✅ KQL |
| Splunk | ✅ | ✅ SPL |
| SentinelOne | ✅ | ✅ S1QL |
| Carbon Black | ✅ | ✅ Lucene |
| CrowdStrike | ✅ | ❌ |
| HarfangLab | ✅ | ❌ |

CrowdStrike and HarfangLab: `can_validate is False` — return `supported: False`, never fake validation.

## Code quality scope

Ruff and ty **exclude** large ported platform/deployer modules until those areas are actively cleaned up. Do not expand lint scope in unrelated PRs. When touching excluded paths, still run `scripts/ci-local.sh` — tests cover behaviour.

Paths and excludes: `pyproject.toml` → `[tool.ruff]`, `[tool.ty.src]`. Skills: [ruff](.agents/skills/ruff/SKILL.md), [python-typing](.agents/skills/python-typing/SKILL.md).

## Repository layout

```
src/opentide/     # PyPI package (models, CLI, MCP, platforms, bundled data)
tests/
docs/
scripts/          # ci-local.sh, codeql-local.sh, jj-*.sh
.agents/skills/
```

Bundled data: `src/opentide/data/`. Logging: `opentide.core.logging` (structlog + Rich) — no operational `print()`.

Client repos: `opentide setup` or `opentide setup ci`.

## Docs

- [`docs/TEST_PLAN.md`](docs/TEST_PLAN.md)
- [`docs/migration/MIGRATION.md`](docs/migration/MIGRATION.md)
