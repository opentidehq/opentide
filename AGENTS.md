# opentide — Agent Guide

**opentide** (`opentide`) is the DetectionOps engine — a versioned Python package on PyPI for detection-as-code: validate, index, generate schemas, deploy, and document rules across eight security platforms.

**Entry point:** this file, then a domain skill from [`.agents/skills/`](.agents/skills/) when the task matches.

**Repository:** [opentidehq/opentide](https://github.com/opentidehq/opentide). Trunk: `development`.

## Skills — when to read which

| Task | Skill |
|------|-------|
| Dependencies, `uv run`, pre-commit, local CI | [`.agents/skills/uv/SKILL.md`](.agents/skills/uv/SKILL.md) |
| Ruff lint / format failures | [`.agents/skills/ruff/SKILL.md`](.agents/skills/ruff/SKILL.md) |
| ty type-check failures | [`.agents/skills/python-typing/SKILL.md`](.agents/skills/python-typing/SKILL.md) |
| CodeQL alerts or security workflows | [`.agents/skills/codeql/SKILL.md`](.agents/skills/codeql/SKILL.md) |
| pytest fixtures, mocks, test design | [`.agents/skills/python-testing-patterns/SKILL.md`](.agents/skills/python-testing-patterns/SKILL.md) |
| Coverage gaps, `--cov-fail-under` | [`.agents/skills/pytest-coverage/SKILL.md`](.agents/skills/pytest-coverage/SKILL.md) |
| GitHub Actions workflows | [`.agents/skills/github-actions-templates/SKILL.md`](.agents/skills/github-actions-templates/SKILL.md) |
| CLI E2E tests, tide_corpus, deploy payloads | [`.agents/skills/cli-e2e-testing/SKILL.md`](.agents/skills/cli-e2e-testing/SKILL.md) |
| Documentation pages, Fumadocs structure, doc/code sync | [`.agents/skills/docs-maintenance/SKILL.md`](.agents/skills/docs-maintenance/SKILL.md) |
| PyPI release, changelog, `v*` tag, install pins | [`.agents/skills/release-management/SKILL.md`](.agents/skills/release-management/SKILL.md) |

Stub pointers (content merged above): `uv-package-manager`, `ruff-recursive-fix`.

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

**Stack comments:** [`.github/workflows/stack-comment.yml`](.github/workflows/stack-comment.yml) posts merge order **only** on stacked PRs (non-trunk base or child PR exists). Standalone PRs to `development` are skipped.

## Platform capability matrix

| Platform | Deploy | Query validate |
|----------|:------:|:--------------:|
| Sentinel | ✅ | ✅ KQL |
| Defender | ✅ | ✅ KQL |
| Elastic | ✅ | ✅ Kuery, Lucene, EQL, ES\|QL |
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
scripts/          # ci-local.sh, codeql-local.sh, validate-docs.sh
.agents/skills/
```

Bundled data: `src/opentide/data/`. Logging: `opentide.core.logging` (structlog + Rich) — no operational `print()`.

Client repos: `opentide setup` or `opentide setup ci`.

## Docs

Fumadocs-ready content under [`docs/`](docs/) — four tabs: Usage, CLI, MCP, SDK. Authoring guide: [`docs/README.md`](docs/README.md). Agent skill: [`.agents/skills/docs-maintenance/SKILL.md`](.agents/skills/docs-maintenance/SKILL.md).

- [`docs/internal/test-plan.md`](docs/internal/test-plan.md)
- [`docs/usage/migration/index.md`](docs/usage/migration/index.md)
