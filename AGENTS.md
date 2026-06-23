# OpenTide — Agent Guide

**OpenTide** (`opentide`) is the DetectionOps engine — a versioned Python package on PyPI for detection-as-code: validate, index, generate schemas, deploy, and document rules across seven security platforms.

**Agent entry point:** This file (`AGENTS.md`), then domain skills in [`.agents/skills/`](.agents/skills/) when a task matches an installed skill.

**Repository:** [OpenTideHQ/opentide](https://github.com/OpenTideHQ/opentide) — all implementation work lands here. Base branch: `development`.

## Ground rules

| Rule | Detail |
|------|--------|
| Repo | [OpenTideHQ/opentide](https://github.com/OpenTideHQ/opentide) only |
| Base branch | `development` |
| PRs | Target `development`; link issues with `Closes #<N>` (opentide issues) |
| Scope | One concern per PR — no drive-by refactors |
| Commits | [Conventional Commits](https://www.conventionalcommits.org/): `feat`, `fix`, `refactor`, `docs`, `chore`, `test`, `ci` |

Branch naming: `<type>/<short-slug>` (e.g. `feat/sentinel-query-cache`, `fix/cli-init-path`).

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

## Agent workflow

1. Read the opentide issue (or task brief) and confirm acceptance criteria
2. `uv sync --group dev` and `uv run pre-commit install --install-hooks` (first time)
3. Branch from `development`
4. Implement acceptance criteria only
5. Run `scripts/ci-local.sh --full` before opening a PR
6. Open PR with summary, test plan, and `Closes #<N>`
7. Address review feedback; do not expand scope mid-PR

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

Remote CI: lint and test matrix run **in parallel**; stale runs are cancelled on new pushes. Coverage runs on the latest supported Python (**3.14**, see `COVERAGE_PYTHON` in `ci.yml`) in one matrix cell only.

### Agent skills (npx skills)

| Skill | Use when |
|-------|----------|
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
scripts/          # ci-local.sh, migration utilities
.agents/skills/   # Shared agent skills
```

Bundled data: `src/opentide/data/`. No legacy root folders (`Configurations/`, `Engines/`, etc.).

Client detection repos use **`opentide init --ci github|gitlab|azure`** or **`opentide ci generate`** — pipelines call the PyPI package, not submodule workflows.

Logging: `opentide.core.logging` (structlog + Rich). New code must not use legacy `print()` for operational output.

## Docs

- [`docs/TEST_PLAN.md`](docs/TEST_PLAN.md) — test strategy and coverage
- [`docs/migration/MIGRATION.md`](docs/migration/MIGRATION.md) — client repo migration

TideKit programme history (CoreTide → OpenTide migration) is archived in migration docs — not part of day-to-day agent workflow.
