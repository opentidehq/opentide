# uv — OpenTide

[uv](https://docs.astral.sh/uv/) is the Python package and project manager for this repo. Use it for all dependency install, test, lint, and script execution.

## When to use

- Installing or syncing dependencies
- Running pytest, ruff, ty, pre-commit, or CLI tools
- Local CI parity before push

## OpenTide commands

```bash
uv sync --group dev              # install dev deps (pytest, ruff, ty, pre-commit, …)
uv run pytest tests/ -v
uv run ruff check tests src/opentide
uv run ty check src/opentide
uv run pre-commit install --install-hooks   # once per clone
scripts/ci-local.sh --quick      # ruff + ty
scripts/ci-local.sh              # lint + pytest (no coverage gate)
scripts/ci-local.sh --full       # lint + pytest + coverage gate — pre-push parity
```

CI (`.github/workflows/ci.yml`) runs `uv sync --group dev` on every job.

## Dependency groups

| Group | Purpose |
|-------|---------|
| `dev` | Tests, ruff, ty, pre-commit, pandas fixtures |

Docs build/deploy: [OpenTideHQ/website](https://github.com/OpenTideHQ/website). This repo validates with `scripts/validate-docs.sh`.

Add runtime deps with `uv add <package>`. Add dev tools with `uv add --group dev <package>`.

## Conventions

- **Always** `uv run …` — do not activate `.venv` manually or call bare `python` / `pip`.
- Lockfile: `uv.lock` — commit when dependencies change.
- Python: `requires-python = ">=3.10"`; CI matrix 3.10–3.14.
- Optional extras (`cli`, `mcp`, platform names) exist for client installs; day-to-day dev uses `--group dev`.

## Hooks

```bash
uv run pre-commit install --install-hooks
```

- **pre-commit:** whitespace, YAML/TOML, ruff, ruff-format, ty (staged)
- **pre-push:** `scripts/ci-local.sh --full` when code/CI paths change; `scripts/validate-docs.sh` when `docs/` changes

Hooks run on `jj git push` (colocated git backend).

## General uv reference

Scripts, tools, migration from pip/poetry/pyenv:

```bash
uv run script.py
uvx ruff check .                 # ephemeral tool (prefer uv run in this repo)
uv add requests
uv lock
uv python install 3.12
```

Full upstream docs: https://docs.astral.sh/uv/llms.txt

Advanced patterns (Docker, monorepos): see stub [`.agents/skills/uv-package-manager/`](../uv-package-manager/SKILL.md).
