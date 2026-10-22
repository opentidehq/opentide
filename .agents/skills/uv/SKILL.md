---
name: uv
description: >-
  Manage opentide's Python environment with uv: sync the dev group, run tools through uv run,
  change or upgrade dependencies, refresh uv.lock, merge Dependabot PRs, install and run the
  pre-commit/pre-push hooks and scripts/ci-local.sh. Use for any dependency, lockfile, hook or
  local-CI question.
---

# uv — opentide

[uv](https://docs.astral.sh/uv/) is the Python package and project manager for this repo. Use it for all dependency install, test, lint, and script execution.

## When to use

- Installing or syncing dependencies
- Running pytest, ruff, ty, pre-commit, or CLI tools
- Local CI parity before push

## opentide commands

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

Docs build/deploy: [opentidehq/website](https://github.com/opentidehq/website). This repo validates with `scripts/validate-docs.sh`.

Add runtime deps with `uv add <package>`. Add dev tools with `uv add --group dev <package>`.

## Dependency upgrades and Dependabot

Dependabot (`.github/dependabot.yml`) opens weekly PRs for three ecosystems: `uv` (the
test toolchain grouped; ruff and ty on their own), `github-actions` (one grouped PR; actions
are pinned by commit SHA with a `# vX.Y.Z` comment) and `pre-commit` (remote hooks only —
ruff and ty run as local hooks from `uv.lock`).

To merge one:

1. Green CI is necessary but not sufficient: a Dependabot PR's checks ran on the base it was
   opened against. If `development` has moved, re-check on the current base before merging
   (`git merge-tree --write-tree origin/development origin/<branch>` must be clean; for a
   ruff/ty bump run `uvx ty@<new> check src/opentide` / `uvx ruff@<new> check src/opentide tests`).
2. ty renames rules between patch releases. A ty bump that reds lint is usually a rename:
   compare the reported sites with `[tool.ty.rules]` in `pyproject.toml` before changing code.
3. Squash-merge, matching the repo history.
4. Two Dependabot PRs that both touch `uv.lock` conflict after the first merges. Never
   hand-edit the lockfile: `uv lock` on the branch (or `@dependabot rebase`).

To refresh everything within the declared constraints yourself:

```bash
uv lock --upgrade              # review the "Updated ..." lines
uv sync --group dev
scripts/ci-local.sh            # lint + unit tests at minimum
```

Watch for resolver walk-backs: `boto3>=1.35` exists because python-dateutil 3.0 once sent
the resolver back to boto3 0.0.3. `mcp<2` stays until the FastMCP import migration (#581).

## Conventions

- **Always** `uv run …` — do not activate `.venv` manually or call bare `python` / `pip`.
- Lockfile: `uv.lock` — commit when dependencies change.
- Python: `requires-python = ">=3.10"`; CI matrix 3.10–3.14.
- There are no optional extras: `pip install opentide` ships every platform SDK. Day-to-day dev uses `--group dev`. Never add an extra; a new runtime dependency goes in `[project] dependencies`.

## Hooks

```bash
uv run pre-commit install --install-hooks
```

- **pre-commit:** whitespace, YAML/TOML, ruff check, ruff format, ty (staged). ruff and ty are local hooks that run the versions pinned in `uv.lock`, so a hook never disagrees with CI.
- **pre-push:** `scripts/ci-local.sh --full` when code/CI paths change; `scripts/validate-docs.sh` when `docs/` changes

The pre-push hook runs on `git push`.

- Do **not** run `pre-commit run --all-files`: the whitespace hooks would rewrite dozens of
  untouched data files, golden fixtures and templates (trailing spaces there can be content).
  Hooks are meant for staged files.
- Claude Code cloud sessions run `.claude/hooks/session-start.sh`, which syncs the dev group
  but does not install the git hooks (pre-push takes ~10 min). Run `scripts/ci-local.sh`
  yourself before pushing.

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
