# Python typing (ty) — OpenTide

Static type checking with [ty](https://docs.astral.sh/ty/) on the in-scope `src/opentide` tree.

## When to use

- `ty check` failures in CI, pre-commit, or `scripts/ci-local.sh`
- Adding typed code under checked paths
- Deciding whether a module is in or out of ty scope

## Commands

```bash
uv sync --group dev
uv run ty check src/opentide
uv run ty check src/opentide --output-format github   # CI format
```

Included in:

- `scripts/ci-local.sh` (all modes except skipped in `--quick`… actually --quick includes ty)
- `.github/workflows/ci.yml` lint job
- pre-commit hook `ty` (files under `^src/opentide/`)

## Scope

`pyproject.toml` → `[tool.ty.src]`:

- **include:** `src/opentide`
- **exclude:** ported platforms, CLI, deployment/mutation, most generation/loading/models/validation, legacy core helpers (full list in `exclude`)

Checked areas typically include: core registry/index paths, generation templates, schemas, and other actively maintained modules **not** in the exclude list.

Rule overrides in `[tool.ty.rules]`:

- `invalid-method-override = "warn"` — Tide models delegate to Pydantic
- `redundant-cast = "ignore"`

Do **not** remove excludes to “fix” ty in unrelated PRs. Expand scope only when cleaning up that area.

## Workflow

1. Run `uv run ty check src/opentide`.
2. Fix reported issues in included files.
3. If touching an excluded module for other reasons, ty may still pass — run `scripts/ci-local.sh --quick` to confirm.
4. Prefer proper types over `# type: ignore`; use ignores only with a brief reason.

## Related

- [`ruff`](../ruff/SKILL.md) — lint/format (paired in `--quick`)
- [`uv`](../uv/SKILL.md) — installs `ty` via `--group dev`
