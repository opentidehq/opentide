# Ruff — OpenTide

Lint and format for `tests/` and typed core under `src/opentide/`. Large ported modules are excluded until actively cleaned up.

## When to use

- Ruff check or format failures locally or in CI
- Pre-commit hook failures on `ruff` / `ruff-format`
- Iterating on lint fixes before push

## Commands (match CI)

```bash
uv sync --group dev
uv run ruff check tests src/opentide
uv run ruff format --check tests src/opentide   # CI uses --check
uv run ruff format tests src/opentide           # apply formatting
```

Fast path: `scripts/ci-local.sh --quick` (ruff + ty, no pytest).

## Scope

Configured in `pyproject.toml` → `[tool.ruff]`:

- **Paths:** `src`, `tests` (via `src = ["src", "tests"]`)
- **Exclude:** ported platform/deployer modules, legacy indexing/loading/generation paths (see `exclude` list)
- **Rules:** `E`, `F`, `I`, `UP`, `B`, `SIM`
- **Per-file ignores:** generation pipeline, CLI services, MCP server (behavioural preservation)

Do **not** expand lint scope in unrelated PRs.

## Fix workflow

1. Run `uv run ruff check tests src/opentide` — note findings.
2. Apply safe fixes: `uv run ruff check tests src/opentide --fix`
3. Format: `uv run ruff format tests src/opentide`
4. Re-run check until clean.
5. If unsafe fixes needed: `--fix --unsafe-fixes` — review diff carefully.
6. Use `# noqa: RULE` only when suppression is justified (narrow, documented).

For iterative autofix patterns, see the stub at [`.agents/skills/ruff-recursive-fix/`](../ruff-recursive-fix/SKILL.md) (upstream reference).

## Hooks and CI

- **pre-commit:** `ruff` (with `--fix`) and `ruff-format` on staged files
- **CI:** `.github/workflows/ci.yml` lint job — same paths, format with `--check`
- **pre-push:** `scripts/ci-local.sh --full` when code or CI config changes

## Related

- [`python-typing`](../python-typing/SKILL.md) — ty (runs alongside ruff in `--quick`)
- [`uv`](../uv/SKILL.md) — `uv run` / dev dependencies
