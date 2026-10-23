---
name: ruff
description: Lint and format opentide with ruff — one rule set for the package, tests and scripts (no excluded modules), what each selected family guards against, how to fix findings safely and when a noqa is acceptable. Use when ruff check or ruff format fails locally, in pre-commit or in CI, or when changing the ruff configuration.
---

# Ruff — opentide

`pyproject.toml` → `[tool.ruff]`. Every file under `src/opentide`, `tests` and `scripts` is linted and
formatted with the same configuration; there is no exclude list, only the few documented
`per-file-ignores`.

```bash
uv run ruff check src/opentide tests scripts
uv run ruff format --check src/opentide tests scripts   # CI form
uv run ruff check --fix src/opentide tests scripts && uv run ruff format src/opentide tests scripts
scripts/ci-local.sh --quick                         # ruff + ty + build
```

The pre-commit hooks run the same ruff (`uv run ruff`, pinned by `uv.lock`) on staged files.

## Selected rules and why

| Family | Guards against |
|--------|----------------|
| `E`, `F`, `I`, `UP`, `B`, `SIM` | errors, unused names, import order, outdated syntax, bugbear, simplifications |
| `ISC` | implicit string concatenation, e.g. a missing comma (`ISC004` is off: parenthesising every multi-line string in a list was churn) |
| `PIE` | duplicate enum values, needless placeholders |
| `RUF` | mutable class/`fromkeys` defaults, unused `noqa`, ambiguous characters |
| `PLE`, `PLW1510` | pylint errors; `subprocess.run` without `check=` |
| `DTZ` | naive datetimes |
| `PGH` | blanket `# noqa` / `# type: ignore` |
| `T20` | `print()` — output goes through `opentide.core.logging` (stderr) or `opentide.cli.output` |
| `TID251` | banned APIs: a plain `requests.Session` in `platforms/` instead of `TenantSession` |
| `C4`, `FURB`, `ERA`, `G`, `LOG` | comprehensions, modern idioms, commented-out code, logging calls |

`per-file-ignores` (each commented in `pyproject.toml`): `T201` for the few entry points
whose job is to print and for `scripts/`; `TID251` outside `src/opentide/platforms/`;
`PLW1510`/`RUF012` in tests.

Next candidates, not yet on: `ANN` for `src/` (about 140 unannotated functions) and `PT`
for tests. Turn one on only together with its fixes.

`typer.Option`/`typer.Argument` are configured as immutable calls, so Typer's call defaults
don't trip `B008`.

## Fixing findings

1. `ruff check --fix` applies safe fixes only. `--unsafe-fixes` is allowed for a named rule
   (`--select RULE --fix --unsafe-fixes`) after reading the diff.
2. Long string literals: split into implicit concatenation inside parentheses. Never wrap the
   *second* half of an existing concatenation in parentheses — `"a " ("b")` is a call on a
   string and fails at runtime, not at lint time.
3. After any mechanical change across many files, prove it is behaviour-preserving:
   `uv run python scripts/ast_equivalence.py <base-rev>` lists files whose AST changed
   (imports and annotations ignored). Expect only the files you changed on purpose.
4. A `# noqa: RULE` needs a reason on the same line (`# noqa: T201 -- the CLI's one stdout
   writer`). Blanket `# noqa` is rejected (`PGH004`); stale ones are reported (`RUF100`).

## Changing the configuration

Add a rule family only with its findings fixed in the same change. Prefer rules that catch
defects over pure style; record why in the table above.

## Related

- [`python-typing`](../python-typing/SKILL.md) — ty
- [`review-checklist`](../review-checklist/SKILL.md) — what lint cannot see
- [`uv`](../uv/SKILL.md) — hooks and `ci-local.sh`
