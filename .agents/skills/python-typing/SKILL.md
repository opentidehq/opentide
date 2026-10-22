---
name: python-typing
description: Keep opentide fully typed — ty over the whole src/opentide package with no excluded modules, ruff ANN for annotation coverage, and the policy for casts and ignores. Use when ty reports a diagnostic (CI, pre-commit, ci-local.sh), when adding or changing typed code, or after a ty version bump.
---

# Python typing — opentide

The package is type-checked by [ty](https://docs.astral.sh/ty/) end to end: `[tool.ty.src]`
includes `src/opentide` and excludes nothing. Two checks keep it that way:

| Check | Guarantees |
|-------|------------|
| `uv run ty check src/opentide` | the annotations that exist are consistent |
| ruff `ANN` (on `src/`) | every function has parameter and return annotations, so ty has something to check |

Both run in `scripts/ci-local.sh --quick`, the pre-commit hooks and the CI lint job
(`--output-format github` there). The only per-file relief is `ANN` in `tests/`.

## Writing typed code

- Annotate every parameter and return, including `-> None` and `__init__`.
- Prefer precise types: `Path` over `str` for paths, `Sequence`/`Mapping` for read-only
  inputs, `TypedDict` or a dataclass for structured dicts that cross module boundaries,
  `Literal[...]` for closed string sets, `Protocol` for duck-typed collaborators (SDK
  clients, fakes in tests).
- `Any` is allowed (`ANN401` is off) where the value really is arbitrary: parsed YAML/JSON
  payloads, vendor SDK objects without stubs. Narrow it at the boundary with `isinstance`
  rather than passing `Any` deeper.
- `from __future__ import annotations` is the norm, but pydantic models and Typer commands
  evaluate annotations at runtime: names used there must be importable at runtime, not only
  under `TYPE_CHECKING`.
- Python 3.10 is the floor: no `Self` from `typing` (use `typing_extensions`), no PEP 695
  `type X = ...` / `def f[T]()` syntax.

## Fixing a diagnostic

1. Read it as a possible bug first. `possibly-missing-attribute` on `x.y` where `x` can be
   `None` is often a real crash path (e.g. an optional YAML block that loads as `None`).
2. Fix with narrowing (`if x is None: raise/return`, `isinstance`), a more precise
   annotation, or a small typed helper.
3. `cast()` only when it is provably true and ty cannot see why; say why in a comment.
4. Suppress only when ty is wrong: `# ty: ignore[<rule>]` with the reason on the same line.
   Never a bare `# type: ignore` (`PGH003` rejects it) and never a blanket rule disable to
   silence one site.
5. Refactors done for typing must not change behaviour: run the module's tests, and for
   larger mechanical edits `uv run python scripts/ast_equivalence.py <base>`.

## Project-wide rule settings

`[tool.ty.rules]` in `pyproject.toml`, each with its reason in a comment there:

- `invalid-method-override = "warn"` — Tide domain models deliberately shadow pydantic's
  `BaseModel.validate`.
- `invalid-property-type-override`, `invalid-attribute-override`, `invalid-mutable-override`
  = `"ignore"` — per-platform system configs narrow the nested `SystemConfig.Tenant` types;
  ty reports the same sites under all three names.
- `redundant-cast = "ignore"`.

## After a ty upgrade

ty is pre-1.0 and renames rules between patch releases. When a bump reds the lint job, compare
the reported sites with the ones above before changing code — a rename is fixed in
`[tool.ty.rules]`, a genuinely new finding in code. `uvx ty@<version> check src/opentide`
tries a version without touching the lockfile.

## Related

- [`ruff`](../ruff/SKILL.md) — `ANN`, `PGH` and the rest of the lint bar
- [`review-checklist`](../review-checklist/SKILL.md) — the definition of done
- [`uv`](../uv/SKILL.md) — upgrading ty through Dependabot
