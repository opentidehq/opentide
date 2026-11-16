---
name: python-typing
description: Keep opentide typed — ty over the whole src/opentide package with no exclude list, annotation expectations, the typed boundaries (the `_native` stubs, the plugin API, the SDK), and the policy for casts and ignores. Use when ty reports a diagnostic (CI, pre-commit, ci-local.sh), when adding or changing typed code, or after a ty version bump.
---

# Python typing — opentide

The package is type-checked by [ty](https://docs.astral.sh/ty/): `[tool.ty.src]` includes
`src/opentide` and excludes nothing. Keep it that way: never add an exclusion. ty runs in
`scripts/ci-local.sh --quick`, the pre-commit hooks and the CI lint job
(`--output-format github` there).

ty checks the annotations that exist; it does not require them. Until ruff `ANN` is enabled
for `src/`, annotating new and touched functions is a review requirement.

## Writing typed code

- Annotate every parameter and return, including `-> None` and `__init__`.
- Prefer precise types: `Path` over `str` for paths, `Sequence`/`Mapping` for read-only
  inputs, `TypedDict` or a dataclass for structured dicts that cross module boundaries,
  `Literal[...]` for closed string sets, `Protocol` for duck-typed collaborators (SDK
  clients, fakes in tests).
- `Any` is allowed (`ANN401` is off) where the value really is arbitrary: parsed YAML/JSON
  payloads, vendor SDK objects without stubs. Narrow it at the boundary with `isinstance`
  rather than passing `Any` deeper.
- `from __future__ import annotations` is the norm, but pydantic models (a plugin's
  `configuration_model`) evaluate annotations at runtime: names used there must be importable at runtime, not only
  under `TYPE_CHECKING`.
- Python 3.10 is the floor: no `Self` from `typing` (use `typing_extensions`), no PEP 695
  `type X = ...` / `def f[T]()` syntax.

## Typed boundaries

The package is a thin layer over the Rust core; what ty sees of it comes from three places.

- **The compiled module's stubs** (`src/opentide/_native/`): `__init__.pyi` is written by
  hand, updated with every change to the binding; `models.pyi` and `sdk.pyi` are generated
  from the extension by `cargo xtask stubs` (`--check` in ci.yml's `stubs` job), never edited.
  A diagnostic about `opentide._native` is fixed in the stub (or by regenerating it), not
  ignored at the call site.
- **The plugin API** (`opentide.plugins`): frozen dataclasses (`Tenant`, `DeployRequest`,
  `DeployResult`, `QueryRequest`, `QueryResult`, `LiveCheck`, `ConfigurationFinding`) and the
  `Operation` literal. Tests build real `Tenant` objects, not `SimpleNamespace`.
- **The SDK** (`opentide.sdk`): every native call goes through `_call` (or `_document` for
  an awaitable), which turns the binding's `SdkError` into `OpentideError`; a new method
  keeps that shape and its annotations match the generated `sdk.pyi`.

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

`pyproject.toml` has no `[tool.ty.rules]`: every rule runs at ty's default level. Adding an
override is a decision of its own, with its reason in a comment there, never part of a fix.

## After a ty upgrade

ty is pre-1.0 and renames rules between patch releases. When a bump reds the lint job, read each
new diagnostic as in "Fixing a diagnostic" above: a renamed rule only matters where a
`# ty: ignore[<rule>]` names it (rename it there), a genuinely new finding is fixed in code. `uvx ty@<version> check src/opentide`
tries a version without touching the lockfile.

## Related

- [`ruff`](../ruff/SKILL.md) — `PGH` and the rest of the lint bar
- [`review-checklist`](../review-checklist/SKILL.md) — the definition of done
- [`uv`](../uv/SKILL.md) — upgrading ty through Dependabot
