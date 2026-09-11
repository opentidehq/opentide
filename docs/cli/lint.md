---
title: opentide lint
description: Catalogue hygiene — filename slugs and recommended metadata, distinct from schema validation.
---

# opentide lint

Convention checks that `opentide validate` does not cover. Lint does **not** replace `--strict` schema/graph validation.

```bash
opentide lint
opentide lint --check filenames
opentide lint --fix
opentide lint --strict
```

## Checks

| `--check` | What it does | `--fix` |
|----------|----------------|---------|
| `filenames` | Object YAML stem must equal `slugify(name)` | Renames files. On a collision in the same folder, appends `{uuid[:8]}` |
| `metadata` | Warns when `metadata.author` or `metadata.organisation` is missing | Not auto-fixed |

Default (no `--check`) runs both. YAML formatting, orphan doc pages, and vocabulary pin drift are not in this command yet.

Lint walks `objects/{threats,objectives,rules}/**/*.yaml` and does not rebuild the object registry.

## Flags

| Flag | Purpose |
|------|---------|
| `--check` | Repeatable. `filenames` or `metadata` |
| `--fix` | Apply safe filename renames |
| `--strict` | Exit `1` when any finding exists (CI gate). Default is report-only |

`--fix` is idempotent.

## Source

`src/opentide/cli/services/lint.py`
