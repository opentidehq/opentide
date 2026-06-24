---
title: opentide migrate
description: Scan and rewrite legacy CoreTide submodule imports and Orchestration script invocations.
---

# opentide migrate

Scan or rewrite legacy submodule imports and Orchestration script calls.

```bash
opentide migrate --check     # report findings, no changes
opentide migrate --apply     # rewrite known patterns in place
```

## Options

| Flag | Purpose |
|------|---------|
| `--check` | Report legacy patterns without modifying files |
| `--apply` | Rewrite known legacy imports and script calls |

When neither flag is set, behaves like `--check`.

## Patterns handled

- `Engines.modules.*` imports → `opentide` equivalents
- `Orchestration/*.py` invocations → documented CLI replacements

Always review `jj diff` or your VCS diff after `--apply`.

## Usage guide

Full migration walkthrough: [Migration guide](../usage/migration/index.md)

## Source

`src/opentide/cli/__init__.py`, `src/opentide/cli/migrate.py`
