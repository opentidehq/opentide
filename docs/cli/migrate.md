---
title: opentide migrate
description: Move legacy Configurations/, Objects/, and .opentide/framework paths into the greenfield layout.
---

# opentide migrate

Layout migration for detection repositories that still use CoreTide directory names. This does **not** replace a CoreTide git submodule or Orchestration scripts — see the [migration guide](../usage/migration/index.md) for that.

```bash
opentide migrate objects            # dry-run (default)
opentide migrate objects --apply    # move
opentide migrate objects --apply --copy
```

## migrate objects

Moves (or copies) well-known legacy directories:

| From | To |
|------|----|
| `Configurations/` | `.opentide/configurations/` |
| `.opentide/framework/schemas/` | `.opentide/schemas/` |
| `.opentide/framework/templates/` | `.opentide/templates/` |
| `Objects/Threat Vectors/` | `objects/threats/` |
| `Objects/Detection Objectives/` | `objects/objectives/` |
| `Objects/Detection Rules/` | `objects/rules/` |

Default is a **dry-run**. Pass `--apply` to execute. `--copy` keeps the source tree.

Existing non-empty destinations are skipped (never overwritten). Empty destination directories are replaced. After a move, empty `Objects/` and `.opentide/framework/` parents are removed.

## Flags

| Flag | Purpose |
|------|---------|
| `--apply` | Perform the planned operations |
| `--copy` | Copy instead of move |

## Source

`src/opentide/cli/services/migrate_objects.py`
