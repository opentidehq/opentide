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

### Case-insensitive filesystems

On macOS and Windows, `Objects/` and `objects/` are the same folder, so the moves land inside the legacy `Objects/` folder. The command then renames that folder to `objects/`, so a case-sensitive checkout such as a Linux CI runner finds it. The `--json` output lists the rename under `case_renamed`, in the dry-run too. Anything left in `Objects/` (the legacy folders after `--copy`, or folders the command does not migrate) ends up in `objects/` too, because the two names cannot exist side by side on these filesystems. The rename goes through a temporary `Objects.opentide-case-rename/` folder; if one is left over from an interrupted run, the command keeps `Objects/` and says so under `warnings`. That leftover can hold your files: check it before you delete it. On these filesystems the command also lower-cases an object folder such as `objects/Rules`, and repairs a repository an earlier release migrated into `Objects/`.

A repository that an earlier release migrated on macOS or Windows can still have `objects/threats/`, `objects/objectives/` or `objects/rules/` inside a folder named `Objects/`, with no legacy folders left to move. Run `opentide migrate objects --apply` again to rename `Objects/` to `objects/`. Git tracks those files under `Objects/`, so then follow the check below.

Git keeps the folder case it recorded while the folder still has tracked files, which is the case after `--copy` or when files stay behind. Check before you commit:

```bash
git add -A
git ls-files Objects             # prints nothing once git records objects/
# only when it printed files:
git rm -r --cached -q Objects
git add objects
```

## Flags

| Flag | Purpose |
|------|---------|
| `--apply` | Perform the planned operations |
| `--copy` | Copy instead of move |

## Source

`src/opentide/cli/services/migrate_objects.py`
