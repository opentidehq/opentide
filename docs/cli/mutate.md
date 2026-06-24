---
title: opentide mutate
description: Bulk object mutations — promote status, rename, fix references, and security domain updates.
---

# opentide mutate

Bulk content mutations across the detection catalogue.

```bash
opentide mutate                    # run all mutation actions
opentide mutate promote
opentide mutate rename
opentide mutate references
opentide mutate security-domain
```

## Subcommands

| Subcommand | Purpose |
|------------|---------|
| *(default)* | Run all configured mutation actions |
| `promote` | Bulk status promotion |
| `rename` | Rename objects and update references |
| `references` | Fix or normalise cross-object references |
| `security-domain` | Update security domain fields |

Mutations modify YAML files in place. Commit results through your normal VCS workflow.

## Source

`src/opentide/cli/__init__.py`, `src/opentide/cli/services/mutate.py`
