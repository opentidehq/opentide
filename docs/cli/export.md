---
title: opentide export
description: Export ATT&CK Navigator layers, object dumps, revision snapshots, and playbook maps.
---

# opentide export

Export catalogue data for external tools and reporting.

```bash
opentide export navigator
opentide export objects
opentide export revisions
opentide export playbook-map
```

## Subcommands

| Subcommand | Purpose |
|------------|---------|
| `navigator` | ATT&CK Navigator layer JSON |
| `objects` | Object catalogue export |
| `revisions` | Revision snapshot export |
| `playbook-map` | Playbook mapping export |

Output paths follow configuration under `.opentide/` exports and `global.toml` paths.

## Source

`src/opentide/cli/__init__.py`, `src/opentide/cli/services/export.py`
