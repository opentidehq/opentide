---
title: opentide extract
description: Import detection rules from Microsoft Sentinel and Defender for Endpoint.
---

# opentide extract

Import rules from external platforms into OpenTide object format.

```bash
opentide extract sentinel
opentide extract defender
```

## Subcommands

| Subcommand | Platform |
|------------|----------|
| `sentinel` | Microsoft Sentinel |
| `defender` | Microsoft Defender for Endpoint |

Imports require platform credentials configured under `.opentide/configurations/platforms/`.

Review and validate imported content before committing:

```bash
opentide validate --strict
```

## Source

`src/opentide/cli/__init__.py`, `src/opentide/cli/services/extraction.py`
