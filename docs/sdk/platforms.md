---
title: Platforms API
description: Platform registry, entry-point plugins, deployers, and query validators.
---

# Platforms API

Platforms register through setuptools entry points in `pyproject.toml`:

```toml
[project.entry-points."opentide.platforms"]
sentinel = "opentide.platforms.sentinel:declare"
splunk = "opentide.platforms.splunk:declare"
# …
```

## PlatformsRegistry

```python
from opentide import OpenTide

OpenTide.initialise()
for name, platform in OpenTide.Platforms.items():
    print(name, platform.enabled, platform.can_deploy, platform.can_validate)
```

## Platform dataclass

| Field | Description |
|-------|-------------|
| `name` | Registry key (e.g. `defender_for_endpoint`) |
| `enabled` | Whether platform is active in client config |
| `config` | Loaded platform configuration |
| `deployer` | Rule deployer instance or None |
| `validator` | Query validator instance or None |
| `can_deploy` | Property — deployer present |
| `can_validate` | Property — validator present |

## Query validators

Five platforms register validators (see `QUERY_VALIDATION_PLATFORMS` in `opentide.cli.enums`):

- `sentinel` → KQL
- `defender_for_endpoint` → KQL
- `splunk` → SPL
- `sentinel_one` → S1QL
- `carbon_black_cloud` → Lucene

CrowdStrike and HarfangLab have deployers only.

## Rule deployment

```python
rule = OpenTide.Rules[uuid]
result = rule.deploy("sentinel", dry_run=True)
print(result.dry_run, result.message)
```

## Plugin declaration

Each platform module exposes `declare()` returning deployer/validator factories. Client enablement is read from `.opentide/configurations/platforms/`.

## Capability matrix

Human-readable table: [Usage: Platforms](../usage/concepts/platforms.md).

## Source

`src/opentide/platforms/registry.py`, `src/opentide/platforms/plugins.py`
