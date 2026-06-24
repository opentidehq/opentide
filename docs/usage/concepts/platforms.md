---
title: Platforms
description: Seven deployment platforms and five query validators — capability matrix and CLI identifiers.
---

# Platforms

OpenTide integrates with **seven detection platforms** through entry-point plugins registered at install time.

## Capability matrix

| Platform | CLI `--platform` | Deploy | Query validate | Query language |
|----------|------------------|:------:|:--------------:|----------------|
| Microsoft Sentinel | `sentinel` | yes | yes | KQL |
| Defender for Endpoint | `defender_for_endpoint` | yes | yes | KQL |
| Splunk Enterprise Security | `splunk` | yes | yes | SPL |
| SentinelOne | `sentinel_one` | yes | yes | S1QL |
| Carbon Black Cloud | `carbon_black_cloud` | yes | yes | Lucene |
| CrowdStrike Falcon | `crowdstrike` | yes | no | — |
| HarfangLab | `harfanglab` | yes | no | — |

CLI `--platform` uses **registry keys** (`defender_for_endpoint`, `carbon_black_cloud`). PyPI install extras remain `defender` and `carbon-black` — those are not `--platform` values.

## Inspecting capabilities at runtime

```bash
opentide info
opentide --json info --platform sentinel
```

MCP resource: `opentide://platforms`

```python
from opentide import OpenTide
OpenTide.initialise()
for name, plat in OpenTide.Platforms.items():
    print(name, plat.enabled, plat.can_deploy, plat.can_validate)
```

## Query validation policy

Only platforms with `can_validate=True` run syntax validation. For CrowdStrike and HarfangLab, CLI and MCP return `supported: false` — **never fake validation**.

```bash
opentide validate query --platform crowdstrike   # reports unsupported
```

## Platform configuration

Per-platform settings live under `.opentide/configurations/platforms/`. Enable platforms in client config; the registry loads deployers and validators for enabled systems only.

## PyPI extras

Install platform extras to pull optional SDK dependencies:

```bash
pip install "opentide[sentinel,splunk,carbon-black]>=0.1"
```

See [Installation](../installation.md) for the full extras table.

## SDK access

Deploy and validate programmatically via `OpenTide.Platforms` — see [SDK platforms](../../sdk/platforms.md).
