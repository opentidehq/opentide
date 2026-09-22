---
title: Platforms
description: Seven deployment platforms and five query validators — capability matrix and CLI identifiers.
---

# Platforms

OpenTide integrates with **seven detection platforms** through built-in adapters registered at import time (`opentide.platforms` entry points). All ship in the base PyPI package.

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

CLI `--platform` uses **registry keys** (`defender_for_endpoint`, `carbon_black_cloud`, `sentinel_one`). These are runtime identifiers — not pip install extras.

Normative capability flags: [Platforms spec](/docs/specifications/specs/platforms/).

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

For the five that can, validation is **offline by default**: a structural check
of the query language that needs no vendor SDK and no tenant. Pass `--live` to
submit the query to the platform instead, which requires the matching extra and
credentials. Only the requested platform's engine is imported, so a Sentinel run
never loads the CrowdStrike or HarfangLab modules. See
[`validate`](../../cli/validate.md#query-validation).

## The `query` field

The five platforms that carry a query string — Sentinel, Defender for Endpoint, Splunk, CrowdStrike, and Carbon Black Cloud — all declare `query` **required and non-blank**. Templates show it uncommented for each of them.

Splunk `splunk::2.x` objects used a flat layout: `search` for the search string, `cron_schedule` for the schedule, and top-level `throttling`, `threshold`, `notable`, `risk`, and `email`, with `frequency` / `lookback` directly under `scheduling`. All of these are still accepted. `opentide validate` and `opentide deploy` map them onto the v3 layout with the same function, so a 2.x rule validates exactly when it deploys. `search` and `cron_schedule` stay on the object so it round-trips unchanged. A `query` or `scheduling.schedule` set explicitly wins over the legacy key.

A Splunk `scheduling.schedule` is deployed as a scheduled search whether or not `scheduling.type` is set; only `type: Real Time` opts out.

### Upgrading to 0.4.0

This is a **breaking change** for objects that previously passed validation:

| Object | Before 0.4.0 | From 0.4.0 |
|--------|--------------|------------|
| Splunk or Carbon Black rule with no `query` (and, for Splunk, no `search`) | Validated; the deployer skipped it silently | `opentide validate` reports `query: Field required` |
| Any platform with `query: ""` or whitespace only | Validated; the deployer skipped it silently | `opentide validate` reports `query must not be empty` |
| splunk::2.x rule with `search` / `cron_schedule` | Loaded with no query and no schedule; skipped silently | Deploys the search on its schedule |
| splunk::2.x rule with flat `throttling` / `notable` / `scheduling.frequency` | Deployed, but `opentide validate` rejected the keys | Validates and deploys |
| Splunk schedule with no `scheduling.type` | Saved with `cron_schedule` but never scheduled | Scheduled |

Every row that now fails was already a rule that never reached the platform. Run `opentide validate` after upgrading to find them.

## Platform configuration

Per-platform settings live under `.opentide/configurations/platforms/`. Enable platforms with `opentide setup platforms` or the parent `opentide setup --platform` flags; the registry loads deployers and validators for enabled systems only.

## Live deploy dependencies

Validate, generate, and dry-run deploy work with `pip install opentide` alone. **Live** API deploy to Splunk or Carbon Black may require additional vendor SDKs — see [Installation](../installation.md).

## SDK access

Deploy and validate programmatically via `OpenTide.Platforms` — see [SDK platforms](../../sdk/platforms.md).
