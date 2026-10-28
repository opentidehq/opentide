---
title: Platforms
description: Eight deployment platforms, six query validators (five offline), eight query runners, and where each platform block schema is specified.
---

# Platforms

opentide integrates with **eight detection platforms** through built-in adapters registered at import time (`opentide.platforms` entry points). All ship in the base PyPI package.

## Capability matrix

| Platform | CLI `--platform` | Deploy | Query validate (live) | Offline query check | [Query](../../cli/query.md) | Query language |
|----------|------------------|:------:|:--------------:|:------------:|:-----:|----------------|
| Microsoft Sentinel | `sentinel` | yes | yes | yes | yes | KQL |
| Defender for Endpoint | `defender_for_endpoint` | yes | yes | yes | yes | KQL |
| Elastic Security | `elastic` | yes | yes | yes | yes | Kuery / Lucene / EQL / ES\|QL |
| Splunk Enterprise Security | `splunk` | yes | yes | yes | yes | SPL |
| SentinelOne | `sentinel_one` | yes | yes | no | yes | S1QL |
| Carbon Black Cloud | `carbon_black_cloud` | yes | yes | yes | yes | Lucene |
| CrowdStrike Falcon | `crowdstrike` | yes | no | no | yes | correlation filter (CQL) |
| HarfangLab | `harfanglab` | yes | no | no | telemetry filters | Sigma or YARA |

The offline check is the analysis engine that ships with `pip install opentide` (`opentide validate query`, `opentide validate --deep`, [`opentide lsp`](../../cli/lsp.md)): it parses each query in its language, with the platform's tables or dialect, and needs no tenant.

CLI `--platform` uses **registry keys** (`defender_for_endpoint`, `carbon_black_cloud`, `sentinel_one`). These are runtime identifiers; every platform ships with `pip install opentide`.

CrowdStrike stores a correlation filter. HarfangLab stores a Sigma rule or a YARA rule. Neither language is syntax-checked: `opentide validate query` reports `supported: false`.

Every platform answers [`opentide query`](../../cli/query.md), which runs a read-only query on its tenants and returns the rows. CrowdStrike queries run on Next-Gen SIEM. HarfangLab has no query language for telemetry: a query names a telemetry source and field filters, and a HarfangLab rule has no query to run.

`validate query --platform elastic --live` previews the compiled rule in Kibana and runs the Elasticsearch pre-flight (ES|QL `LIMIT 0`, then `_field_caps` on aggregation fields). The same pre-flight runs before every Elastic deploy. Offline, the engine parses Kuery, Lucene, EQL and ES|QL, ES|QL against the stack versions of the block's tenants. See [Validate](../../cli/validate.md#elastic-live-validation-and-deploy).

Normative capability flags and the shared block: [Platforms spec](/docs/specifications/specs/platforms/).

## Platform block schemas

Every key on `configurations.<platform>`, required and optional, is specified under [Platforms](/docs/specifications/specs/platforms/). That directory is the contract. This page does not restate the fields. A block that passes `opentide validate` can still fail at deploy; each spec's Deploy section is that list.

<Cards>
  <Card title="Platforms" href="/docs/specifications/specs/platforms/" description="Shared fields, external rule ids, and the three checks: validate, load, deploy." />
  <Card title="Sentinel" href="/docs/specifications/specs/platforms/sentinel-1.0/" description="KQL analytics rule. Grouping is optional at validate and required at deploy." />
  <Card title="Defender for Endpoint" href="/docs/specifications/specs/platforms/defender-for-endpoint-1.0/" description="KQL custom detection, response actions, and the scope the loader requires." />
  <Card title="Splunk" href="/docs/specifications/specs/platforms/splunk-1.0/" description="SPL saved search, including the splunk::2.x keys that still normalise." />
  <Card title="SentinelOne" href="/docs/specifications/specs/platforms/sentinel-one-1.0/" description="STAR rule: one S1QL query or a correlation of sub-queries." />
  <Card title="Carbon Black Cloud" href="/docs/specifications/specs/platforms/carbon-black-cloud-1.0/" description="Lucene IOC on an existing watchlist report." />
  <Card title="CrowdStrike" href="/docs/specifications/specs/platforms/crowdstrike-1.0/" description="Correlation filter. No query validator." />
  <Card title="HarfangLab" href="/docs/specifications/specs/platforms/harfanglab-1.0/" description="Sigma or YARA. No query validator. Sigma wins when both are set." />
</Cards>

## Inspecting capabilities at runtime

```bash
opentide info
opentide --json info --platform sentinel
```

MCP resource: `opentide://platforms`

```python
from opentide import Opentide
Opentide.initialise()
for name, plat in Opentide.Platforms.items():
    print(name, plat.enabled, plat.can_deploy, plat.can_validate)
```

## Query validation policy

Only platforms with `can_validate=True` run syntax validation. For CrowdStrike and HarfangLab, CLI and MCP return `supported: false` — **never fake validation**.

```bash
opentide validate query --platform crowdstrike   # reports unsupported
```

For the six that can, `opentide validate query` checks each query offline with
the analysis engine (every platform but SentinelOne, whose S1QL it does not
parse), and `--live` submits the catalogue queries to the tenants, which
requires credentials; every vendor SDK ships with `pip install opentide`. A
missing plan fails that check. Only the requested platform's engine is
imported, so a Sentinel run never loads the CrowdStrike or HarfangLab modules.
See [`validate`](../../cli/validate.md#query-validation).

## The `query` field

Where a platform spec marks `query` required, the value is a non-blank string. Splunk still accepts the `splunk::2.x` layout and normalises it before validation; the mapping is [splunk-1.0](/docs/specifications/specs/platforms/splunk-1.0/).

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

Deploy and validate programmatically via `Opentide.Platforms` — see [SDK platforms](../../sdk/platforms.md).
