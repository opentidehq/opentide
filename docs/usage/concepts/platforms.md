---
title: Platforms
description: Nine deployment platforms, six query validators (five offline), eight query runners, and where each platform block schema is specified.
---

# Platforms

opentide integrates with **nine detection platforms** through connectors built into its Rust core. All ship in the base PyPI package; a Python package can add another as a [platform plugin](../../sdk/platforms.md#platform-plugins).

## Capability matrix

| Platform | CLI `--platform` | Deploy | Query validate (live) | Offline query check | [Query](../../cli/query.md) | Query language |
|----------|------------------|:------:|:--------------:|:------------:|:-----:|----------------|
| Microsoft Sentinel | `sentinel` | yes | yes | yes | yes | KQL |
| Defender for Endpoint | `defender_for_endpoint` | yes | yes | yes | yes | KQL |
| Elastic Security | `elastic` | yes | yes | yes | yes | Kuery / Lucene / EQL / ES\|QL |
| Splunk Enterprise Security | `splunk` | yes | yes | yes | yes | SPL |
| SentinelOne | `sentinel_one` | yes | yes | no | yes | S1QL |
| Carbon Black Cloud | `carbon_black_cloud` | yes | yes | yes | yes | Lucene |
| CrowdStrike Falcon | `crowdstrike` | yes | no | yes | yes | correlation rule (CQL) |
| HarfangLab | `harfanglab` | yes | no | no | telemetry filters | Sigma or YARA |
| Sysdig Secure (Falco) | `sysdig` | yes | no | yes | no | Falco condition |

The offline check is the analysis engine that ships with `pip install opentide` (`opentide validate`, `opentide validate query`, `opentide lint`, [`opentide lsp`](../../cli/lsp.md)): it parses each query in its language, with the platform's tables or dialect, and needs no tenant.

CLI `--platform` uses **registry keys** (`defender_for_endpoint`, `carbon_black_cloud`, `sentinel_one`). These are runtime identifiers; every platform ships with `pip install opentide`.

CrowdStrike stores a Next-Gen SIEM correlation rule, whose `query` is CrowdStrike Query Language (CQL, Falcon LogScale's language). The analysis engine checks it offline; opentide calls no CrowdStrike query check, so `validate query --platform crowdstrike --live` reports `supported: false`. HarfangLab stores a Sigma rule or a YARA rule, which is not syntax-checked: `opentide validate query --platform harfanglab` reports `supported: false`.

### CrowdStrike: the offline CQL checks

`opentide validate`, `validate query --platform crowdstrike`, `lint`, [`opentide lsp`](../../cli/lsp.md) and MCP `validate_query` parse `configurations.crowdstrike.query`, a hunt's query with `system: crowdstrike`, and a `.cql` file, following CrowdStrike's published grammar and function reference:

- A query that does not parse is a `cql_parse_error`.
- A function call is checked against the function reference: an unknown (`cql_unknown_function`, with the nearest name) or removed function, an unknown, repeated or missing parameter, a second unnamed argument, and a literal outside a parameter's allowed values are errors; a deprecated function is a warning.
- A correlation rule may not combine `correlate()` with another aggregate function (`cql_correlate_aggregate`), and `<=>` links fields only inside `correlate()`.
- A `#event_simpleName` no Falcon sensor event has is a warning, with the nearest event name.

Fields, saved searches (`$falcon/...()`), lookup files and repositories live in the tenant, so none is ever reported unknown, and the check cannot tell whether Next-Gen SIEM allows a function in a correlation rule. [Diagnostic codes](../../cli/diagnostics.md) lists every `cql_` code; each finding links [CrowdStrike's CQL reference](https://library.humio.com/crowdstrike-query-language/).

Every platform but Sysdig answers [`opentide query`](../../cli/query.md), which runs a read-only query on its tenants and returns the rows. CrowdStrike queries run on Next-Gen SIEM. HarfangLab has no query language for telemetry: a query names a telemetry source and field filters, and a HarfangLab rule has no query to run.

`validate query --platform elastic --live` previews the compiled rule in Kibana and runs the Elasticsearch pre-flight (ES|QL `LIMIT 0`, then `_field_caps` on aggregation fields). The same pre-flight runs before every Elastic deploy. Offline, the engine parses Kuery, Lucene, EQL and ES|QL, ES|QL against the stack versions of the block's tenants. See [Validate](../../cli/validate.md#elastic-live-validation-and-deploy).

Sysdig Secure runs Falco. A `sysdig` block is a Falco rule (a condition, its exceptions, and the macros and lists only that rule uses), which deploy creates through the Sysdig Secure runtime API and adds to the runtime policies the tenant or block names, keeping Sysdig's rule id in [deployment state](deployment-state.md). Deploy expands the block's own macros and lists into the condition and derives the Falco `desc`, `priority`, MITRE tags and a default `output` from the rule. The analysis engine checks the Falco condition offline; Sysdig has no rule preview, so `validate query --platform sysdig --live` reports `supported: false`. `deploy --dry-run` shows the API body.

Normative capability flags and the shared block: [Platforms spec](/docs/specifications/specs/platforms/).

## Platform block schemas

Every key on `configurations.<platform>`, required and optional, is specified under [Platforms](/docs/specifications/specs/platforms/). That directory is the contract. This page does not restate the fields. A block that passes `opentide validate` can still fail at deploy; each spec's Deploy section is that list.

<Cards>
  <Card title="Platforms" href="/docs/specifications/specs/platforms/" description="Shared fields, external rule ids, and the three checks: validate, load, deploy." />
  <Card title="Sentinel" href="/docs/specifications/specs/platforms/sentinel-1.0/" description="KQL analytics rule. Grouping is optional at validate and required at deploy." />
  <Card title="Defender for Endpoint" href="/docs/specifications/specs/platforms/defender-for-endpoint-1.0/" description="KQL custom detection, response actions, and the scope the loader requires." />
  <Card title="Splunk" href="/docs/specifications/specs/platforms/splunk-1.0/" description="SPL saved search." />
  <Card title="SentinelOne" href="/docs/specifications/specs/platforms/sentinel-one-1.0/" description="STAR rule: one S1QL query or a correlation of sub-queries." />
  <Card title="Carbon Black Cloud" href="/docs/specifications/specs/platforms/carbon-black-cloud-1.0/" description="Lucene IOC on an existing watchlist report." />
  <Card title="CrowdStrike" href="/docs/specifications/specs/platforms/crowdstrike-1.0/" description="Next-Gen SIEM correlation rule in CQL. Checked offline; no tenant query check." />
  <Card title="HarfangLab" href="/docs/specifications/specs/platforms/harfanglab-1.0/" description="Sigma or YARA. No query validator. Sigma wins when both are set." />
  <Card title="Sysdig Secure" href="/docs/specifications/specs/platforms/sysdig-1.0/" description="Custom Falco rule through the Sysdig Secure API. Block macros and lists are expanded at deploy." />
</Cards>

## Inspecting capabilities at runtime

```bash
opentide info
opentide --json info --platform sentinel
```

MCP resource: `opentide://platforms`

```python
from opentide import Workspace
ws = Workspace.open(".")
for platform in ws.info()["platforms"]:
    print(platform["name"], platform["enabled"], platform["can_deploy"], platform["can_validate"])
```

## Query validation policy

Only platforms with `can_validate=True` check queries on the tenant. CrowdStrike, HarfangLab and Sysdig have no tenant check: CLI and MCP return `supported: false` for them with `--live` (`live: true`), and for HarfangLab offline too — **never fake validation**. CrowdStrike's CQL and Sysdig's Falco conditions are checked offline only.

```bash
opentide validate query --platform crowdstrike          # the offline CQL check
opentide validate query --platform crowdstrike --live   # reports unsupported
opentide validate query --platform harfanglab           # reports unsupported
```

For the six that can, `opentide validate query` checks each query offline with
the analysis engine (every platform but SentinelOne, whose S1QL it does not
parse), and `--live` submits the catalogue queries to the tenants, which
requires credentials; every vendor SDK ships with `pip install opentide`. A
missing plan fails that check. Only the requested platform's engine is
imported, so a Sentinel run never loads the CrowdStrike or HarfangLab modules.
See [`validate`](../../cli/validate.md#query-validation).

## The `query` field

Where a platform spec marks `query` required, the value is a non-blank string. A Splunk block takes the [splunk-1.0](/docs/specifications/specs/platforms/splunk-1.0/) layout only: the `splunk::2.x` keys (`search`, `cron_schedule`, flat `throttling`, `notable`, `scheduling.frequency`, `advanced`, ...) are unknown keys, as every other unknown key is.

### Upgrading to 0.4.0

This is a **breaking change** for objects that previously passed validation:

| Object | Before 0.4.0 | From 0.4.0 |
|--------|--------------|------------|
| Splunk or Carbon Black rule with no `query` (and, for Splunk, no `search`) | Validated; the deployer skipped it silently | `opentide validate` reports `query: Field required` |
| Any platform with `query: ""` or whitespace only | Validated; the deployer skipped it silently | `opentide validate` reports `query must not be empty` |
| Splunk schedule with no `scheduling.type` | Saved with `cron_schedule` but never scheduled | Scheduled |

Every row that now fails was already a rule that never reached the platform. Run `opentide validate` after upgrading to find them.

## Platform configuration

Per-platform settings live under `.opentide/configurations/platforms/`. Enable platforms with `opentide setup platforms` or the parent `opentide setup --platform` flags; only enabled platforms are deployed to and validated.

## Live deploy dependencies

Validate, generate, dry-run deploy and live deploy all work with `pip install opentide` alone: no vendor SDK is needed.

## SDK access

Deploy and validate programmatically with [`opentide.Workspace`](../../sdk/workspace.md) and its tenant operations — see [SDK platforms](../../sdk/platforms.md).
