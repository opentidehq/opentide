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
| Exabeam New-Scale SIEM | `exabeam` | yes | yes (the filter) | no | yes | Exabeam Query Language |
| Google Security Operations | `google_secops` | yes | yes (`verifyRuleText`) | no | yes (`udmSearch`) | YARA-L 2.0 |

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

Exabeam New-Scale SIEM takes correlation rules. An `exabeam` block is one rule: one or more `sequences`, each a filter in the Exabeam Query Language (profile `rule`) that triggers on any matching event or on a `threshold` (`count`, `unique_count`, `value`, `max`, `min`, `sum` or `average` with `more_than`, `less_than`, `in` or `not_in`, within a window). Two or more sequences correlate within `correlation.within`, optionally on common fields, in the order they are written. `outcome` is `alert` (the default), `case` or `none`, with an optional `email`, `suppression`, `delay` (7 to 180 minutes) and `schedule`. Durations are a whole number and one unit (`30m`, `4h`, `1d`, and `2w` for `suppression.for`).

```yaml
configurations:
  exabeam:
    schema: platform::exabeam::1.0
    status: STAGING
    outcome: case
    sequences:
      - name: Failed logins from outside
        query: |
          activity_type:"app-login" AND outcome:"fail"
          AND NOT src_ip:[10.0.0.0/8]
        group_by: [src_ip]
        threshold:
          function: unique_count
          field: user
          operator: more_than
          value: 3
          within: 30m
    suppression:
      for: 1h
      group_by: [src_ip]
```

Deploy derives the Exabeam rule name (the block's `name`, else the rule's), the description (whitespace collapsed, then an `ATT&CK:` line and an `opentide: <uuid>` line) and the severity (`none` to `critical`, from `response.alert_severity` unless the block sets it). It creates, updates and deletes through the Correlation Rules API, always sending the whole rule; `DISABLEMENT` is the same `PUT` with `enabled: false`. The rule UUID is kept in [deployment state](deployment-state.md). Before a create, deploy checks that no Exabeam rule has the name, case-insensitively, and fails with `exabeam_name_conflict` rather than adopt one; a create with no answer, or a server error, is never sent again (`exabeam_create_unconfirmed`). Requests are paced to 100 a minute across every Exabeam tenant of a run, and a `429` is waited out. A tenant names its API `region` (`us-west`, `us-east`, `ca`, `eu`, `sa`, `sg`, `ch`, `jp`, `au` or `uk`; calls go to `https://api.<region>.exabeam.cloud`), or an `api_url`, and its `client_id` and `client_secret` as `$VAR`s; `test_mode = true` deploys every block that does not set `test_mode` in test mode.

`opentide validate` checks the block (the `exabeam_*` codes) and two enabled blocks sharing a name (`exabeam_name_duplicate`). It warns, as `opentide lint` does, on `outcome: none` without an `email` (`exabeam_outcome_silent`: nobody is told when the rule triggers) and on a `correlation.within` that is not more than the ordered sequences need, their windows plus a minute between sequences (`exabeam_correlation_window`). `validate query --platform exabeam --live` sends each sequence filter to Exabeam Search over the last 15 minutes: Exabeam has no rule preview, so the condition, windows and grouping are not checked on the tenant. [`opentide query --platform exabeam`](../../cli/query.md) runs a `system: exabeam` hunt through Search, at most 3,000 rows. `deploy --dry-run` shows the create request.

Google Security Operations (Google SecOps, formerly Chronicle) takes YARA-L 2.0 custom rules. A `google_secops` block carries the rule's sections as keys: `events`, `outcome` and `condition` (and `setup`, `export`) as YARA-L text, written as block scalars, and `match` and `options` as YAML objects. Deploy assembles the rule from them: `rule <name> {`, a `meta` section it derives from the rule (author, description, severity, priority, the ATT&CK `technique` list Google's coverage matrix reads, `opentide_uuid` and `opentide_version`, then the block's own `meta`), then each section under its label. The rule name is the block's `name`, else the rule's title in `snake_case`.

```yaml
configurations:
  google_secops:
    schema: platform::google_secops::1.0
    status: PRODUCTION
    run_frequency: LIVE_CUSTOMIZABLE
    events: |
      $fail.metadata.event_type = "USER_LOGIN"
      $fail.security_result.action = "BLOCK"
      $fail.target.user.userid = $user
      $success.metadata.event_type = "USER_LOGIN"
      $success.security_result.action = "ALLOW"
      $success.target.user.userid = $user
    match:
      group_by: [$user]
      window: 30m
    outcome: |
      $risk_score = max(80)
    condition: |
      #fail >= 10 and $success
    options:
      suppression_window: 1h
```

`condition` is a block scalar on purpose: `condition: #fail >= 10 and $success` as a plain scalar is a YAML comment, loads as null, and fails with `yaral_section_empty`. `opentide validate` checks the block's constraints (`google_secops_rule_name`, `google_secops_severity`, `google_secops_run_frequency`, `google_secops_schedule`, `google_secops_meta_key`) and the sections' structure (`yaral_section_missing`, `yaral_section_empty`, `yaral_section_header`, `yaral_match_shape`, `yaral_match_window`, `yaral_option`), each at its field path, and that no two enabled blocks share a rule name, ignoring case (`google_secops_name_duplicate`). It warns, as `opentide lint` does, when `outcome` assigns no `$risk_score` (Google then gives every detection the instance's default score, 40 for an alert and 15 otherwise unless the instance's settings change them), when a rule matches a producer by a literal `ru_…` id, and on `run_frequency: LIVE` for a rule with two or more event variables, which deploy refuses because Google allows `LIVE` for single-event rules only (write `LIVE_CUSTOMIZABLE`).

Deploy goes through the Chronicle API v1 and keeps Google's rule id (`ru_<uuid>`) in [deployment state](deployment-state.md); it never lists rules. Every create and every changed text is compiled by `verifyRuleText` first, and an unchanged text is not sent again, so the rule keeps its revision (a new revision is re-initialised for about an hour). A bound rule is read with its deployment, unarchived first when archived, then its text, its `scope` and its run state are each updated only where they differ. A `PREVIEW` rule runs without alerting, `RELEASE` and `UNIVERSAL` alert, `DISABLEMENT` disables, even when the rule's new text fails `verifyRuleText` or its update (the failure is still reported, and an archived rule is left archived), and `DELETION` archives the rule, or deletes it without `force` when the tenant's `deletion = "delete"`, archiving it instead when Google refuses (any 4xx but 401, 403, 404 and 429): deploy never deletes a rule's detections. `runFrequency` is sent only when the block names `run_frequency`: otherwise Google keeps the rule's frequency, or gives a new rule its default, and never moves a rule off a legacy schedule, which it cannot undo. A block `schedule` is compared as Google stores it, and removed from the rule when removed from the block. `data_access_scope` is a data access scope id or its full resource name; a changed or removed one reaches every rule. Credentials are a service-account key, or Application Default Credentials (a service-account key, a gcloud user login or the metadata server), applied with their quota project; a token that cannot be obtained stops the tenant before any request (`google_secops_tenant_unauthorized`). A 429, or a 503 on any call but a create, is waited out (`Retry-After`, else Google's `RetryInfo`, else 5, 15 and 60 seconds, three resends at most); a create is never resent after a 5xx or no answer (`google_secops_create_unconfirmed`). Deploy warns when Google reports a bound rule's execution as limited or paused (`google_secops_rule_execution_limited`) or its compilation as failed (`google_secops_rule_compilation_failed`). It manages custom rules and their deployment only: curated rules, rule exclusions, reference lists, data tables, retrohunts and rule tests stay in the console. `validate query --platform google_secops --live` sends each rule to `verifyRuleText`, which compiles it with the instance's reference lists and data tables and creates nothing, and places each diagnostic on its section key and line. [`opentide query`](../../cli/query.md) runs a YARA-L search through `udmSearch`; `--rule` is not supported. `deploy --dry-run` shows the assembled rule.

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
  <Card title="Exabeam New-Scale SIEM" href="/docs/specifications/specs/platforms/exabeam-1.0/" description="Correlation rule: sequences of Exabeam Query Language filters, through the Correlation Rules API." />
  <Card title="Google Security Operations" href="/docs/specifications/specs/platforms/google-secops-1.0/" description="YARA-L 2.0 rule written as sections, assembled with derived meta, through the Chronicle API v1." />
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

Where a platform spec marks `query` required, the value is a non-blank string. A Splunk block takes the [splunk-1.0](/docs/specifications/specs/platforms/splunk-1.0/) layout only: the `splunk::2.x` keys (`search`, `cron_schedule`, flat `throttling`, `notable`, `scheduling.frequency`, ...) are unknown keys, as every other unknown key is.

### Splunk's `advanced` table

A Splunk block's `advanced` table sets `savedsearches.conf` keys that no other field of the block sets, such as the parameters of a custom alert action:

```yaml
configurations:
  splunk:
    query: index=main sourcetype=canarytokens
    advanced:
      action.misp_alert_create_event.param.title: "Canary token triggered"
      action.misp_alert_create_event.param.distribution: 0
      action.misp_alert_create_event.param.tags:
```

`opentide deploy` sends each key as written: a `null` value as the empty value, a boolean as `1` or `0`, any other value as text. A list or table is refused, as `savedsearches.conf` cannot hold one, and so is a blank key. A key the block also sets (`alert_threshold`, `cron_schedule`) takes the `advanced` value; the `[[modifiers]]` of `platforms/splunk.toml` still apply after it. An action whose parameters are set here is triggered when it is in the tenant's `[tenants.setup] actions_enabled`. The table is left out of the generated templates and of editor completion.

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
