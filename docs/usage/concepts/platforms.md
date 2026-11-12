---
title: Platforms
description: Eleven deployment platforms, seven query validators (five offline), nine query runners, and where each platform block schema is specified.
---

# Platforms

opentide integrates with **eleven detection platforms** through built-in adapters registered at import time (`opentide.platforms` entry points). All ship in the base PyPI package.

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
| HarfangLab | `harfanglab` | yes | no | YARA | telemetry filters | Sigma or YARA |
| Sysdig Secure (Falco) | `sysdig` | yes | no | yes | no | Falco condition |
| Bitdefender GravityZone | `bitdefender` | yes | no | YARA | no | GravityZone criteria or YARA |
| Google Security Operations | `google_secops` | yes | yes (`verifyRuleText`) | not yet | yes (`udmSearch`) | YARA-L 2.0 |

The offline check is the analysis engine that ships with `pip install opentide` (`opentide validate`, `opentide validate query`, `opentide lint`, [`opentide lsp`](../../cli/lsp.md)): it parses each query in its language, with the platform's tables or dialect, and needs no tenant.

CLI `--platform` uses **registry keys** (`defender_for_endpoint`, `carbon_black_cloud`, `sentinel_one`). These are runtime identifiers; every platform ships with `pip install opentide`.

CrowdStrike stores a correlation filter, which is not syntax-checked: `opentide validate query` reports `supported: false`. HarfangLab stores a Sigma rule or a YARA rule. Its YARA is checked offline, as libyara 4.5 compiles it, and Sigma is not; `--live` reports `supported: false`.

A HarfangLab block is one kind: `sigma` or `yara`, never both (`harfanglab_rule_kind`). A `yara` block is either `signature`, a whole YARA text deploy sends verbatim, or the decomposed `meta`, `strings`, `condition` and `imports` deploy assembles into one rule, never both (`harfanglab_yara_form`):

```yaml
configurations:
  harfanglab:
    schema: platform::harfanglab::1.0
    status: STAGING
    yara:
      signature: |
        import "pe"

        rule Loader_Stage1 {
          meta:
            context = "file,memory"
          strings:
            $cfg = { 43 46 47 21 [4-16] 00 01 }
          condition:
            pe.number_of_sections > 3 and $cfg
        }
```

`opentide validate` checks `signature`, and the rule the decomposed form assembles, against the YARA language (its `queries` check, the `yara_*` codes): a YARA error fails the rule. Its `schema` check fails an `include` (`yara_include`), a signature with no rule that is neither private nor global (`yara_empty_signature`), a rule name used twice (`yara_duplicate_rule`), a signature written as a YAML alias (`yara_signature_alias`), and, in the decomposed form, a section or rule header in `strings` or `condition`, an unknown module in `imports`, and a rule `name` that derives a YARA keyword, a non-ASCII rule name or one over 128 characters. `opentide lint` reports YARA warnings, and warns when a rule in a signature has no meta `context` (`yara_meta_missing`), or when a rule's `context`, written in a signature or deployed by the decomposed form, is not a comma-joined list of `file`, `memory`, `file.pe`, `file.elf` and `file.macho` (`harfanglab_yara_context`). An empty `meta.context: []` in the decomposed form deploys the rule with no `context` and is `yara_meta_missing`. A `.yar` or `.yara` file is checked with `opentide validate query --file`.

Every platform but Sysdig and Bitdefender answers [`opentide query`](../../cli/query.md), which runs a read-only query on its tenants and returns the rows. CrowdStrike queries run on Next-Gen SIEM. HarfangLab has no query language for telemetry: a query names a telemetry source and field filters, and a HarfangLab rule has no query to run.

`validate query --platform elastic --live` previews the compiled rule in Kibana and runs the Elasticsearch pre-flight (ES|QL `LIMIT 0`, then `_field_caps` on aggregation fields). The same pre-flight runs before every Elastic deploy. Offline, the engine parses Kuery, Lucene, EQL and ES|QL, ES|QL against the stack versions of the block's tenants. See [Validate](../../cli/validate.md#elastic-live-validation-and-deploy).

Sysdig Secure runs Falco. A `sysdig` block is a Falco rule (a condition, its exceptions, and the macros and lists only that rule uses), which deploy creates through the Sysdig Secure runtime API and adds to the runtime policies the tenant or block names, keeping Sysdig's rule id in [deployment state](deployment-state.md). Deploy expands the block's own macros and lists into the condition and derives the Falco `desc`, `priority`, MITRE tags and a default `output` from the rule. The analysis engine checks the Falco condition offline; Sysdig has no rule preview, so `validate query --platform sysdig --live` reports `supported: false`. `deploy --dry-run` shows the API body.

Bitdefender GravityZone takes custom detection rules. A `bitdefender` block is one rule of one kind: `detection`, a list of criteria on a process, file, connection, registry or XDR event, or `yara`, a YARA signature written out in the block. Deploy calls the Incidents API (JSON-RPC `createCustomRule`, `updateCustomRule`, `deleteCustomRule`), sends the whole payload on every update, and keeps GravityZone's 24-hex rule id in [deployment state](deployment-state.md); it never lists rules, and never creates, updates or deletes an exclusion rule. It derives the GravityZone name, description, severity and tags from the rule, and resolves `targets` aliases with the tenant's `endpoint_tags` and `companies` tables. `opentide validate` checks the criteria catalogue, the actions each kind allows, and the YARA signature, and warns (as does `opentide lint`) on a full registry hive name, a `contains` value without a wildcard, and a `Critical` or `Informational` severity GravityZone collapses; The analysis engine checks `yara.signature` offline under its Bitdefender profile, as `opentide validate` (its `queries` check), `opentide validate query --platform bitdefender` and the editor do: a YARA error, a character that is not ASCII (`bitdefender_yara_ascii`) or a signature over 30,000 characters (`bitdefender_yara_size`) fails the rule, each reported once, at its place in the signature, and `opentide lint` warns on a module GravityZone has not confirmed (`yara_module_unconfirmed`). GravityZone has no dry run, so `validate query --platform bitdefender --live` reports `supported: false`. `deploy --dry-run` shows the `createCustomRule` request.

Google Security Operations (Google SecOps, formerly Chronicle) takes YARA-L 2.0 custom rules. A `google_secops` block carries the rule's sections as keys: `events`, `outcome` and `condition` (and `setup`, `export`) as YARA-L text, written as block scalars, and `match` and `options` as YAML objects. Deploy assembles the rule from them: `rule <name> {`, a `meta` section it derives from the rule (author, description, severity, priority, ATT&CK `tactic` and `technique`, `opentide_uuid` and `opentide_version`, then the block's own `meta`), then each section under its label. The rule name is the block's `name`, else the rule's title in `snake_case`.

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

`condition` is a block scalar on purpose: `condition: #fail >= 10 and $success` as a plain scalar is a YAML comment, loads as null, and fails with `yaral_section_empty`. `opentide validate` checks the block's constraints (`google_secops_rule_name`, `google_secops_severity`, `google_secops_run_frequency`, `google_secops_schedule`, `google_secops_meta_key`), the sections' structure (`yaral_section_missing`, `yaral_section_empty`, `yaral_section_header`, `yaral_section_alias`, `yaral_match_shape`, `yaral_match_window`, `yaral_option`), and that no two enabled blocks share a rule name, ignoring case (`google_secops_name_duplicate`). It warns, as `opentide lint` does, when `outcome` assigns no `$risk_score`, when a rule matches a producer by a literal `ru_…` id, and on `run_frequency: LIVE` for a multi-event rule.

Deploy goes through the Chronicle API v1 and keeps Google's rule id (`ru_<uuid>`) in [deployment state](deployment-state.md); it never lists rules. Every create and every changed text is compiled by `verifyRuleText` first, and an unchanged text is not sent again, so the rule keeps its revision. A `PREVIEW` rule runs without alerting, `RELEASE` and `UNIVERSAL` alert, `DISABLEMENT` disables, and `DELETION` archives the rule, or deletes it without `force` when the tenant's `deletion = "delete"`: deploy never deletes a rule's detections. `validate query --platform google_secops --live` sends each rule to `verifyRuleText`, which compiles it with the instance's reference lists and data tables and creates nothing, and places each diagnostic on its section key and line. [`opentide query`](../../cli/query.md) runs a YARA-L search through `udmSearch`; `--rule` is not supported. The analysis engine's offline YARA-L check is not wired in this release: `validate query --platform google_secops` without `--live` names `--live`. `deploy --dry-run` shows the assembled rule.

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
  <Card title="CrowdStrike" href="/docs/specifications/specs/platforms/crowdstrike-1.0/" description="Correlation filter. No query validator." />
  <Card title="HarfangLab" href="/docs/specifications/specs/platforms/harfanglab-1.0/" description="Sigma or YARA, never both. YARA as a whole signature or decomposed, checked offline." />
  <Card title="Sysdig Secure" href="/docs/specifications/specs/platforms/sysdig-1.0/" description="Custom Falco rule through the Sysdig Secure API. Block macros and lists are expanded at deploy." />
  <Card title="Bitdefender GravityZone" href="/docs/specifications/specs/platforms/bitdefender-1.0/" description="Custom detection rule: Basic criteria or a YARA signature, through the Incidents API." />
  <Card title="Google Security Operations" href="/docs/specifications/specs/platforms/google-secops-1.0/" description="YARA-L 2.0 rule written as sections, assembled with derived meta, through the Chronicle API v1." />
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

Only platforms with `can_validate=True` run live validation. For CrowdStrike, HarfangLab, Sysdig and Bitdefender, CLI and MCP return `supported: false` for `--live` — **never fake validation**. HarfangLab's and Bitdefender's YARA and Sysdig's Falco are checked offline; Bitdefender's criteria are checked by `opentide validate`.

```bash
opentide validate query --platform crowdstrike   # reports unsupported
```

For the seven that can, `opentide validate query` checks each query offline with
the analysis engine (every platform but SentinelOne, whose S1QL it does not
parse, and Google SecOps, whose YARA-L check the engine does not run yet), and `--live` submits the catalogue queries to the tenants, which
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

`opentide deploy` sends each key as written: a `null` value as the empty value, a boolean as `1` or `0`, any other value as text. A list or table is refused, as `savedsearches.conf` cannot hold one. A key the block also sets (`alert_threshold`, `cron_schedule`) takes the `advanced` value; the `[[modifiers]]` of `platforms/splunk.toml` still apply after it. An action whose parameters are set here is triggered when it is in the tenant's `[tenants.setup] actions_enabled`. The table is left out of the generated templates.

### Upgrading to 0.4.0

This is a **breaking change** for objects that previously passed validation:

| Object | Before 0.4.0 | From 0.4.0 |
|--------|--------------|------------|
| Splunk or Carbon Black rule with no `query` (and, for Splunk, no `search`) | Validated; the deployer skipped it silently | `opentide validate` reports `query: Field required` |
| Any platform with `query: ""` or whitespace only | Validated; the deployer skipped it silently | `opentide validate` reports `query must not be empty` |
| Splunk schedule with no `scheduling.type` | Saved with `cron_schedule` but never scheduled | Scheduled |

Every row that now fails was already a rule that never reached the platform. Run `opentide validate` after upgrading to find them.

## Platform configuration

Per-platform settings live under `.opentide/configurations/platforms/`. Enable platforms with `opentide setup platforms` or the parent `opentide setup --platform` flags; the registry loads deployers and validators for enabled systems only.

## Live deploy dependencies

Validate, generate, and dry-run deploy work with `pip install opentide` alone. **Live** API deploy to Splunk or Carbon Black may require additional vendor SDKs — see [Installation](../installation.md).

## SDK access

Deploy and validate programmatically via `Opentide.Platforms` — see [SDK platforms](../../sdk/platforms.md).
