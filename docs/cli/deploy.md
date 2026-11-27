---
title: opentide deploy
description: Deploy the changed rules whose status maps to a strategy, to the tenants that accept it.
---

# opentide deploy

Deploy the rules a run changed whose status maps to the run's `--strategy`, to the tenants that accept that strategy.

```bash
opentide deploy --strategy PREVIEW --dry-run          # pull or merge request job
opentide deploy --strategy RELEASE --platform splunk  # default-branch job
opentide deploy --strategy PREVIEW --strategy RELEASE --all --dry-run   # every rule file
opentide --json deploy --dry-run --strategy PREVIEW --uuid <uuid>   # one rule
```

Three things decide what is sent:

1. **The rule's status maps to a strategy** in `deployment.toml`. With the default statuses, `DEVELOPMENT`, `IMPROVING`, `STAGING` and `ACCEPTANCE` map to `PREVIEW`, and `PRODUCTION` maps to `RELEASE`. Status names never matter, only the strategy they map to.
2. **The run deploys a strategy.** `--strategy PREVIEW` deploys rules mapping to `PREVIEW` or `UNIVERSAL`. `--strategy RELEASE` deploys rules mapping to `RELEASE` or `UNIVERSAL`, and disables or deletes rules mapping to `DISABLEMENT` or `DELETION`.
3. **The tenant accepts the strategy.** A tenant's `strategies` (default: both) decide which runs reach it.

[Statuses, strategies and tenants](../usage/concepts/statuses-and-strategies.md) walks through this with examples.

## When to use it

- In a pull or merge request pipeline, with `--strategy PREVIEW`, to deploy the changed rules to the tenants that take previews.
- On merge to the default branch, with `--strategy RELEASE`, to deploy, disable or delete the changed rules on the tenants that take releases.
- Locally with `--dry-run` to preview what a deploy would send, and to which tenants.

Always `--dry-run` first, and always [validate](./validate.md) before deploying.

## Prerequisites

A real (non-dry-run) deploy contacts the platform API, so it needs:

1. The platform **enabled** in `.opentide/configurations/platforms/<name>.toml`.
2. **Credentials** for that platform, typically via environment variables referenced from the platform TOML — see [Configuration → credentials](../usage/configuration.md#credentials).

`--dry-run` needs neither and is safe to run anywhere.

## Options

| Flag | Purpose |
|------|---------|
| `--strategy` | Required, repeatable. `PREVIEW`: rules whose status maps to `PREVIEW` or `UNIVERSAL`. `RELEASE`: rules whose status maps to `RELEASE` or `UNIVERSAL`; also disables `DISABLEMENT` rules and deletes `DELETION` rules. Each rule goes to the tenants whose `strategies` accept the run's strategy. A status name such as `STAGING` is refused, and the message names the strategy it maps to |
| `--all` | Read every rule file. Without it, deploy reads the rule files the run changed: the pull or merge request (from its merge base), the push (from the commit the branch held before it; see [Troubleshooting](#troubleshooting)), or outside CI the last commit |
| `--uuid` | Read the rule with this `metadata.uuid` instead of the changed rules (repeatable, case-insensitive). See [Selecting rules](#selecting-rules) |
| `--file` | Read this rule file instead of the changed rules (repeatable), matched as [`validate --file`](./validate.md) matches: a file name, or a path relative to the current directory or the workspace |
| `--platform` | Target platform (see [platforms](../usage/concepts/platforms.md)) |
| `--wide` | Deploy the rule files read whatever their status strategy, `INERT` included, to the tenants accepting the run's strategies. `DISABLEMENT` and `DELETION` still follow `--keep-deprecated` |
| `--dry-run` | Simulate deployment without writes. `--json` lists the tenants each rule would reach. On a push to the default branch a `RELEASE` deploy promotes, the plan shows the changed rules promoted, as the deploy will send them, with a warning saying so; nothing is written |
| `--keep-deprecated` / `--drop-deprecated` | Include rules whose status maps to `DISABLEMENT` or `DELETION`, so a `RELEASE` run disables or deletes them. Default: on, off with `--all` |
| `--skip-promotion` | Skip the promotion step of a `RELEASE` run on a push to the default branch |
| `--skip-unconfigured` | Exit 0 when every platform with rules to deploy has no `[[tenants]]` block |
| `--prune` | With `--strategy RELEASE`: retire (delete) the rules deployed earlier whose rule file is gone, shown first in the dry run's plan. Without it, deploy only warns about them. Not with `--uuid` or `--file`. See [Deleted rule files](#deleted-rule-files) |
| `--persist-state-externally` | In CI, allow a run other than `--strategy RELEASE` on a push to create rules on the platforms that keep vendor ids (Microsoft Defender, SentinelOne, CrowdStrike, Sysdig, Bitdefender, Graylog, Exabeam, Google SecOps and Datadog, and platform plugins). Pass it only when the pipeline commits `.opentide/states/deployment/` itself; see [Creates outside the production job](../usage/concepts/deployment-state.md#creates-outside-the-production-job) |

### Selecting rules

`--uuid` and `--file` name the rules a run reads, in place of the rules the run changed: no git checkout or diff is read, and a `RELEASE` run skips status promotion, which applies to the diff. Both are repeatable and add up: `--uuid A --file b.yaml` reads both rules. The rest of the run is unchanged: each selected rule is planned on the platform blocks whose status a run strategy deploys (pass `--wide` to ignore the status), and goes to the tenants that accept the strategy. An editor's "preview deploy" of one rule is, for the [tutorial](../usage/tutorial.md)'s rule:

```bash
opentide --json deploy --dry-run --strategy PREVIEW --uuid 00000000-0000-4000-8003-000000000001
```

Its `plan` and `payloads` hold only that rule, and the document carries `"scope": "selected"`:

```json output-of="opentide --json deploy --dry-run --strategy PREVIEW --uuid 00000000-0000-4000-8003-000000000001"
{
  "scope": "selected",
  "dry_run": true,
  "plan": { "sentinel": ["00000000-0000-4000-8003-000000000001"] }
}
```

- With `--all`, either flag is a usage error: exit `2`, `failure.code` `usage_error`. `--all` reads every file; a selection reads some.
- A value that selects no rule fails the run with exit `1` before anything is planned, and `unmatched` lists each one. A usage error, such as an unknown `--strategy`, is reported first (exit `2`). Candidates are the files directly in the rules folder, as for `--all`.

`--plan` and `DEPLOYMENT_PLAN` were removed in 0.17.0. Either now fails with exit `2` and names the `--strategy` to pass: `STAGING` became `--strategy PREVIEW`, `PRODUCTION` became `--strategy RELEASE`, and `FULL` became `--strategy PREVIEW --strategy RELEASE --all`. A platform file whose tenant still sets `deployment` fails to load and names the `strategies` or `manual` line that replaces it ([migration table](../usage/concepts/statuses-and-strategies.md#moving-from-deployment-plans-016-and-earlier)).

## Output

A dry-run in the [tutorial](../usage/tutorial.md) repository prints the plan: each rule on each tenant with what a deploy would do (`+ create`, `~ update`, `+ create or update`, `- disable`, `× delete`), then the tally as the outcome line:

```bash
opentide deploy --platform sentinel --dry-run --strategy PREVIEW --all
```

```text output-of="opentide deploy --platform sentinel --dry-run --strategy PREVIEW --all"
Deploy plan · strategy PREVIEW · 1 platform, 0 tenants · dry run, nothing is sent

sentinel · 0 tenants
  + create or update  Sentinel KQL Rule  …000000000001  status STAGING

Plan: 0 to create, 0 to update, 1 to create or update, 0 to disable, 0 to delete
  help: add (or uncomment) a [[tenants]] entry in .opentide/configurations/platforms/sentinel.toml
warning: sentinel has no tenants configured in .opentide/configurations/platforms/sentinel.toml, so a real deploy would stop
dry run, nothing sent
```

Microsoft Defender, SentinelOne, CrowdStrike, Sysdig, Bitdefender, Graylog, Exabeam, Google SecOps and Datadog (and platform plugins) keep vendor ids in `.opentide/states/deployment/`, so their rows say `create` or `update`. The other platforms write a rule whether it exists or not, by its UUID or, on Splunk, by its title, and opentide does not claim either: their rows say `create or update`. Once sent, an Elastic or Sentinel rule's row says what the vendor did (`created` or `updated`); a Sentinel rule the workspace already held as sent reads `unchanged`. See [Splunk's renamed rules](#splunks-renamed-rules) for how a Splunk deploy removes the saved search a rule's earlier name left. A dry run ends with `dry run, nothing sent` after the tally and any next steps. A real run reports each rule as it is sent and ends with a counted outcome line; see [A real run](#a-real-run). Before anything is sent, which rules will be created and which updated is a prediction from `.opentide/states/deployment/` and each rule's status; after the send, only Elastic's and Sentinel's rows report what the vendor did. `--json` returns the same plan under `changes`, its tally under `summary`, and the selection:

```bash
opentide --json deploy --platform sentinel --dry-run --strategy PREVIEW --all
```

```json output-of="opentide --json deploy --platform sentinel --dry-run --strategy PREVIEW --all"
{
  "deployed": [],
  "dry_run": true,
  "plan": { "sentinel": ["00000000-0000-4000-8003-000000000001"] },
  "payloads": {
    "sentinel": [
      {
        "uuid": "00000000-0000-4000-8003-000000000001",
        "name": "Sentinel KQL Rule",
        "api_request": "..."
      }
    ]
  },
  "missing_tenants": {
    "sentinel": ".opentide/configurations/platforms/sentinel.toml"
  },
  "advice": "add (or uncomment) a [[tenants]] entry in .opentide/configurations/platforms/sentinel.toml",
  "ok": true,
  "status": "completed",
  "message": "Plan: 0 to create, 0 to update, 1 to create or update, 0 to disable, 0 to delete",
  "warnings": [
    "sentinel has no tenants configured in .opentide/configurations/platforms/sentinel.toml, so a real deploy would stop"
  ]
}
```

### Payloads

`plan` lists the rule UUIDs selected for each platform, and `strategies` the run's strategies. On a dry-run, `tenants` maps each platform to the tenants a real deploy would reach and the rules each would receive. A rule that no tenant takes is in `unrouted`, one entry per platform block (`platform`, `uuid`, `reason`, the reason a real deploy reports it `skipped` with: see [A real run](#a-real-run)), with a warning; it has no row in `changes`, and `unrouted` is absent when every rule has a tenant. `payloads` is present on dry-runs only; each rule's `api_request` (elided here) is the request a live deploy would send:

- **Sentinel**: the ARM alert-rule body, with `warnings` (the text of each technique it changes) when it changes any; see [Sentinel techniques](#sentinel-techniques).
- **Elastic**: `{"payload": <the Kibana rule body>, "block": <the rule's elastic block>}`. The block is what the Elasticsearch checks read before the rule is written, and the SDKs' `deploy` takes this body as it is. It is compiled for the first tenant the run sends the rule to, with that tenant's modifiers and `setup`, and the entry names that `tenant`. A rule that does not compile is shown as its block, with the model's defaults filled in, without the `null` of an optional field the block does not set, and without `enabled` and `name` when the block does not write them.
- **Sysdig**: the `/api/secure/rules` body. Beside it, `policies` lists the runtime policies a block that names its own joins instead of the tenant's.
- **Bitdefender**: the `createCustomRule` JSON-RPC body. **Exabeam** and **Graylog**: the create request, `{"method", "path", "body"}`. **Google SecOps**: the `rules.create` body with the run state the deploy sets.
- **Microsoft Defender, SentinelOne, CrowdStrike, HarfangLab, Splunk and Carbon Black Cloud**: the requests a deploy sends to the first tenant the run sends the rule to, in order, each `{"method", "url", "body"}`, and the entry names that `tenant`. Each `url` is the whole URL the deploy sends to: Splunk's create goes to `https://<url>:<port>/servicesNS/nobody/<app>/saved/searches/` (port `8089` and app `search` when the tenant names none), with the trailing slash, and each update to the saved search's percent-encoded name after it; Carbon Black's URLs start with the tenant's `url`. Splunk sends each body as a form (`application/x-www-form-urlencoded`), not as JSON, so a number or a boolean shown in it (`"is_scheduled": 1`, `"alert.severity": 5`) reaches the tenant as its text (`1`, `5`). `[]` means nothing is sent: a rule to disable or delete that the deployment state has no id for. The rule is compiled for every tenant the run sends it to, so a tenant that cannot take it (a Carbon Black tenant with no watchlist, a SentinelOne tenant with neither `site_id` nor `account_id`) fails the dry run, and the error names it.

SentinelOne and CrowdStrike create a rule, or update or delete the id `.opentide/states/deployment/` records for the tenant, as `changes` says. Microsoft Defender addresses each rule by `opentide-<uuid>`, its Defender rule id, and keeps no deployment state ([Microsoft Defender rules](#microsoft-defender-rules)): `api_request` is the rule's first request, the `PATCH` of `detectionRules/opentide-<uuid>` that creates, updates or disables it, or the `DELETE` that retires it. HarfangLab writes a Sigma rule by its UUID (a `PUT` the tenant answers `404` is sent again as a create) and posts a YARA file. Splunk and Carbon Black Cloud look the rule up on the tenant as they send, and `api_request` is what a tenant that does not hold it yet receives:

- a Splunk tenant that holds the saved search gets the same updates without the create, and a rule to delete is deleted there (`[]` here); after the writes, or the delete, a deploy sends one `GET` listing the saved searches that name the rule and a `DELETE` for each copy an earlier name of it left, and, once per tenant and only when the listing holds a copy owned by another user, one `GET /services/authentication/current-context` to read the user the token signs in as ([Splunk's renamed rules](#splunks-renamed-rules)): none of them is in `api_request`, since only the tenant knows its saved searches and its user;
- a Carbon Black report of the same title is updated in place, and a rule to retire has its IOC taken out of the report that holds it (`[]` here).

A value the dry run cannot know is a placeholder in `api_request`, `<KIND:NAME>`, anywhere inside a string ([Placeholders](./json-output.md#placeholders) has the grammar and the full list): look for the pattern `<(send-time|tenant-read|tenant):[a-z0-9_]+>` in every string, not for a string that starts with `<` and ends with `>`. Only a placeholder that is the whole string stands for a number or an object.

| Placeholder | What a deploy sends |
|---|---|
| `<send-time:minute>`, `<send-time:hour>` | Splunk: the minute and hour of a `frequency` schedule read from the clock as the request is sent (a tenant's `frequency_scheduling = "current"`), as in `"cron_schedule": "<send-time:minute> */2 * * *"`. A schedule opentide draws (`random`, the default) is shown as the deploy sends it: its minute and hour come from the rule's UUID |
| `<send-time:timestamp>` | Carbon Black Cloud: the report's `timestamp`, the time it is sent (a number, where the placeholder is a string) |
| `<tenant-read:watchlist_id>`, `<tenant-read:watchlist>` | Carbon Black Cloud: the id of the watchlist the new report joins, and that watchlist as the tenant holds it (an object, where the placeholder is a string), sent back with the report's id added to `report_ids` |
| `<tenant:KEY>` | The tenant's `setup.KEY`: when the run reaches no tenant of the platform (`url`, `port`, `app`, `api`, `customer_id`, `site_id`, `source_id`, `org_key`), or when the value names an environment variable (`$NAME`, `${NAME}`), which a dry run never resolves, set or not, so it needs no credential and prints no secret. The entry's `unresolved` lists the keys in `setup` and says why in `reason`. With no tenant, the requests are compiled for a tenant whose `setup` sets nothing else, with no exclusion or modifier scoped to a tenant, and SentinelOne's scope is shown as `siteIds` (a tenant with `account_id` gets `accountIds`) |

A setting the deploy reads as it is written, not as a variable (Splunk's `enterprise_security`), still fails the dry run when it names one, as it fails the deploy.

A vendor's rule id is not a placeholder: an update or a delete addresses the id the deployment state records, and a create carries none, since the platform gives it. Replace each placeholder before you send `api_request` yourself; a real deploy sends its value. A rule that would fail to deploy (a Sentinel rule with an unparseable duration, a missing `grouping` or `grouping.alert`, or an empty `response` block with no `alert.severity`; a CrowdStrike rule whose `details.trigger` the platform does not take, such as `event`, even when no tenant is configured; a tenant that cannot take the rule) is listed with `"status": "failed"`, a `code`, an `error` naming the cause, a `help`, and a null `api_request`. `diagnostics` holds one entry per such rule (`code`, `severity`, `message`, `help`, a workspace-relative `path`, `platform`, `uuid`, `name`), and the dry-run reports `failed` and exits `1`. The plan prints each one as a [code frame](./validate.md), like `validate` and `lint`, above its tally, which keeps no glyph:

```text
error[compile_empty_block]: 'response' is empty, so Sentinel cannot read 'alert_severity'
  ╭─▶ objects/rules/sentinel-kql-rule.yaml
  ╰─ help: set response.alert_severity, or configurations.sentinel.alert.severity

Plan: 0 to create, 0 to update, 0 to disable, 0 to delete, 1 would fail
dry run, nothing sent
```

The rule's row in the plan reads `✗ would fail` instead of its action, and the tally counts it apart (`N would fail`, `summary.fail`; each such entry of `changes` has `"fails": true`), since a rule that cannot compile is created or updated nowhere.

The codes are `compile_missing_field`, `compile_empty_block`, `compile_invalid_value`, `compile_invalid_rule` and `compile_failed`. A dry run sends nothing, so an unset `$VARIABLE` in a tenant's setup is a warning there (`a real deploy would need $AZURE_CLIENT_SECRET, which is unset`), not an error. The [tutorial](../usage/tutorial.md) scaffold leaves `[[tenants]]` commented out, so this dry-run previews the payload, leaves `deployed` empty, and warns that a real deploy would stop. After you uncomment a tenant, `deployed` lists the platform and the warning is gone. A real deploy returns the same envelope with `"dry_run": false` and no `payloads`. Non-zero [exit codes](./exit-codes.md) signal deployment errors.

#### ATT&CK techniques

**A block's own technique list is sent; otherwise the rule's objective's is.** On a platform whose block holds a technique list, the block's list is sent when it sets one, and only then are the techniques resolved from the rule's `detection_model` (its objective's `mitre_attack`, otherwise its threats') sent instead. An empty list counts as unset, so `techniques: []` inherits. The two are never merged: explicit beats inherited. Two platforms have such a list:

| Platform | Block field | Sent as |
|---|---|---|
| Sentinel | `alert.techniques`, `alert.tactics` | `techniques`, `subTechniques`, `tactics` ([below](#sentinel-techniques)) |
| Microsoft Defender | `alert.techniques` | the alert template's `tactics` ([below](#microsoft-defender-techniques)) |

**CrowdStrike is the exception.** Its block's `details.tactic` and `details.technique` each hold one value, so they are sent only when set and never inherited: picking one of an objective's several techniques would be arbitrary. The rule's `techniques` are not sent to CrowdStrike either.

The other platforms have no block field. Splunk (the correlation search's `mitre_attack` annotation), Elastic (`threat`), Google Security Operations (`meta`), Exabeam, Bitdefender, Graylog and Sysdig send the rule's own `techniques` together with those it inherits, de-duplicated in order; Carbon Black sends the inherited ones as report tags; SentinelOne and HarfangLab send none.

#### Sentinel techniques

**The block's `alert.techniques` is sent; otherwise the objective's.** `alert.tactics` is sent when the block sets it, even when the techniques come from the objective; otherwise the tactics are those of the techniques that are sent. An empty `alert.techniques` or `alert.tactics` counts as unset. Whatever is sent is held to ATT&CK v18 below.

In a Sentinel body, `techniques` holds parent technique ids and `subTechniques` the sub-technique ids: an objective mapped to `T1556.009` is sent as `"techniques": ["T1556"]` and `"subTechniques": ["T1556.009"]`, because ARM rejects a sub-technique in `techniques`. A sub-technique listed in `alert.techniques` is split the same way. Sentinel is aligned to ATT&CK v18, and ARM rejects an id it does not know, so each id Sentinel does not take is changed (an objective's, since `alert.techniques` takes v18 ids only), and each change earns a `technique_newer_than_sentinel_attack` warning that names the rule, the id and what is sent instead (in the log, and in the dry run's `warnings` on the rule's entry in `payloads`):

- an id newer than v18 is sent as the v18 id or ids it replaced (`T1685.002` as `T1562.008`); with none, a sub-technique sends its v18 parent (`T1027.018` as `T1027`), and anything else is left out. The warning for a newer parent also lists where its sub-techniques go (`Its sub-techniques map to ATT&CK v18 as T1685.001 → T1562.002, T1685.002 → T1562.008, …`), as deploy sends them, so the objective can name the v18 id instead;
- a retired id is sent as the id or ids that replaced it, or left out;
- an id that is not an ATT&CK v18 id Sentinel knows (a typo) is left out.

The ids are de-duplicated, and the parents (and the tactics, when the block sets none) are taken from the ids that are sent. When none can be sent, no `techniques` are sent, and `alert.tactics` is still sent when the block sets it. `alert.techniques` takes ATT&CK v18 ids only ([A technique fails only under the Sentinel block](../usage/troubleshooting.md#a-technique-fails-only-under-configurationssentinelalerttechniques)). The rule's own `techniques` field is not sent. `opentide generate extract sentinel` lists each imported sub-technique in `alert.techniques` in place of its parent, so the rule redeploys with the same ids.

Deploy writes the alert rule with ARM api-version `2025-10-01-preview`, because NRT rules exist only in the preview versions. The stable api-versions do not return `subTechniques`, so a `GET` of the rule with one looks as though the field was dropped: read it with a preview version to see what was sent.

#### Microsoft Defender techniques

A Microsoft Defender block's `alert.techniques` (technique and sub-technique ids such as `T1528` and `T1059.001`) is sent as the alert template's `tactics`: each technique under the tactics the `att&ck` vocabulary gives it, each sub-technique under its parent, with Stealth and Defense Impairment sent as `DefenseEvasion`. A block that sets none, or an empty list, sends the rule's objective's techniques instead. An id outside Enterprise ATT&CK (Mobile and ICS ids), or one the vocabulary does not know, is left out with a `technique_not_enterprise_left_out` warning in the log naming the rule and the id. When no technique is left, the alert template has no `tactics`. The rule's own `techniques` field is not sent. Defender takes the `att&ck` vocabulary's ids as they are: the Sentinel v18 mapping does not apply. `opentide generate extract defender` imports the tenant's tactics tree into `alert.techniques`, so an extracted rule redeploys with the same ids.

#### Microsoft Defender rules

Microsoft Defender rules are custom detections on the Graph **beta** API, `https://graph.microsoft.com/beta/security/rules/detectionRules` ([`platform::microsoft_defender::1.0`](/docs/specifications/specs/platforms/microsoft-defender-1.0/)). The Defender rule id is `opentide-` followed by the rule's `metadata.uuid` in lowercase canonical form (`opentide-8f3c4a7e-…`, 45 characters), so a deploy reads no deployment state and writes none. Graph refuses a rule id that begins with a digit, which a bare UUID does ten times in sixteen; the prefix also marks the rule as opentide's in the portal and in Graph:

| Change | Requests | The tenant's answer |
|---|---|---|
| create or update | `PATCH detectionRules/opentide-<uuid>` with the rule | `404`: `POST detectionRules` with the rule and its `id`; that create's `409`: one more `PATCH`, which updates the rule when another run created it first, and fails the rule with `microsoft_defender_rule_conflict` when it answers `404` too (another rule most likely holds the display name or the alert title) |
| disable (`DISABLED`) | `PATCH detectionRules/opentide-<uuid>` with the rule and `status: disabled` | `404`: the rule is skipped, `not on the tenant: nothing to disable`, with the `microsoft_defender_rule_absent` warning |
| delete (`REMOVED`, `--prune`) | `DELETE detectionRules/opentide-<uuid>` | `404`: skipped, `no rule opentide-<uuid> on the tenant` |

The plan counts each active rule as `create or update`; the row of `results` says which it was. A rule that fails with `microsoft_defender_rule_conflict` has the code before its message in the row's `error` (`microsoft_defender_rule_conflict: Graph refused to create …`). Any other answer fails the rule with `tenant_refused`, the status and Graph's message. A deleted rule file is retired by `opentide-<uuid>`, so `--prune` deletes only a rule opentide deployed.

A rule an earlier release created is not under that id: 1.0.0 deployed under the bare uuid (only a uuid that begins with `a` to `f`; Graph refused the others), and 0.x under ids of its own. Deploy does not touch those rules. Before the first deploy with this release, delete them in the Defender portal, or rename both their name and their alert title (deleting is simpler): Graph refuses the create of `opentide-<uuid>` while another rule holds its display name, alert title or id, and keeps them reserved for a disabled rule too, so disabling is not enough. The rule then fails with `microsoft_defender_rule_conflict`. A rule to disable or delete that only exists under its bare uuid reads `not on the tenant: nothing to disable`, or `no rule opentide-<uuid> on the tenant`: that rule may still run under the bare uuid, so delete it in the portal.

When no rule the run read has a status mapping to its strategies, the command reports `skipped` with exit `0`. The reserved `deploy metadata` command is hidden and returns a non-zero “not implemented” result rather than reporting false success.

## A real run

A real run prints the plan's header and tally, then one line for each rule as the platform answers, so a CI log shows progress while a platform is slow, and the last line says which rule it is waiting on. The lines are append-only: no spinner and no carriage return unless stdout is a terminal, where the running rule is also shown on a live row that its result line replaces. Platforms deploy one after another; a platform's tenants deploy up to four at once (a platform plugin's one at a time), so the lines of tenants deploying at the same time may interleave: a rule's line that follows another tenant's comes under its own `Deploying to <platform> / <tenant>` header again. The `--json` document lists the rows in the plan's order whatever order they ended in. The samples below are illustrative, not captured output: a real run needs a live tenant.

```text illustrative
Deploy plan · strategy PREVIEW · 1 platform, 1 tenant
Plan: 0 to create, 0 to update, 14 to create or update, 0 to disable, 0 to delete

Deploying to sentinel / contoso · 14 rules
  [ 1/14] ✓ created   Sentinel KQL Rule                           0.4s
  [ 2/14] ✓ unchanged Staging Promote Rule                        0.3s
  [ 3/14] ✗ failed    Password spray from a single source IP      HTTP 400: Failed to parse query: syntax error near '|'
  [ 4/14] · skipped   New service installed on domain controller  not attempted after a failure
  ...
✗ sentinel · 2 deployed, 1 failed, 11 not attempted · 1.2s
✗ Deployment failed · 1 created, 1 unchanged · 1 failed, 11 not attempted · 1.2s
```

| Line | Meaning |
|------|---------|
| `✓ created`, `✓ updated`, `✓ disabled`, `✓ deleted` | The platform accepted the rule. Elastic's and Sentinel's word is what the platform did (`created` or `updated`; Sentinel reads the rule first); a platform that keeps vendor ids shows the planned action; any other platform that writes a rule by its UUID says `deployed`, since opentide cannot tell a create from an update |
| `✓ unchanged` | The tenant already held the rule as this run would write it, so nothing was written (Elastic, Sentinel and Splunk, below) |
| `✗ failed` | The platform, or planning, refused the rule. The line carries the platform's own message and its HTTP status when it has one, so the cause is readable without a traceback. A long message continues on the lines below it on a terminal and stays on one line in a log |
| `· skipped` | The rule was not sent, with the reason: an `INERT` status, a Sigma rule on a YARA tenant, a retirement of a rule that never reached the tenant (`external_id_missing`) |
| `· skipped … not sent: no <platform> tenant takes its status <STATUS> (<STRATEGY> strategy)` | No tenant accepts the strategy the rule's status maps to (often a status a `RELEASE` push's promotion just wrote). The row has no tenant |
| `· skipped … not sent: its tenants list names no <platform> tenant that takes its status …` | The block's `tenants` names only tenants that are not configured or do not accept that strategy |
| `· skipped … not sent: the <platform> tenants that take its status … are manual, and its tenants list does not name them` | Only `manual` tenants accept the strategy, and a manual tenant receives a rule only when its `tenants` names it |
| `· skipped … not attempted: tenant <name> failed` | The tenant failed, so this rule was never sent to it; the other tenants go on. A tenant that failed before any rule (its credentials, its connection or its sign-in) has every rule listed this way; one that failed on a rule has its other rules listed right after that `✗ failed` line |
| `· skipped … not attempted after a failure` | The run stopped (an interrupt, or a failure of the run itself) before this rule. Every rule and platform the run never reached is listed |

A rule the tenant refuses is `failed`, and the rules after it are still deployed. A failure of the tenant itself stops that tenant, and the other tenants go on.

- **Before any rule.** Each tenant's credentials are resolved once, before its first rule, and a platform with a sign-in of its own (Sentinel, Microsoft Defender, CrowdStrike, Exabeam, Google SecOps) signs in then. On the other platforms the first rule's own requests are the first the tenant gets. When the tenant fails before it has taken anything (an unset or refused credential, a refused connection, an unknown host, a refused certificate, a sign-in that gets no token, a setup value that cannot be used, a gateway's error on a lookup), no rule was sent: every rule of the tenant is `not attempted`, and `failures` holds the tenant's own entry (`platform`, `tenant` and `error`, no rule). The tenant has taken nothing while no write the first rule sent may have landed: a sign-in and a read-only check (Elasticsearch's, Graylog's query check, Google SecOps' `verifyRuleText`) are not writes, and a write the tenant refused with a `4xx` was not taken. The run ends with `error: Deployment to <platform> failed on tenant <name>: …` in place of the outcome line, and exits `1` with `failure.code` `command_failed` when no rule failed.
- **On a rule.** When the tenant fails once a write may have landed (it was accepted, or it got no answer, a dropped connection or a `5xx`), or after an earlier rule of the tenant was sent, the rule it came on is `failed` and the tenant's other rules are `not attempted`. A platform plugin sends its requests itself, so opentide cannot tell what reached the tenant: once the plugin was called for a rule, a failure of its tenant is that rule's.

A tenant fails when it cannot be reached or signed in to (a refused or dropped connection; on Elastic, a gateway's `502`, `503` or `504` in front of Kibana on a rule lookup or a delete, once retried, as from a proxy or Elastic Cloud's front end with Kibana down; an unset or refused credential, a sign-in Entra ID or CrowdStrike answers without a token), when it refuses the key on a rule where the platform says so (SentinelOne's `401`, Bitdefender's, Graylog's and Elastic's refused key), or when a platform's own check of the tenant fails (Graylog's version); the SDKs report the same failures with `scope` `tenant`. A `401` from Splunk or HarfangLab refuses the token, so it fails the tenant too. On the other platforms, a refusal of a request made once the tenant is signed in is the rule's (a Graylog `403`, which can be scoped to one stream, among them). The run exits `1` after any failed rule, with `failure.code` `issues_found`.

Every run ends with the platform's counts and one outcome line, passed or failed. The outcome line always counts `failed` and `not attempted` and ends with the elapsed time; it counts an action only when some rule had it:

```text illustrative
✓ Deployed 91 rules to 1 tenant · 60 created, 31 unchanged · 0 failed, 0 not attempted · 1m56s
```

`--quiet` hides the lines of rules that were deployed or skipped, never a failure. With `--json`, stdout is still one document and nothing is printed for each rule: the document carries `results`, one entry for each rule and tenant of the plan, in the order they were sent, with the rules a failure never reached last, so a pipeline can post a job summary or retry only what failed:

```bash
opentide --json deploy --strategy PREVIEW --platform sentinel
```

```json illustrative
{
  "status": "failed",
  "message": "Deployment failed · 1 created, 1 unchanged · 1 failed, 11 not attempted · 1.2s",
  "error": "Deployment to sentinel failed on Password spray from a single source IP: HTTP 400: Failed to parse query: syntax error near '|'",
  "results": [
    {
      "id": "00000000-0000-4000-8003-000000000001",
      "name": "Sentinel KQL Rule",
      "platform": "sentinel",
      "tenant": "contoso",
      "action": "create",
      "status": "deployed",
      "seconds": 0.412,
      "error": null,
      "reason": null
    },
    {
      "id": "00000000-0000-4000-8003-000000000402",
      "name": "Password spray from a single source IP",
      "platform": "sentinel",
      "tenant": "contoso",
      "action": "upsert",
      "status": "failed",
      "seconds": 0.353,
      "error": "HTTP 400: Failed to parse query: syntax error near '|'",
      "reason": null
    },
    {
      "id": "00000000-0000-4000-8003-000000000403",
      "name": "New service installed on domain controller",
      "platform": "sentinel",
      "tenant": "contoso",
      "action": "upsert",
      "status": "not_attempted",
      "seconds": 0,
      "error": null,
      "reason": "not attempted after a failure"
    }
  ]
}
```

`status` is `deployed`, `failed`, `skipped` or `not_attempted`; `removed`, on a Splunk row and only when not empty, lists the saved searches the deploy deleted because an earlier name of the rule left them ([Splunk's renamed rules](#splunks-renamed-rules)), including on a `failed` row whose cleanup stopped part way; `action` is the plan's (`create`, `update`, `upsert`, `disable`, `delete`), except that an `upsert` the platform reports as a create or an update once sent reads `create` or `update` (Elastic and Sentinel), and counts as one in the tally, and a rule the tenant already held as the run would write it reads `unchanged` (its `status` is `deployed`, and on a Splunk row `removed` can still list renamed copies the deploy deleted). `seconds` is how long the rule took, `0` when nothing was sent, and `null` for a platform whose engine does not report its rules one at a time (the rules count as deployed). The envelope's `summary` holds every count, present even when it is `0`: `create`, `update`, `upsert`, `disable`, `delete` (rules sent with that action), `unchanged` (rules the tenant already held, nothing written), `failed`, `skipped` (one per skipped result row, per platform and tenant, plus one per rule a status left out that has no such row), `not_attempted`, `seconds`, `platforms` and `tenants`. `results` is absent on a dry run.

### Unchanged rules

A deploy does not rewrite a rule the tenant already holds as the run would write it, whether the run selected the rule from the commit or with `--all`. It compares what it would send with what the lookup it makes anyway answered, field by field, on the fields opentide sends (Sentinel's replace also drops a member opentide no longer sends, so the workspace's is compared too):

| Platform | Compared | Not a difference |
|----------|----------|------------------|
| Elastic | Kibana's rule against the replace a deploy would send | the fields Kibana writes itself (`id`, `created_at`, `updated_at`, `revision`, `version`, …), a field holding Kibana's default (empty, `max_signals: 100`, `interval: 5m`, `from: now-6m`, `to: now`), an empty member Kibana adds inside a sent object, `73` against `73.0` |
| Sentinel | the rule ARM answers a `GET` of (same resource and `api-version` as the `PUT`) against the `kind` and `properties` a deploy would send. A `PUT` replaces the rule, so a member opentide no longer sends but the workspace holds is a difference too | the members ARM writes itself (`etag`, `id`, `name`, `type`, `systemData`, `lastModifiedUtc`), a member ARM answers empty (`null`, `false`, `""`, `[]`, `{}`), the trigger's defaults (`GreaterThan`, `0`), a duration in ARM's own form (`PT1H` against `PT01H00M00S`), `1` against `1.0` |
| Splunk | the saved search's settings against each setting a deploy sends (an update writes no other), the `description` with its `opentide rule <uuid>` line and the empty `alert.managedBy` among them | Splunk's `1` and `0` for `true` and `false`; an emptied setting the tenant does not answer |

A field opentide sent before and no longer sends is handled as each platform's write handles it:

- **Elastic.** A deploy replaces the whole rule, which drops such a field. While the tenant still holds a value in it, the rule is a change, and the replace removes the value.
- **Sentinel.** A deploy replaces the whole rule. A member the workspace still holds that opentide no longer sends (an alert title, a custom detail, an entity mapping, the trigger, the template link, a grouping or a sub-technique) is a change, and the replace removes it. Members ARM writes itself and members it answers empty are not a difference.
- **Splunk.** An update writes only the settings opentide sends, and the others keep their value on the saved search: a setting removed from the block's `advanced` table stays on the tenant, and the rule reads `unchanged` when every setting opentide sends is the same. Clear such a setting in Splunk. A saved search 0.28.1 deployed has no `opentide rule` line and may hold responders in `alert.managedBy`, which opentide now sends empty: it reads as changed, and is rewritten once.

A Sentinel rule is read with a `GET` before it is written. A `404` is a `create`, a rule that differs is an `update`, and a read ARM refuses (a `403`, or a `5xx` after retries) fails the rule with ARM's reason and writes nothing. A deployed Sentinel rule's `action` is what ARM did (`create`, `update` or `unchanged`) in place of `upsert`; a rule that failed or was not attempted keeps the plan's. A `disable` or `delete` keeps its action.

The rename cleanup ([Splunk's renamed rules](#splunks-renamed-rules)) runs for an unchanged rule too, so a copy a failed delete left is found on the next deploy; the row reads `unchanged` and lists the copies it deleted under `removed`.

A Splunk schedule opentide draws (a `frequency` with no `custom_time`) takes its minute and hour from the rule's UUID, so it is the same on every deploy, and rules spread over the day; a `frequency_scheduling = "current"` tenant takes the deploy's time, so its rules are rewritten on every deploy.

A Datadog rule is read with a `GET` by its stored id before it is written, and updated only when a property opentide writes differs from the compiled body: its name, whether it is enabled, its queries, cases, options, message, tags (as a set), signal grouping and title setting. Properties Datadog adds (`id`, `version`, `defaultTags`, …) and defaults it fills in for a property the body leaves out are not differences. An unchanged rule is sent nothing and its row's `action` is `unchanged`.

The other platforms still write each selected rule, each for its own reason:

| Platform | Why it is rewritten |
|----------|---------------------|
| Microsoft Defender, SentinelOne, CrowdStrike, Sysdig, Bitdefender, Exabeam, Google SecOps | An update goes by the stored vendor id, with no lookup. Comparing would need a `GET` per rule and a reading of each vendor's own form of the rule (fields it renames or computes), and a wrong `unchanged` would leave a changed rule undeployed |
| Graylog | An update is a `PUT` by the stored id, with no lookup. Graylog's form of an event definition adds ids and per-type `config` defaults |
| Carbon Black Cloud | A deploy rewrites the rule's report inside its watchlist. It reads the watchlist, but a report's IOCs come back in another form than the one sent |
| HarfangLab | A deploy is a `PUT`, then a `POST` when the rule is not there (a `404`), with no lookup |


### Splunk's renamed rules

Splunk names a saved search after its rule's title, with ` - Rule` for a correlation search, so a renamed rule, or one that gains or loses ` - Rule`, is written under a new name. Its `search` is the block's `query` as written, with nothing appended, and its `description` is the rule's, with a last line `opentide rule <uuid>` that names the rule.

- **After each write.** Once a rule's saved search is written, the deploy lists the saved searches of the tenant's app that name the rule (one request), and deletes every one under another name that counts as opentide's: a saved search that carries the rule's marker, is in the tenant's app, and is owned by `nobody` or by the account opentide's token signs in as. opentide writes through `/servicesNS/nobody/<app>/`, but Splunk records that account (`admin`, say) as the owner of what it creates. When the listing holds a copy of another owner, the deploy asks `GET /services/authentication/current-context` once per tenant for that account (read-only, and only then); if that fails, it logs a warning and deletes `nobody`'s copies alone. A copy that another user owns, a saved search shared from another app, and one that only mentions the UUID elsewhere in its description are left alone. **A clone an analyst made in Splunk Web while signed in as the token's own account counts as opentide's** (a clone keeps the description and its marker, and is owned by whoever cloned it), so the next deploy of the rule deletes it. Give opentide's token a dedicated Splunk user if analysts' copies must survive: their clones, owned by their own users, are then never touched.
- **When a rule is retired.** A rule whose status maps to `DELETION` deletes its saved search under its name now, then the copies the same way, so a rule renamed and retired in one commit leaves nothing behind.
- **Reported.** The result row lists the deleted names under `removed`, and the dry run's note says the deletes will happen; the listing and the deletes are not in the dry run's plan, since only the tenant knows its saved searches.
- **Failures.** A copy that cannot be listed or deleted fails the rule with `splunk_renamed_search_not_deleted`, which leads the row's `error` (`splunk_renamed_search_not_deleted: saved search …`). The message says the new saved search was written, names the copy and the ones already deleted, and `removed` still lists those. The next deploy of the rule finds the copy again.
- **Saved searches from 0.28.1 and earlier** have no `opentide rule` line until they are deployed again. A rule renamed before its first deploy with this release leaves its old saved search: delete it in Splunk.
- **A deleted rule file** is retired by a `RELEASE` run with `--prune` from the run that deleted it: its saved search under its last name, then every copy that carries its marker ([Deleted rule files](#deleted-rule-files)).

### Deleted rule files

Deleting a rule file does not delete the rule from the tenants it reached. Every run looks for rules deployed earlier whose file is gone, and warns about them: without `--prune`, `--json` lists each one under `retirable` (one entry per rule and tenant: `platform`, `tenant`, `uuid`, `name`, the block's last `status`, `action: "delete"`, and `unsupported` with the reason where the platform cannot retire it), and nothing is sent. A `RELEASE` run with `--prune` retires them, as each platform retires a rule whose status maps to `DELETION`:

```bash
opentide deploy --strategy RELEASE --prune --dry-run   # the plan shows the retirements
opentide deploy --strategy RELEASE --prune             # the job `setup ci` generates for the default branch
```

opentide retires only what it can show it deployed, from two kinds of evidence:

- **The run's diff.** A change-detection run (no `--all`, `--uuid` or `--file`) reads the rule files its commits deleted directly in the rules folder, as the diff's base commit held them: the rule's UUID, its name and its platform blocks. A block whose status maps to `DELETION` (already retired) or `INERT` (never deployed) is left alone; any other block is retired on the tenants it reached.
- **Deployment state.** On the platforms that keep vendor ids (Microsoft Defender, SentinelOne, CrowdStrike, Sysdig, Bitdefender, Graylog, Exabeam, Google SecOps, Datadog, and platform plugins), only the tenants and ids the rule's [shard](../usage/concepts/deployment-state.md) records are retired, then forgotten. An `--all` run reads every shard: a shard whose rule no file in the workspace holds is retired.

| Platform | Retired by |
|---|---|
| Sentinel, Elastic | A delete of the rule's UUID, from the diff |
| Splunk | A delete of the saved search under the deleted file's name (` - Rule` for a correlation search), then of every copy whose description carries `opentide rule <uuid>` ([Splunk's renamed rules](#splunks-renamed-rules)), from the diff |
| HarfangLab | A delete of the rule's UUID, of the deleted block's kind (Sigma or YARA), from the diff |
| The platforms that keep vendor ids | A delete of the id deployment state records, by the diff or by `--all` |
| Carbon Black Cloud | Not supported: the row is `skipped` and says to remove the report from the watchlist by hand |

An `--all` run cannot find a deleted rule on the platforms that keep no state; only the run whose diff deleted the file can. Run `--prune` on the push that deletes rules, or retire them with a `DELETION` status before deleting the file.

A retirement is a `delete` row of `changes` and `results` with `"retired": true`, counted under `delete` in the summary; the plan view says `rule file deleted` in place of a status. A delete the tenant answers `404` is `skipped` (`already gone from the tenant`; on Microsoft Defender `no rule opentide-<uuid> on the tenant`, as a rule 1.0.0 deployed under the bare uuid may still run), and a recorded id is forgotten all the same. Each retirement goes to its tenant after the platform's own rules, and a tenant that stopped on one of them is not asked.

Nothing is retired, and a warning says why, when:

- a rule with the same UUID is still in the workspace (a file moved or renamed is not deleted);
- any object file fails to load: its rule would look deleted (`opentide validate` shows where);
- an `--all` run reads no rule at all: an empty or misplaced rules folder would make every shard an orphan;
- the run cannot read its diff. A shallow checkout or a base commit the checkout does not hold fails the run as it does without `--prune`; a push that created its branch has no deletions;
- deployment state records a tenant the platform's file no longer configures.

`--prune` with a `PREVIEW`-only run, or with `--uuid` or `--file`, is a usage error (exit `2`).

### Connectors and status promotion

A deploy that sends goes through each platform's connector, compiled into opentide ([the implementation](./json-output.md#the-implementation)): to the platform its `--platform` names or, without one, to every platform the workspace enables, in the plan's order. On a run that matched no rule, it warns the CI run.

- A log line names no tenant (`tenant: ***`): opentide redacts tenant names and hosts from every line it logs; the document still names them.
- A credential whose `$NAME` is unset is refused before any request.
- A status promotion that cannot rewrite the push (no promotion target, a platform key that is not a string, a rule file that is not YAML or not a mapping, promoted text that does not read back) fails the run before anything is written (exit `1`); `--skip-promotion` deploys without it.

A status promotion (a `RELEASE` run on a push to the default branch in CI, without `--skip-promotion`) is the `status promotion` step: each block `status` is replaced in place, a byte-order mark, line endings and the file's permissions are kept, and the file is written atomically. A status written as an anchor, an alias or under a merge key is left as it is, with the `rule_not_promoted` warning. With `--debug` (or `OPENTIDE_DEBUG=1`), the step promotes every rule file directly in the rules folder, not only the files the push changed, and the run deploys the files it promoted besides the changed ones, never the folder's other files. Before the run reports, a promoted file whose rule reached no tenant is put back as it was, so the write-back commits no status that was never deployed: a rule no tenant takes, a tenant whose credential is unset or that cannot be reached, a run skipped for want of tenants (`--skip-unconfigured`), a run that ends before it sends, and the files a promotion wrote before one of its writes failed. The `rule_promotion_undone` log line names the file. A file edited during the run is left as it is and fails the run (exit `1`), since the write-back would commit a status no tenant received; a file deleted during the run is not made again, with a warning. A file that cannot be written back also fails the run: `failures` names its `path`, and its status must be set back by hand before a commit. Ctrl-C stops the run the same way; a second Ctrl-C, or a run still stopping after the grace period, puts the files back before the process ends. SIGTERM and SIGHUP put them back, then end the process as their default does (exit status 143 or 129 in a shell). opentide takes a signal only while it still has its default action when the promotion starts: one that is ignored (`nohup`) or that another program handles (`opentide serve`, a host program's own handler) is left alone. That is read from `/proc/self/status` on Linux; elsewhere only SIGTERM is taken, and only by the `opentide` binary itself. So SIGTERM puts the files back with the `opentide` binary on Linux and macOS and with `pip install opentide` on Linux, but not with the pip console script on macOS, on Windows, or with the npm package's `opentide` on any system (Node.js handles SIGTERM itself); SIGHUP only on Linux. A rule a tenant acknowledged is kept promoted as soon as its result is recorded, so a signal in the middle of a platform puts back only the rules no tenant has acknowledged yet. A process killed outright (SIGKILL, a CI runner that loses its machine) puts nothing back. The whole file is kept or put back: a rule with two platform blocks keeps both promoted when either reached a tenant, and a rule that reached one tenant and failed on another stays promoted, as deployed. Send it again with `opentide deploy --uuid <uuid> --strategy RELEASE` once the tenant is fixed. `DEBUG`, which CI systems and other tools set for their own logging, never turns this on, nor does the terminal the run starts in.

## Subcommands

### deploy migrate-state

Moves vendor rule ids off rule files into [deployment state](../usage/concepts/deployment-state.md). Run it once, in every workspace that has deployed to SentinelOne or CrowdStrike with an earlier release. It calls no vendor API and deploys nothing.

```bash
opentide deploy migrate-state
opentide --json deploy migrate-state
```

What it does:

1. **Refuses a gitignored destination.** If git ignores `.opentide/states/deployment/` (the `.opentide/states/` line older setups wrote does), it exits `1` with `deployment_state_ignored`, names the ignore line, and edits nothing. Replace that line with `.opentide/states/sharing.jsonl`; the command does not edit `.gitignore` itself.
2. **Scans every `.yaml` and `.yml` file under `objects/rules/`, subfolders included**, for `rule_id`, `rule_id_bundle` and `rule_id::<tenant>` at the root of each platform block.
3. **Writes the SentinelOne and CrowdStrike ids to `.opentide/states/deployment/<uuid>.json` first**, flushed to disk, and only then removes the keys from the YAML. Comments, key order and whitespace are kept: only the id lines go.
4. **Drops the keys of every other platform.** Microsoft Defender (whose rule id is `opentide-` and the rule's UUID), Sentinel, Splunk, HarfangLab, Carbon Black Cloud and the rest address their rules without a vendor id, so their keys are removed and printed as `external_id_unused` (platform, tenant, value, file), not stored.
5. **Leaves a rule untouched and exits `1`** when a tenant is mapped twice or to a different id than the shard already holds (`external_id_conflict`), or when a value is not a usable id (`external_id_shape`: not a string or integer, an empty tenant or id, or a SentinelOne id that is not a plain decimal like `12345`). Other rules still migrate.

It exits `0` after a migration, after a second run with nothing left to move, and when the only findings are `external_id_unused` warnings. It exits `1` when any rule fails or git ignores the deployment state directory. If the command stopped after writing a shard and before editing the rule, the next run finds the two agree and finishes the edit.

It runs through the same deployment-state code as a deploy: the same shards, edits, warnings, document and exit codes. On a terminal its log lines are one unstyled line each.

<Callout type="warn">
The migration is done when it is committed. Commit the edited rules together with every new file under `.opentide/states/deployment/`. A deploy from a checkout that has the stripped rules but not the shards creates a second live rule for every one of them.
</Callout>

### deploy replay-state

Replays one commit's deployment-state changes onto the checkout. The production job that [`setup ci`](./setup.md#setup-ci) writes runs it in its [write-back](../usage/workflows/ci-cd.md#production-write-back): when its rule files conflict with a merge that landed during the deploy, the job resets to the default branch's tip, runs `opentide deploy replay-state "$state_commit"` with the commit that recorded the deploy, commits what it changed and pushes, so no vendor id is lost. You need it by hand only to do the same after a failed write-back left a state commit on `refs/opentide/deployment-state/<commit>`. It calls no vendor API and deploys nothing.

```bash
opentide deploy replay-state HEAD
opentide --json deploy replay-state "$state_commit"
```

`<state_commit>` is a commit in the checkout, written as `git rev-parse` reads it: its id or a prefix of it, a reference (`HEAD`, a branch, `refs/opentide/deployment-state/<commit>`), a reflog entry (`HEAD@{1}`, `main@{yesterday}`), the branch checked out before (`@{-1}`), a branch's upstream (`@{u}`, mapped through the remote's fetch refspec as git maps it) or a message search (`:/fix` from every reference, `<rev>^{/fix}` from `<rev>`; the pattern is a Rust regular expression, where `.` does not match a newline), each with parent steps if you like (`HEAD~1`, `<commit>^`). Refused: `@{push}` (name the remote branch, `origin/<branch>`), ranges (`a..b`), files (`HEAD:path`, `:path`) and trees, which name no single commit. opentide reads the repository itself, so the runner does not need the `git` program; `GIT_DIR`, `GIT_WORK_TREE` and `GIT_CEILING_DIRECTORIES` choose the checkout as they do for git. Only what it changed under `.opentide/states/deployment/` against its first parent is applied, per platform and tenant, so the ids other runs recorded since are kept:

- a binding the commit added or changed is set on the checkout's shard;
- a binding the commit removed is removed, and a shard left with no binding is deleted;
- every binding the commit did not touch keeps the checkout's value.

When the checkout's shard holds another id for a binding the commit changed, the commit's id is kept and a `deployment_state_conflict <shard> <platform>/<tenant>: kept "<id>", the default branch had "<id>"` line is printed (`warnings` and `conflicts` in `--json`), so the duplicate remote rule can be removed by hand. The command stages and commits nothing.

`--json` returns `state_commit`, `written` and `removed` (shard paths), and `conflicts`, with their counts under `summary`. It exits `0` after a replay, conflicts included, and `1` when git cannot read the commit or a shard does not parse. Through 1.0.0-rc.5 the command was hidden from `--help` and printed one line of text whatever the output mode.

### deploy metadata

Reserved stub. Hidden from `--help`; it deploys nothing and exits `2` with “not implemented”:

```bash
opentide deploy metadata --platform splunk
opentide --json deploy metadata --platform splunk
```

```text output-of="opentide deploy metadata --platform splunk" exit=2
error: Metadata deployment is not implemented for splunk
```

```json output-of="opentide --json deploy metadata --platform splunk" exit=2
{
  "error": "Metadata deployment is not implemented for splunk",
  "ok": false,
  "status": "failed",
  "message": "Metadata deployment is not implemented for splunk"
}
```

<Callout type="warn">
`deploy metadata` is not implemented. Do not rely on it to push lookup tables.
</Callout>

## Troubleshooting

- **Authentication error** — credentials missing/wrong; see [Troubleshooting](../usage/troubleshooting.md#deploy-fails-with-an-authentication-error).
- **`AttributeError: module 'azure.mgmt.securityinsight.models' has no attribute 'AlertPropertyMapping'`** — through 0.14.2 the `sentinel` extra resolved `azure-mgmt-securityinsight` 1.0.0, which lacks that model, so every rule with `alert.dynamic_properties` failed to deploy while the dry-run still passed. Since 0.16.0 opentide calls the ARM REST API directly and no longer uses that SDK; upgrade with `pip install -U opentide`.
- **`configurations.sentinel.grouping.alert is missing`** — Sentinel deploy needs `grouping.event` and `grouping.alert`. The error names the rule UUID, and `deploy --dry-run` reports it too. Through 0.14.2 it was `AttributeError: 'NoneType' object has no attribute 'enabled'`.
- **A rule did not deploy** — check the strategy its status maps to, the run's `--strategy`, and the tenant's `strategies`. A `PREVIEW` run skips a rule in `PRODUCTION` (it maps to `RELEASE`), a `RELEASE` run skips a rule in `DEVELOPMENT` (it maps to `PREVIEW`, unless promotion rewrites it first), `INERT` rules never deploy, and a tenant with `strategies = ["RELEASE"]` never receives a `PREVIEW` run. `deploy` counts the rules a status kept out and names the statuses that would deploy (`skipped` in JSON); with `--debug`, the `rule_skipped_for_strategy` and `skipping_tenant` log lines name all three. Outside CI, deploy reads the last commit only: commit the rule, or pass `--all`. See [Statuses, strategies and tenants](../usage/concepts/statuses-and-strategies.md).
- **`--strategy 'STAGING' is not a deployable strategy`** — `STAGING` is a default status name (and was a deployment plan). Pass `--strategy PREVIEW`. The message names the strategy any configured status maps to.
- **`the tenant key 'deployment' was removed in 0.17.0`** — replace the tenant's `deployment` line as the message says: `STAGING` becomes `strategies = ["PREVIEW"]`, `PRODUCTION` becomes `strategies = ["RELEASE"]`, `ALWAYS` is dropped, `MANUAL` becomes `manual = true`.
- **`--plan was removed` / `DEPLOYMENT_PLAN was removed`** — use `--strategy`, and unset `DEPLOYMENT_PLAN` in your CI variables. Regenerate the pipeline with `opentide setup ci <github|gitlab|azure>`.
- **`deploy reads the rule files the last commit, push or pull request changed, which needs a git checkout`** — run inside the repository, or pass `--all`.
- **`No rule file changed in this run's commits; pass --all to deploy every rule file`** — without `--all`, `--uuid` or `--file`, deploy reads the rule files the last commit, push or pull request changed, and none did: it reports `skipped` with exit `0` and contacts no platform. Pass `--all` to deploy every rule file. When a rule file did change but no status deploys with the run's `--strategy`, the message is `No rule this run read has a status that maps to its strategies` instead.
- **`HEAD names no commit yet (a new repository or an orphan branch), so no file has changed`** — a repository fresh from `git init`, or a branch made with `git checkout --orphan`, has no last commit to read, so deploy reads no rule: it reports `skipped` with exit `0` and this warning, and contacts no platform. Commit the rules, or pass `--all` (or `--uuid`, `--file`). In CI the run's commit must be in the checkout, so there the run still fails with exit `1` (on a push whose diff base is read from `HEAD`: `The git repository at <path> has no commits yet`). Through 0.21.0 both failed with `b'HEAD'`.
- **`N uncommitted object files are not in scope (…); commit them or pass --file`** — outside CI, deploy's default scope is the rule files the last commit changed, read from disk as they are now. A rule file in the rules folder that you edited, staged or created, and that commit did not touch, is not in it, so the run names up to three of them and goes on. Commit them, or pass `--file` to deploy a file as it is on disk. A file deleted from disk is not named. CI runs never give this note.
- **`warning: … rule file(s) in subfolders of objects/rules are not deployed`** — a rule file has to sit directly in `objects/rules/`. A file in a subdirectory is outside the rule catalogue and is not deployed. Move it up into `objects/rules/` to deploy it. In CI, the warning names only the subdirectory files the change touched.
- **Platform not found**, or **`system_disabled_for_deploy`** in the log — the platform is not enabled in your workspace config. A disabled platform is never selected and its engine never loads, for every `--strategy` and with `--wide`, even when the rule's own block says `enabled: true`. The log names the command that enables it, such as `opentide setup platforms --microsoft-defender`. `opentide validate` reports such a block as a `platform_not_enabled` warning.
- **`external_id_in_rule`** — the rule still carries `rule_id`, `rule_id_bundle` or `rule_id::<tenant>` on some platform block. Deploy leaves it out for every platform, `--dry-run` included, before any HTTP call, and the run exits `1`; other rules still deploy. Run [`deploy migrate-state`](#deploy-migrate-state) and commit the result.
- **`external_id_missing`** (warning) — a deletion or disablement found no id for that tenant in `.opentide/states/deployment/`, so nothing is known to exist there and nothing is called. The run does not fail on it: retiring a rule that never reached a tenant is normal. If a remote copy does exist, remove or disable it by hand.
- **`deployment_state_unpersisted`** — a CI run other than `--strategy RELEASE` on a push (the pull-request `PREVIEW` job, for example) would create a rule on a platform that keeps vendor ids (see [Deployment state](../usage/concepts/deployment-state.md#the-shard)), and nothing would commit the id it returns. The create was refused before any vendor call and the run exits `1`; updates and deletes of rules that already have an id still ran. The production job creates the rule after merge. Pass `--persist-state-externally` only if your pipeline commits `.opentide/states/deployment/` itself.
- **`deployment_state_ignored`** — `.gitignore` hides `.opentide/states/deployment/`, so deploy will not create a rule on a platform that keeps vendor ids, whose id git would never see. Ignore `.opentide/states/sharing.jsonl` instead. See [Deployment state](../usage/concepts/deployment-state.md) for the other `deployment_state_*` codes.
- **`bitdefender_yara_rule_limit`** — GravityZone holds at most 50 YARA rules per company (bitdefender-1.0). When the YARA rules `.opentide/states/deployment/` records on a Bitdefender tenant plus those the run creates would pass 50, deploy refuses each YARA create on that tenant before sending anything, and names the counts; updates, deletions and custom detection rules go on. Retire YARA rules (a status that maps to deletion) in one run, then create in the next: a deletion in the same run makes no room, since rules are sent in plan order. The count is per tenant, each with its own `company_id`. It reads each recorded rule's kind from the workspace as it is now, and leaves out a rule the workspace no longer holds or whose block does not read, and any YARA rule created outside opentide.
- **`skipped` with no rules in a new repository** — git does not keep empty folders, so a fresh clone has no `objects/rules/` until the first rule is committed. Deploy treats the missing folder as an empty catalogue: it reports `skipped` with exit `0`, an empty `plan`, and the `dry_run` flag, and contacts no platform.
- **No tenants** — `setup repo` enables a platform and leaves the `[[tenants]]` example commented out. A real `deploy` of rules for that platform exits `1` before any engine loads, and names the file to edit. `--dry-run` still previews the payloads and warns that a real deploy would stop.
- **GitLab `No Source Commit Found`** — a merge request pipeline whose `CI_MERGE_REQUEST_DIFF_BASE_SHA` is missing or not in the checkout exits `1` with that sentence. (A push pipeline whose `CI_COMMIT_BEFORE_SHA` the checkout does not hold falls back with a warning instead; see the next entry.) Fetch full history (`GIT_DEPTH: "0"`), as the generated jobs do. Through 0.6.1 the same case crashed with `'Repo' object has no attribute 'lookup_ref'`.
- **`status promotion skipped: …`** — a `RELEASE` run on a push promotes only on the default branch. opentide reads the pushed branch from `GITHUB_REF`, `CI_COMMIT_BRANCH` or `BUILD_SOURCEBRANCH`, and the default branch from `OPENTIDE_DEFAULT_BRANCH`, else GitHub's event payload or GitLab's `CI_DEFAULT_BRANCH`. Where one is missing (Azure Pipelines has no default-branch variable; another CI system sets neither; GitHub has no event file), the run deploys without promoting and the warning names what to set. On another CI system, set `CI_COMMIT_BRANCH` to the pushed branch and `OPENTIDE_DEFAULT_BRANCH` to the default branch; or regenerate the pipeline with `opentide setup ci <github|gitlab|azure> --yes`. When `OPENTIDE_DEFAULT_BRANCH` differs from GitHub's own default branch and the push is to GitHub's, a second warning names both values: the variable is stale, for instance after the branch was renamed.
- **Which commits a push deploys** — a push diffs from the commit the branch held before it: GitHub's push event `before`, GitLab's `CI_COMMIT_BEFORE_SHA`. So a push of several commits deploys the rules each of them changed. A push that created the branch (an all-zero `before`, as on the first push of a new repository) reads every file of the pushed commit. Azure Pipelines names no such commit itself (the generated Azure pipeline sets `OPENTIDE_PUSH_BASE` from the pipeline's last successful build of the branch, see [CI/CD](../usage/workflows/ci-cd.md#which-commits-an-azure-push-deploys)), so there when `OPENTIDE_PUSH_BASE` is unset, and on GitHub or GitLab when the commit is missing (no push event, a `before` the checkout does not hold after a force push, a manual or scheduled GitLab pipeline, whose `CI_COMMIT_BEFORE_SHA` is all zeros), the run diffs from the last commit's first parent and warns `This push's diff starts at its last commit's parent: … pass --all to deploy every rule file`. Pass `--all` when that push held several commits, or set `OPENTIDE_PUSH_BASE` to the commit the diff starts at (any provider, on a push: it must be an ancestor of `HEAD`, else the run exits `2`, and the run does not warn). On Azure the warning is also an issue in the build summary (`##vso[task.logissue type=warning]`); `validate query --changed` and `lint --changed` give it too. A shallow checkout (`fetch-depth: 1`) that lacks the `before` commit or the pushed commit's parent fails with `Could not find git commit <sha>: the checkout is shallow, …` (a push that creates its branch needs neither, so it still works); check out the full history, as the generated pipelines do. A repository's first commit has no parent: every file it holds counts as added. Through 0.16.1 an all-zero `CI_COMMIT_BEFORE_SHA` failed with `No Source Commit Found`.
- **GitHub pull request diff without pull-request refs** — the failure names `GITHUB_HEAD_REF` and `GITHUB_BASE_REF`. Through 0.6.1 it asked for Azure `SYSTEM_PULLREQUEST_SOURCEBRANCH` and `SYSTEM_PULLREQUEST_TARGETBRANCHNAME`, then `KeyError`.
- **Other CI diff failures** — a missing tip SHA names `CI_COMMIT_SHA`, `GITHUB_SHA`, or `BUILD_SOURCEVERSION`. An Azure pull request without its pull-request variables names those variables before fetching. A ref that is not on `origin` names `origin/<name>`. A one-parent GitLab merged result keeps the tip SHA.
- **GitHub production deploy skipped** — through 0.6.3 the generated production job needed `deploy_staging`, which runs only on a pull request, so a push to the default branch skipped production. 0.6.4 needs `generate` and still runs only on that push. Regenerate with `opentide setup ci github --yes`.
- **`DISABLED` or `REMOVED` rule never retired** — through 0.14.2 `--keep-deprecated` defaulted to off, so the default-branch deploy dropped those rules. A `RELEASE` run now keeps them by default; pass `--drop-deprecated` for the old behaviour. With `--all` they are left out unless you pass `--keep-deprecated`.
- **Default-branch deploy empty or wrong after a merge commit** — the GitHub and Azure push diff runs from HEAD's first parent (`HEAD^1`), the default branch before the merge. Through 0.14.2 the base was the second commit by date, which on a merge commit is usually the merged branch's head: the rules the merge changed were not deployed, and a pull-request job on the synthetic merge ref reported `skipped`. GitLab uses `CI_COMMIT_BEFORE_SHA` and was not affected.
- **Shallow checkout** — deploy jobs fetch full history. A missing parent commit is named. Through 0.6.3 a depth-1 checkout exited `1` with the parent SHA and no sentence.

## Per-rule deployment via SDK or MCP

```python
from opentide import Workspace

ws = Workspace.open(".")
plan = ws.deploy_plan(uuids=[uuid], platform="sentinel", strategies=["PREVIEW"])  # nothing sent
```

`Workspace.deploy_plan` is `deploy --dry-run` for those rules ([Workspace](../sdk/workspace.md#plan-a-deploy)); a real deploy is `ws.run_json(["deploy", "--uuid", uuid, "--platform", "sentinel", "--strategy", "RELEASE"])`. MCP: `deploy_rule(uuid, platform, dry_run=True)` (defaults to dry-run) deploys one rule by the run strategies that deploy the strategy its block's status maps to, to the tenants that accept them. On the command line, `deploy --uuid` does the same for one rule or several, with the dry run's rendered `payloads` ([Selecting rules](#selecting-rules)).

## Source

`crates/opentide-cli/src/commands/deploy.rs`, `crates/opentide-cli/src/commands/deploy_send.rs`, `crates/opentide-cli/src/commands/deploy_promote.rs`, `crates/opentide-cli/src/commands/migrate_state.rs`, `crates/opentide-compile/` (compile and plan), `crates/opentide-connectors/` (the platforms)
