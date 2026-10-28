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
| `--all` | Read every rule file. Without it, deploy reads the rule files the run changed: the pull or merge request (from its merge base), the push, or outside CI the last commit |
| `--platform` | Target platform (see [platforms](../usage/concepts/platforms.md)) |
| `--wide` | Deploy the rule files read whatever their status strategy, `INERT` included, to the tenants accepting the run's strategies. `DISABLEMENT` and `DELETION` still follow `--keep-deprecated` |
| `--dry-run` | Simulate deployment without writes. `--json` lists the tenants each rule would reach |
| `--keep-deprecated` / `--drop-deprecated` | Include rules whose status maps to `DISABLEMENT` or `DELETION`, so a `RELEASE` run disables or deletes them. Default: on, off with `--all` |
| `--skip-promotion` | Skip the promotion step of a `RELEASE` run on a push |
| `--skip-unconfigured` | Exit 0 when every platform with rules to deploy has no `[[tenants]]` block |
| `--persist-state-externally` | In CI, allow a run other than `--strategy RELEASE` on a push to create Defender for Endpoint, SentinelOne and CrowdStrike rules. Pass it only when the pipeline commits `.opentide/states/deployment/` itself; see [Creates outside the production job](../usage/concepts/deployment-state.md#creates-outside-the-production-job) |

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

warning: sentinel has no tenants configured in .opentide/configurations/platforms/sentinel.toml, so a real deploy would stop
Plan: 0 to create, 0 to update, 1 to create or update, 0 to disable, 0 to delete
  help: add (or uncomment) a [[tenants]] entry in .opentide/configurations/platforms/sentinel.toml
dry run, nothing sent
```

Defender for Endpoint, SentinelOne and CrowdStrike keep vendor ids in `.opentide/states/deployment/`, so their rows say `create` or `update`. The other platforms write a rule by its UUID whether it exists or not, and opentide does not claim either: their rows say `create or update`. A dry run ends with `dry run, nothing sent` after the tally and any next steps. A real run reports each rule as it is sent and ends with a counted outcome line; see [A real run](#a-real-run). Which rules were created and which updated is the plan: it is predicted from `.opentide/states/deployment/` and each rule's status before anything is sent, not reported back by the vendor. `--json` returns the same plan under `changes`, its tally under `summary`, and the selection:

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

`plan` lists the rule UUIDs selected for each platform, and `strategies` the run's strategies. On a dry-run, `tenants` maps each platform to the tenants a real deploy would reach and the rules each would receive. `payloads` is present on dry-runs only; each rule's `api_request` (elided here) is the request body the deployer would send: the ARM alert-rule body for Sentinel, the Kibana rule body for Elastic, and the rule's platform configuration block for the other platforms. A Sentinel rule that would fail to deploy (an unparseable duration, a missing `grouping` or `grouping.alert`, or an empty `response` block with no `alert.severity`) is listed with `"status": "failed"`, a `code`, an `error` naming the cause, a `help`, and a null `api_request`. `diagnostics` holds one entry per such rule (`code`, `severity`, `message`, `help`, a workspace-relative `path`, `platform`, `uuid`, `name`), and the dry-run reports `failed` and exits `1`. The plan prints each one as a [code frame](./validate.md), like `validate` and `lint`, above its tally, which keeps no glyph:

```text
error[compile_empty_block]: 'response' is empty, so Sentinel cannot read 'alert_severity'
  ╭─▶ objects/rules/sentinel-kql-rule.yaml
  ╰─ help: set response.alert_severity, or configurations.sentinel.alert.severity

Plan: 0 to create, 0 to update, 0 to disable, 0 to delete, 1 would fail
dry run, nothing sent
```

The rule's row in the plan reads `✗ would fail` instead of its action, and the tally counts it apart (`N would fail`, `summary.fail`; each such entry of `changes` has `"fails": true`), since a rule that cannot compile is created or updated nowhere.

The codes are `compile_missing_field`, `compile_empty_block`, `compile_invalid_value`, `compile_invalid_rule` and `compile_failed`. A dry run sends nothing, so an unset `$VARIABLE` in a tenant's setup is a warning there (`a real deploy would need $AZURE_CLIENT_SECRET, which is unset`), not an error. The [tutorial](../usage/tutorial.md) scaffold leaves `[[tenants]]` commented out, so this dry-run previews the payload, leaves `deployed` empty, and warns that a real deploy would stop. After you uncomment a tenant, `deployed` lists the platform and the warning is gone. A real deploy returns the same envelope with `"dry_run": false` and no `payloads`. Non-zero [exit codes](./exit-codes.md) signal deployment errors.

When no rule the run read has a status mapping to its strategies, the command reports `skipped` with exit `0`. The reserved `deploy metadata` command is hidden and returns a non-zero “not implemented” result rather than reporting false success.

## A real run

A real run prints the plan's header and tally, then one line for each rule as the platform answers, so a CI log shows progress while a platform is slow, and the last line says which rule it is waiting on. The lines are append-only: no spinner and no carriage return unless stdout is a terminal, where the running rule is also shown on a live row that its result line replaces. The samples below are illustrative, not captured output: a real run needs a live tenant.

```text illustrative
Deploy plan · strategy PREVIEW · 1 platform, 1 tenant
Plan: 0 to create, 0 to update, 14 to create or update, 0 to disable, 0 to delete

Deploying to sentinel / contoso · 14 rules
  [ 1/14] ✓ deployed  Sentinel KQL Rule                           0.4s
  [ 2/14] ✓ deployed  Staging Promote Rule                        0.4s
  [ 3/14] ✗ failed    Password spray from a single source IP      HTTP 400: Failed to parse query: syntax error near '|'
  [ 4/14] · skipped   New service installed on domain controller  not attempted after a failure
  ...
✗ sentinel · 2 deployed, 1 failed, 11 not attempted · 1.2s
✗ Deployment failed · 2 created or updated, 1 failed, 11 not attempted · 1.2s
```

| Line | Meaning |
|------|---------|
| `✓ created`, `✓ updated`, `✓ disabled`, `✓ deleted` | The platform accepted the rule. The word is the planned action. A platform that writes a rule by its UUID says `deployed`, since opentide cannot tell a create from an update |
| `✗ failed` | The platform, or planning, refused the rule. The line carries the platform's own message and its HTTP status when it has one, so the cause is readable without a traceback. A long message continues on the lines below it on a terminal and stays on one line in a log |
| `· skipped` | The rule was not sent, with the reason: an `INERT` status, a Sigma rule on a YARA tenant, a retirement of a rule that never reached the tenant (`external_id_missing`) |
| `· skipped … not attempted after a failure` | An earlier rule failed and the run stopped before this one. Every rule and platform the run never reached is listed |

When a deployer stops at the first rejected rule (Sentinel, Splunk, Carbon Black, Defender for Endpoint, SentinelOne, CrowdStrike and HarfangLab all do), the rules before it are deployed, it is `failed` and the rules after it are `not attempted`. Elastic fails a rule and carries on with the next, except for an authentication error, which fails the tenant. The run exits `1` after any failed rule, with `failure.code` `issues_found`. An error before any rule is sent, such as a tenant's credentials, has no rule to blame: every rule is `not attempted`, and the outcome line is the error.

Every run ends with the platform's counts and one outcome line, passed or failed. The outcome line always counts `failed` and `not attempted` and ends with the elapsed time; it counts an action only when some rule had it:

```text illustrative
✓ Deployed 91 rules to 1 tenant · 91 created or updated · 0 failed, 0 not attempted · 1m56s
```

`--quiet` hides the lines of rules that were deployed or skipped, never a failure. With `--json`, stdout is still one document and nothing is printed for each rule: the document carries `results`, one entry for each rule and tenant of the plan, in the order they were sent, with the rules a failure never reached last, so a pipeline can post a job summary or retry only what failed:

```bash
opentide --json deploy --strategy PREVIEW --platform sentinel
```

```json illustrative
{
  "status": "failed",
  "message": "Deployment failed · 2 created or updated, 1 failed, 11 not attempted · 1.2s",
  "error": "Deployment to sentinel failed on Password spray from a single source IP: HTTP 400: Failed to parse query: syntax error near '|'",
  "results": [
    {
      "id": "00000000-0000-4000-8003-000000000001",
      "name": "Sentinel KQL Rule",
      "platform": "sentinel",
      "tenant": "contoso",
      "action": "upsert",
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

`status` is `deployed`, `failed`, `skipped` or `not_attempted`; `action` is the plan's (`create`, `update`, `upsert`, `disable`, `delete`). `seconds` is how long the rule took, `0` when nothing was sent, and `null` for a platform whose engine does not report its rules one at a time (the rules count as deployed). The envelope's `summary` holds every count, present even when it is `0`: `create`, `update`, `upsert`, `disable`, `delete` (rules sent with that action), `failed`, `skipped`, `not_attempted`, `seconds`, `platforms` and `tenants`. `results` is absent on a dry run.

## Subcommands

### deploy migrate-state

Moves vendor rule ids off rule files into [deployment state](../usage/concepts/deployment-state.md). Run it once, in every workspace that has deployed to Microsoft Defender for Endpoint, SentinelOne or CrowdStrike with an earlier release. It calls no vendor API and deploys nothing.

```bash
opentide deploy migrate-state
opentide --json deploy migrate-state
```

What it does:

1. **Refuses a gitignored destination.** If git ignores `.opentide/states/deployment/` (the `.opentide/states/` line older setups wrote does), it exits `1` with `deployment_state_ignored`, names the ignore line, and edits nothing. Replace that line with `.opentide/states/sharing.jsonl`; the command does not edit `.gitignore` itself.
2. **Scans every `.yaml` and `.yml` file under `objects/rules/`, subfolders included**, for `rule_id`, `rule_id_bundle` and `rule_id::<tenant>` at the root of each platform block.
3. **Writes the Defender, SentinelOne and CrowdStrike ids to `.opentide/states/deployment/<uuid>.json` first**, flushed to disk, and only then removes the keys from the YAML. Comments, key order and whitespace are kept: only the id lines go.
4. **Drops the keys of every other platform.** Sentinel, Splunk, HarfangLab, Carbon Black Cloud and the rest address their rules without a vendor id, so their keys are removed and printed as `external_id_unused` (platform, tenant, value, file), not stored.
5. **Leaves a rule untouched and exits `1`** when a tenant is mapped twice or to a different id than the shard already holds (`external_id_conflict`), or when a value is not a usable id (`external_id_shape`: not a string or integer, an empty tenant or id, or a Defender or SentinelOne id that is not a plain decimal like `12345`). Other rules still migrate.

It exits `0` after a migration, after a second run with nothing left to move, and when the only findings are `external_id_unused` warnings. It exits `1` when any rule fails or git ignores the deployment state directory. If the command stopped after writing a shard and before editing the rule, the next run finds the two agree and finishes the edit.

<Callout type="warn">
The migration is done when it is committed. Commit the edited rules together with every new file under `.opentide/states/deployment/`. A deploy from a checkout that has the stripped rules but not the shards creates a second live rule for every one of them.
</Callout>

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
- **`warning: … rule file(s) in subfolders of objects/rules are not deployed`** — a rule file has to sit directly in `objects/rules/`. A file in a subdirectory is outside the rule catalogue and is not deployed. Move it up into `objects/rules/` to deploy it. In CI, the warning names only the subdirectory files the change touched.
- **Platform not found**, or **`system_disabled_for_deploy`** in the log — the platform is not enabled in your workspace config. A disabled platform is never selected and its engine never loads, for every `--strategy` and with `--wide`, even when the rule's own block says `enabled: true`. The log names the command that enables it, such as `opentide setup platforms --defender-for-endpoint`. `opentide validate` reports such a block as a `platform_not_enabled` warning.
- **`external_id_in_rule`** — the rule still carries `rule_id`, `rule_id_bundle` or `rule_id::<tenant>` on some platform block. Deploy leaves it out for every platform, `--dry-run` included, before any HTTP call, and the run exits `1`; other rules still deploy. Run [`deploy migrate-state`](#deploy-migrate-state) and commit the result.
- **`external_id_missing`** (warning) — a deletion or disablement found no id for that tenant in `.opentide/states/deployment/`, so nothing is known to exist there and nothing is called. The run does not fail on it: retiring a rule that never reached a tenant is normal. If a remote copy does exist, remove or disable it by hand.
- **`deployment_state_unpersisted`** — a CI run other than `--strategy RELEASE` on a push (the pull-request `PREVIEW` job, for example) would create a Defender for Endpoint, SentinelOne or CrowdStrike rule, and nothing would commit the id it returns. The create was refused before any vendor call and the run exits `1`; updates and deletes of rules that already have an id still ran. The production job creates the rule after merge. Pass `--persist-state-externally` only if your pipeline commits `.opentide/states/deployment/` itself.
- **`deployment_state_ignored`** — `.gitignore` hides `.opentide/states/deployment/`, so deploy will not create a Defender, SentinelOne or CrowdStrike rule whose id git would never see. Ignore `.opentide/states/sharing.jsonl` instead. See [Deployment state](../usage/concepts/deployment-state.md) for the other `deployment_state_*` codes.
- **`skipped` with no rules in a new repository** — git does not keep empty folders, so a fresh clone has no `objects/rules/` until the first rule is committed. Deploy treats the missing folder as an empty catalogue: it reports `skipped` with exit `0`, an empty `plan`, and the `dry_run` flag, and contacts no platform.
- **No tenants** — `setup repo` enables a platform and leaves the `[[tenants]]` example commented out. A real `deploy` of rules for that platform exits `1` before any engine loads, and names the file to edit. `--dry-run` still previews the payloads and warns that a real deploy would stop.
- **GitLab `No Source Commit Found`** — a run whose base SHA is not in the checkout, or a merge request pipeline with no `CI_MERGE_REQUEST_DIFF_BASE_SHA`, exits `1` with that sentence. Fetch full history (`GIT_DEPTH: "0"`), as the generated jobs do. Through 0.6.1 the same case crashed with `'Repo' object has no attribute 'lookup_ref'`.
- **GitLab push diff on a manual run, a schedule or a branch's first push** — GitLab sets `CI_COMMIT_BEFORE_SHA` to all zeros when there is no previous tip. The run then diffs from HEAD's first parent, as on GitHub and Azure. Through 0.16.1 it failed with `No Source Commit Found`.
- **GitHub pull request diff without pull-request refs** — the failure names `GITHUB_HEAD_REF` and `GITHUB_BASE_REF`. Through 0.6.1 it asked for Azure `SYSTEM_PULLREQUEST_SOURCEBRANCH` and `SYSTEM_PULLREQUEST_TARGETBRANCHNAME`, then `KeyError`.
- **Other CI diff failures** — a missing tip SHA names `CI_COMMIT_SHA`, `GITHUB_SHA`, or `BUILD_SOURCEVERSION`. An Azure pull request without its pull-request variables names those variables before fetching. A ref that is not on `origin` names `origin/<name>`. A one-parent GitLab merged result keeps the tip SHA.
- **GitHub production deploy skipped** — through 0.6.3 the generated production job needed `deploy_staging`, which runs only on a pull request, so a push to the default branch skipped production. 0.6.4 needs `generate` and still runs only on that push. Regenerate with `opentide setup ci github --yes`.
- **`DISABLED` or `REMOVED` rule never retired** — through 0.14.2 `--keep-deprecated` defaulted to off, so the default-branch deploy dropped those rules. A `RELEASE` run now keeps them by default; pass `--drop-deprecated` for the old behaviour. With `--all` they are left out unless you pass `--keep-deprecated`.
- **Default-branch deploy empty or wrong after a merge commit** — the GitHub and Azure push diff runs from HEAD's first parent (`HEAD^1`), the default branch before the merge. Through 0.14.2 the base was the second commit by date, which on a merge commit is usually the merged branch's head: the rules the merge changed were not deployed, and a pull-request job on the synthetic merge ref reported `skipped`. GitLab uses `CI_COMMIT_BEFORE_SHA` and was not affected.
- **Shallow checkout** — deploy jobs fetch full history. A missing parent commit is named. Through 0.6.3 a depth-1 checkout exited `1` with the parent SHA and no sentence.

## Per-rule deployment via SDK or MCP

```python
rule = Opentide.Rules[uuid]
result = rule.deploy("sentinel", dry_run=True)                       # as its status says
result = rule.deploy("sentinel", dry_run=True, strategies=["PREVIEW"])
```

Without `strategies`, the rule is deployed by the run strategies that deploy the strategy its `sentinel` status maps to, to the tenants that accept them. MCP: `deploy_rule(uuid, platform, dry_run=True)` (defaults to dry-run) deploys the same way.

## Source

`src/opentide/cli/commands/deploy.py`, `src/opentide/cli/services/deploy.py`, `src/opentide/cli/services/migrate_state.py`
