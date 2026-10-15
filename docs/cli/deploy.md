---
title: opentide deploy
description: Deploy detection rules to configured platforms with dry-run, promotion, and plan controls.
---

# opentide deploy

Deploy detection rules to configured platforms, honoring each rule's `status` and your deployment plan.

```bash
opentide deploy --platform sentinel --dry-run
opentide deploy --platform splunk --plan STAGING
```

## When to use it

- On merge to `main` in CI, to push validated rules to a platform.
- Locally with `--dry-run` to preview exactly what a deploy would change.

Always `--dry-run` first, and always [validate](./validate.md) before deploying.

## Prerequisites

A real (non-dry-run) deploy contacts the platform API, so it needs:

1. The platform **enabled** in `.opentide/configurations/platforms/<name>.toml`.
2. **Credentials** for that platform, typically via environment variables referenced from the platform TOML — see [Configuration → credentials](../usage/configuration.md#credentials).

`--dry-run` needs neither and is safe to run anywhere.

## Options

| Flag | Env | Purpose |
|------|-----|---------|
| `--platform` | — | Target platform (see [platforms](../usage/concepts/platforms.md)) |
| `--plan` | `DEPLOYMENT_PLAN` | Deployment plan / strategy |
| `--wide` | — | Wide output |
| `--dry-run` | — | Simulate deployment without writes |
| `--keep-deprecated` / `--drop-deprecated` | — | Include rules whose status strategy is `DISABLEMENT` or `DELETION`, so the deploy disables or deletes them. Default: on for `--plan PRODUCTION`, off for other plans |
| `--skip-promotion` | — | Skip promotion step |
| `--skip-unconfigured` | — | Exit 0 when every platform in the plan has no `[[tenants]]` block |

## Output

A dry-run in the [tutorial](../usage/tutorial.md) repository prints the section header on stderr and the result on stdout:

```bash
opentide deploy --platform sentinel --dry-run
```

```text output-of="opentide deploy --platform sentinel --dry-run"
== MDR Deployment ==
OK Deployment completed
```

A colour terminal draws the header as a rule. Human output does not list the rules; `DEBUG=1` logs each selected rule to stderr, and `--json` returns the plan:

```bash
opentide --json deploy --platform sentinel --dry-run
```

```json output-of="opentide --json deploy --platform sentinel --dry-run"
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
  "message": "Deployment completed",
  "warnings": [
    "sentinel has no tenants configured in .opentide/configurations/platforms/sentinel.toml, so a real deploy would stop"
  ]
}
```

`plan` lists the rule UUIDs selected for each platform. `payloads` is present on dry-runs only; each rule's `api_request` (elided here) is the ARM request body the Sentinel deployer compiles when the `sentinel` extra is installed, and otherwise the rule's platform configuration block. A Sentinel rule that would fail to deploy (an unparseable duration, or a missing `grouping` or `grouping.alert`) is listed with `"status": "failed"`, an `error` naming the cause, and a null `api_request`; the error is also logged with the rule's name and UUID, and the dry-run reports `failed` and exits `1`. The [tutorial](../usage/tutorial.md) scaffold leaves `[[tenants]]` commented out, so this dry-run previews the payload, leaves `deployed` empty, and warns that a real deploy would stop. After you uncomment a tenant, `deployed` lists the platform and the warning is gone. A real deploy returns the same envelope with `"dry_run": false` and no `payloads`. Non-zero [exit codes](./exit-codes.md) signal deployment errors.

When no rules match the selected plan, the command reports `skipped` with exit `0`. The reserved `deploy metadata` command is hidden and returns a non-zero “not implemented” result rather than reporting false success.

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
FATAL: Metadata deployment is not implemented for splunk
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
- **`AttributeError: module 'azure.mgmt.securityinsight.models' has no attribute 'AlertPropertyMapping'`** — through 0.14.2 the `sentinel` extra resolved `azure-mgmt-securityinsight` 1.0.0, which lacks that model, so every rule with `alert.dynamic_properties` failed to deploy while the dry-run still passed. The extra now requires 2.0.0b2 or later; run `pip install -U 'opentide[sentinel]'`.
- **`configurations.sentinel.grouping.alert is missing`** — Sentinel deploy needs `grouping.event` and `grouping.alert`. The error names the rule UUID, and `deploy --dry-run` reports it too. Through 0.14.2 it was `AttributeError: 'NoneType' object has no attribute 'enabled'`.
- **A rule did not deploy** — check its `status` strategy; `INERT` statuses never deploy. See [Configuration → deployment statuses](../usage/configuration.md#deployment-statuses-and-strategies).
- **`WARNING … rule file(s) in subfolders of objects/rules are not deployed`** — a rule file has to sit directly in `objects/rules/`. A file in a subdirectory is outside the rule catalogue and is not deployed. Move it up into `objects/rules/` to deploy it. In CI, the warning names only the subdirectory files the change touched.
- **Platform not found** — it is not enabled in your workspace config.
- **`external_id_in_rule`** — the rule still carries `rule_id`, `rule_id_bundle` or `rule_id::<tenant>` on some platform block. The deployment plan leaves it out for every platform, `--dry-run` included, before any HTTP call, and the run exits `1`; other rules still deploy. Run [`deploy migrate-state`](#deploy-migrate-state) and commit the result.
- **`external_id_missing`** (warning) — a deletion or disablement found no id for that tenant in `.opentide/states/deployment/`, so nothing is known to exist there and nothing is called. The run does not fail on it: retiring a rule that never reached a tenant is normal. If a remote copy does exist, remove or disable it by hand.
- **`deployment_state_ignored`** — `.gitignore` hides `.opentide/states/deployment/`, so deploy will not create a Defender, SentinelOne or CrowdStrike rule whose id git would never see. Ignore `.opentide/states/sharing.jsonl` instead. See [Deployment state](../usage/concepts/deployment-state.md) for the other `deployment_state_*` codes.
- **`skipped` with no rules in a new repository** — git does not keep empty folders, so a fresh clone has no `objects/rules/` until the first rule is committed. Deploy treats the missing folder as an empty catalogue: it reports `skipped` with exit `0`, an empty `plan`, and the `dry_run` flag, and contacts no platform.
- **No tenants** — `setup repo` enables a platform and leaves the `[[tenants]]` example commented out. A real `deploy` of rules for that platform exits `1` before any engine loads, and names the file to edit. `--dry-run` still previews the payloads and warns that a real deploy would stop.
- **GitLab `No Source Commit Found`** — a `STAGING` or `PRODUCTION` plan whose base SHA is unset or not in the checkout exits `1` with that sentence. Through 0.6.1 the same case crashed with `'Repo' object has no attribute 'lookup_ref'`.
- **GitHub `STAGING` without pull-request refs** — the failure names `GITHUB_HEAD_REF` and `GITHUB_BASE_REF`. Through 0.6.1 it asked for Azure `SYSTEM_PULLREQUEST_SOURCEBRANCH` and `SYSTEM_PULLREQUEST_TARGETBRANCHNAME`, then `KeyError`.
- **Other CI diff failures** — a missing tip SHA names `CI_COMMIT_SHA`, `GITHUB_SHA`, or `BUILD_SOURCEVERSION`. Azure `STAGING` without its pull-request variables names those variables before fetching. A ref that is not on `origin` names `origin/<name>`. `DEBUG`, `MANUAL`, and `ALWAYS` say they are not a CI diff plan. A one-parent GitLab merged result keeps the tip SHA.
- **GitHub production deploy skipped** — through 0.6.3 the generated production job needed `deploy_staging`, which runs only on a pull request, so a push to the default branch skipped production. 0.6.4 needs `generate` and still runs only on that push. Regenerate with `opentide setup ci github --yes`.
- **`DISABLED` or `REMOVED` rule never retired** — through 0.14.2 `--keep-deprecated` defaulted to off for every plan, so a `PRODUCTION` deploy dropped those rules before its allow-list, which includes both strategies, was consulted. `PRODUCTION` now keeps them by default; pass `--drop-deprecated` for the old behaviour. Other plans are unchanged.
- **`PRODUCTION` plan empty or wrong after a merge commit** — the GitHub and Azure `PRODUCTION` diff runs from HEAD's first parent (`HEAD^1`), the default branch before the merge. Through 0.14.2 the base was the second commit by date, which on a merge commit is usually the merged branch's head: the rules the merge changed were not deployed, and a pull-request job on the synthetic merge ref reported `skipped`. GitLab uses `CI_COMMIT_BEFORE_SHA` and was not affected.
- **Shallow checkout** — deploy jobs fetch full history. A missing parent commit is named. Through 0.6.3 a depth-1 checkout exited `1` with the parent SHA and no sentence.

## Per-rule deployment via SDK or MCP

```python
rule = OpenTide.Rules[uuid]
result = rule.deploy("sentinel", dry_run=True)
```

MCP: `deploy_rule(uuid, platform, dry_run=True)` (defaults to dry-run).

## Source

`src/opentide/cli/__init__.py`, `src/opentide/cli/services/deploy.py`, `src/opentide/cli/services/migrate_state.py`
