---
title: opentide validate
description: Object validation (schema, UUID, uniqueness) and platform query syntax validation.
---

# opentide validate

Validates detection objects and platform query syntax.

## Object validation (default)

```bash
opentide validate
opentide validate --strict
opentide validate --file objects/rules/example.yaml
opentide validate --uuid <uuid> --uuid <uuid2>
opentide validate --type rule
opentide validate --check schema
```

### Options

| Flag | Purpose |
|------|---------|
| `--check` | Run a single check: `id-uniqueness`, `uuid-format`, `schema`, `cve`, `sharing-config` |
| `--file` | Validate one YAML file — repo-relative path, absolute path, or bare file name (see [Selecting a file](#selecting-a-file)). Repeatable: each `--file` adds a file to the scope |
| `--uuid` | Validate specific UUIDs (repeatable) |
| `--type` | Filter by object type (repeatable) |
| `--strict` | Treat warnings as failures (exit `1`) |

`--strict` fails warning runs with exit `1`. Without it, warnings are reported in output and the process still exits `0`. Validation failures in `--json` mode include the complete report before the process exits.

`sharing-config` is off unless you pass `--check sharing-config`. It checks the merged `sharing.toml`: required MISP fields, block names, unknown keys, `max_tlp`, organisation UUIDs, object types, and a `sharing/` configuration directory. `opentide share push` runs the same check. A literal API key is a warning and is never printed.

Without `--json`, issues are listed in a **Validation issues** panel, grouped by file, one `[severity] field: message` line each — for example `[error] detection_model: Unknown objective or signal reference '…'`.

Filename conventions and recommended metadata are **not** schema errors — use [`opentide lint`](./lint.md).

### One JSON shape for every invocation

`--json` emits the same document whichever way you invoke validation. The full
report is always under `report`, and `checks` always maps a check name to that
check's verdict. Passing `--check` narrows `checks` to the one check you asked
for and adds `check` naming it; it does **not** move the report.

```bash
opentide --json validate --check schema
```

```json output-of="opentide --json validate --check schema"
{
  "checks": {
    "schema": { "check": "schema", "status": "passed" }
  },
  "report": {
    "ok": true,
    "issues": []
  },
  "check": "schema",
  "workspace": "...",
  "ok": true,
  "status": "passed"
}
```

So one expression reads the issue list regardless of invocation:

```bash
opentide --json validate                  | jq '.report.issues'
opentide --json validate --check schema   | jq '.report.issues'
```

!!! warning "Changed in 0.13.0"

    `--check` previously returned a different document from a bare `validate`:
    the report was placed under `issues` (so the list was at `issues.issues`)
    and a legacy `errors` map, keyed by UUID, was emitted alongside it. Neither
    appeared on a bare run, so a consumer could not parse both the same way.
    Both paths now emit the shape above. Read `report.issues` instead of
    `issues.issues`, and replace `errors` with `report.issues`, which carries
    the same failures with their field paths, codes and line numbers.

### Which workspace was checked

Run from anywhere inside the detection workspace: the CLI walks up to it (see [Repository root resolution](./global-options.md#repository-root-resolution)). The JSON payload names the directory it read objects from under `workspace`.

An empty catalogue is not an error. A full run that checked no objects still passes with exit `0`, `--strict` included, but says where it looked:

```text illustrative
OK Validation passed, but no detection objects were found under /home/you/monorepo
```

If that path is not your workspace, `cd` into it or pass `--repo`.

### Selecting a file

Object folders may contain subfolders, and files in different folders may share a name. `--file` matches like this:

| Target | Matches |
|--------|---------|
| Repo-relative path (`objects/rules/team-a/rule.yaml`, `./objects/rules/team-a/rule.yaml`) | That file only. It is resolved from the working directory and from the repository root, so it also works from outside the repo or with `--repo`. |
| Absolute path | That file only. |
| Bare file name (`rule.yaml`) | Every object file with that name, in any object folder or subfolder. |

A path never falls back to its file name: `objects/rules/rule.yaml` does not select `objects/rules/team-a/rule.yaml`, and a path that names no object file fails with `scope_no_match`. Give a path when a file name is not unique.

Every issue reports the `file_path` of the object it concerns, so issues from two files that share a name stay apart when a bare file name selects both.

### Unparseable object files

An object file that is not valid YAML is reported as a `yaml_parse` issue against that path (exit `1`, and a complete report in `--json` mode) instead of raising a parser traceback. The file is not indexed, so no other check can see it — the issue is emitted regardless of `--check`.

### Vendor rule ids

`rule_id`, `rule_id_bundle` and `rule_id::<tenant>` are not keys of any platform block. A rule that still carries one fails the `schema` check with `external_id_in_rule` at that field. Vendor ids belong in [deployment state](../usage/concepts/deployment-state.md); move them with [`opentide deploy migrate-state`](./deploy.md#deploy-migrate-state). A full-workspace run also checks every `*.json` under `.opentide/states/deployment/`, including orphan shards whose rule was deleted, and fails each unusable one with its `deployment_state_*` code (a non-canonical file name, a second file for the same rule, or a tenant key with surrounding spaces included). A run narrowed with `--file`, `--uuid` or `--type` checks the shards of the selected rules only. A rule without a shard is fine.

### CVE check

`opentide validate --check cve` looks up each `threat.cve` identifier on [CIRCL Vulnerability-Lookup](https://vulnerability.circl.lu) (`GET /api/vulnerability/{id}`). Unknown IDs (empty JSON body) fail the check. Links in generated docs use the same aggregator: `https://vulnerability.circl.lu/vuln/{id}`.

Accepted identifiers:

- CVE (`CVE-2024-3094`)
- GitHub Security Advisories (`GHSA-rxwq-x6h5-x525`)
- GCVE, including GNA 0 which maps to CVE (`GCVE-0-2024-3094` is stored as `CVE-2024-3094`)

The check no longer scrapes NVD through `mitrecve`. If Vulnerability-Lookup is unreachable, those identifiers are skipped (logged) rather than reported as invalid.

### Default checks

When no `--check` is specified, the pipeline runs:

- `id-uniqueness`
- `uuid-format`
- `schema` (includes vocabulary and cross-object references)

CVE lookup is **opt-in**: pass `--check cve`. It is not part of the default CLI pipeline so offline `opentide validate` stays deterministic.

## Query validation

```bash
opentide validate query --platform sentinel
opentide validate query --platform sentinel --live
opentide validate query --platform splunk --live --plan STAGING --wide
```

| Flag | Purpose |
|------|---------|
| `--platform` | **Required.** Platform enum value |
| `--live` | Check the catalogue queries against the tenant (needs SDKs + credentials) |
| `--plan` | Deployment plan (`DEPLOYMENT_PLAN` env) — `--live` only |
| `--wide` | Wide output format — `--live` only |

### The tenant check is `--live`

Query validation is tenant-only. A bare `validate query` is not an offline check and does not scan query text. It exits `1` and names `--live`. `--live` fails when a credential is still an unsubstituted `$VARIABLE` placeholder:

```bash
opentide --json validate query --platform sentinel
```

```json output-of="opentide --json validate query --platform sentinel" exit=1
{
  "platform": "sentinel",
  "supported": true,
  "ok": false,
  "status": "failed",
  "message": "Query validation checks the tenant. Re-run with --live."
}
```

### `--live`

`--live` builds the platform client and submits the catalogue queries, so it needs the
matching extra (`pip install 'opentide[sentinel]'`) and tenant credentials. When
the SDK is absent the command fails with the extra to install rather than a
`ModuleNotFoundError` traceback: the `advice` field in `--json`, an
`advice: install opentide[sentinel] …` line under the `FATAL` line otherwise.
A missing SDK or a missing plan is a failed live check.
Only the requested platform's engine is
loaded — validating Sentinel never imports the CrowdStrike or HarfangLab
modules. A platform with no `[[tenants]]` entry fails the same way, before the
client is built, and names the file to edit.

### Which tenants are checked

A live check only reads, so it is not bound by the tenant `deployment`
strategy the way `deploy` is. With no `--plan` (the `FULL` plan), every
tenant a rule can reach is checked: `STAGING`, `PRODUCTION` and `ALWAYS`
tenants, and a `MANUAL` tenant when the rule lists it under `tenants`. A
rule's `tenants` list still limits it to those tenants. `--plan STAGING` or
`--plan PRODUCTION` narrows the check to the tenants that plan deploys to.
When that leaves every rule without a tenant (for example, only staging-only
rules under `--plan PRODUCTION`), nothing needed checking: the result is
`skipped` with exit `0`. Exit `2` is kept for rules that reach no configured
tenant at all, where the check could never run.
`deploy` itself is unchanged: a `FULL` deploy still targets only `ALWAYS`,
listed `MANUAL` and plan-equal tenants.

`--json` reports the plan and how many queries each tenant received. The sample is illustrative, because a live run needs tenant credentials:

```json illustrative
{
  "platform": "sentinel",
  "mode": "live",
  "status": "passed",
  "plan": "FULL",
  "queries_validated": 4,
  "queries_per_tenant": { "Staging": 2, "Production": 2 }
}
```

A run that sends no query never reports `passed`. When the plan has rules for
the platform but none of them resolves to a configured tenant, the command
reports `skipped`, names the reason in `message` and `advice`, and exits `2`,
the same code the generated CI credential guard uses for a check that did not
run. Through 0.14.2 that case printed `Query validation passed` with zero
queries sent, which made the generated pipeline's live gate a no-op for the
usual `STAGING` + `PRODUCTION` tenant layout. A plan with no rules for the
platform at all is still `skipped` with exit `0`: there is nothing to check.

### Supported platforms

Query validation works on **five platforms** only:

- `sentinel` (KQL)
- `defender_for_endpoint` (KQL)
- `splunk` (SPL)
- `sentinel_one` (S1QL)
- `carbon_black_cloud` (Lucene)

CrowdStrike (correlation filter) and HarfangLab (Sigma or YARA) return unsupported — never fake validation. The fields on each `configurations` block, required and optional, are the [platform specs](/docs/specifications/specs/platforms/). [Platforms](../usage/concepts/platforms.md#platform-block-schemas) links each one.

The result is a normal failure envelope, so `--json` shape does not change between
supported and unsupported platforms:

```bash
opentide --json validate query --platform crowdstrike
```

```json output-of="opentide --json validate query --platform crowdstrike" exit=1
{
  "platform": "crowdstrike",
  "valid": null,
  "supported": false,
  "ok": false,
  "status": "failed",
  "message": "query validation not supported for crowdstrike"
}
```

The process exits `1`.

## SDK equivalent

```python
from opentide.validation.session import run_validation
from opentide.validation.scope import ValidationScope

report = run_validation(scope=ValidationScope.full())
print(report.ok, len(report.errors))
```

See [SDK validation](../sdk/validation.md).

## Source

`src/opentide/cli/__init__.py`, `src/opentide/cli/services/validation.py`
