---
title: MCP tools
description: Tool reference for the opentide MCP server — parameters, behaviour, and response shapes.
---

# MCP tools

Registered in `src/opentide/mcp_server/server.py`. Implementations in `src/opentide/mcp_server/tools.py`.

Each tool below lists its parameters, an example call, and an example response so an agent knows exactly what to expect. The tool descriptions an agent reads in `tools/list` say the same in a few lines each.

The server's `instructions`, sent with the `initialize` response, open with the tagline (*Spec-driven development for agentic detection engineering*) and give the agent its workflow: search, draft from a template, call `validation_report` until it is clean, then preview with `deploy_rule` and `dry_run: true`. People review and merge, and run real deployments.

### Next actions

`validate_rule`, `validation_report` and `validate_query` add a `next_actions` list: the calls worth making next.

```json
{
  "tool": "explain",
  "arguments": { "code": "vocab_unknown" },
  "command": "opentide explain vocab_unknown",
  "reason": "what vocab_unknown means and how to fix it"
}
```

`tool` and `arguments` are the MCP call. `command` is the same step as an `opentide` command line, for an agent with a shell (the CLI's own `next_actions` are `{command, reason}`). The list is empty when there is nothing to do. Every other key of these payloads is unchanged.

## search

Search the catalogue by keyword, UUID, or ATT&CK technique. Use it first when you do not know a UUID.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `query` | string | required | Search term |
| `type` | string | `""` | Object type filter: `rule`, `threat`, `objective` |
| `platform` | string | `""` | Platform filter |
| `status` | string | `""` | Rule status filter |
| `technique` | string | `""` | ATT&CK technique ID |
| `actor` | string | `""` | Threat actor filter |

```json
// call
{ "query": "credential access", "type": "objective", "technique": "T1059" }

// returns: list of match dicts
[
  {
    "uuid": "00000000-0000-4000-8002-000000000001",
    "type": "objective",
    "title": "Credential Access Objective",
    "status": null
  }
]
```

The return type is always a list of `{uuid, type, title, status}` summaries — a
UUID query yields at most one summary, an unknown UUID yields `[]`. Filters
apply to a UUID query too: `search(<rule uuid>, type="threat")` returns `[]`. Read
`opentide://rules/{uuid}` (or the matching `threats`/`objectives` resource) for
a full body.

Filter semantics:

- `platform` matches a configuration **key** exactly, so `sentinel` never
  returns `sentinel_one` rules.
- `technique` unions every location content can use: top-level `techniques`,
  `tags.techniques`, `tags.attack`, and `threat.att&ck`. Matching is
  case-insensitive.
- `actor` reads `threat.actors` (and `tags.actors`). Namespaced identifiers match
  on either form, so `att&ck::G0006` and `G0006` both hit.

## get_chaining

Return the threat → objective → rule lineage for a UUID, plus threat-to-threat links from `threat.chaining`. Use it to see which objects belong together before editing.

| Parameter | Type | Description |
|-----------|------|-------------|
| `uuid` | string | Threat, objective, or rule UUID |

```json
// call — objective that lists a threat and is the detection_model of a rule
{ "uuid": "00000000-0000-4000-8002-000000000001" }

// returns
{
  "uuid": "00000000-0000-4000-8002-000000000001",
  "found": true,
  "type": "objective",
  "graph": {
    "threats": ["00000000-0000-4000-8001-000000000001"],
    "objectives": ["00000000-0000-4000-8002-000000000001"],
    "rules": ["00000000-0000-4000-8003-000000000001"]
  },
  "lineage": {
    "threats": ["00000000-0000-4000-8001-000000000001"],
    "objectives": ["00000000-0000-4000-8002-000000000001"],
    "rules": ["00000000-0000-4000-8003-000000000001"]
  },
  "chaining_index": {
    "00000000-0000-4000-8002-000000000001": {
      "threats": ["00000000-0000-4000-8001-000000000001"],
      "objectives": ["00000000-0000-4000-8002-000000000001"],
      "rules": ["00000000-0000-4000-8003-000000000001"]
    }
  }
}
```

`rules` lists every rule in the connected set. A repository with several rules on one objective returns all of those UUIDs; the snippet above shows the shape with one rule.

When this threat has `threat.chaining` entries, `graph` stays `{relation: [vector_uuid, …]}` (for example `{"preceeds": ["…"]}`). `lineage` is still present and lists the threats, objectives, and rules reached through `objective.threats`, `rule.detection_model`, and those threat-to-threat links. `chaining_index` maps every participating UUID to that UUID's `graph`. An empty `graph` means the object has no lineage. A missing UUID returns `{ "uuid": "…", "found": false, "graph": {} }`.

The UUID is matched case-insensitively and trimmed; `uuid` in the response is the object's UUID as written in the repository. `Opentide.Models.chaining` remains the threat-to-threat map only. This tool does not write objective or rule lineage into that registry index.

## coverage

ATT&CK coverage analysis with gap identification. Use it to answer "what do we detect for T1059?" or "where are our gaps?".

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `technique` | string | `""` | When set, return coverage for that technique only |
| `tactic` | string | `""` | Echoed as `tactic_filter` when no technique is set; **does not filter** the matrix today |

Coverage reads the same technique locations as `opentide info coverage --technique <id>`:
top-level `techniques`, `tags.techniques`, `tags.attack`, and `threat.att&ck`.

Matching is case-insensitive, and a parent technique covers its sub-techniques:
`T1059` returns rules tagged `T1059` **and** `T1059.001`, `T1059.003`, … . A
sub-technique query does not widen to its parent — `T1059.001` does not return
a rule tagged only `T1059`. `matched_techniques` lists the identifiers that
answered, so you can tell parent-level from sub-technique-level coverage.

```json
// call
{ "technique": "T1059" }

// returns
{
  "technique": "T1059",
  "covered": true,
  "matched_techniques": ["T1059", "T1059.001"],
  "rules": ["00000000-0000-4000-8003-000000000001"]
}
```

Without `technique`:

```json
{
  "technique_count": 12,
  "matrix": { "T1059": ["…8003…"], "T1003": [] },
  "tactic_filter": null
}
```

## validate_rule

Validate a single rule against its schema and cross-object checks.

| Parameter | Type | Description |
|-----------|------|-------------|
| `uuid` | string | Rule UUID |

**Returns:**

```json
{
  "valid": true,
  "errors": [],
  "warnings": [],
  "issues": [],
  "next_actions": [
    {
      "tool": "deploy_rule",
      "arguments": { "uuid": "00000000-0000-4000-8003-000000000001", "platform": "sentinel", "dry_run": true },
      "command": "opentide --json deploy --dry-run --strategy PREVIEW --all --platform sentinel",
      "reason": "preview the sentinel deployment; nothing is sent"
    }
  ]
}
```

`errors` and `warnings` are strings. `issues` are the report's issues with the [diagnostic fields](#diagnostic-fields), as `validation_report` returns them. A rule that fails points `next_actions` at `explain` for its first error code (each issue's `explain` field names its own code), and then at `validate_rule` again; a valid rule points at a dry-run `deploy_rule` for each platform it has a configuration block for, unless its status there maps to `INERT`. The `command` passes the `--strategy` values that deploy the rule's status (`PREVIEW` for a `STAGING` rule, `RELEASE` for a `PRODUCTION` one) and `--all`, because the CLI has no `--uuid`: it previews every rule those strategies deploy, this one among them. An unknown UUID points at `search` with an empty query, which lists every rule with its title (the `command`, `opentide --json info rules`, lists UUIDs only).

## validation_report

Structured validation report for agents. Full registry by default; narrow with filters. Call it after every edit, until `ok` is `true`.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `file` | string | `""` | Single file: a repo-relative or absolute path matches that file only; a bare file name matches every object file with that name (as [`validate --file`](../cli/validate.md#selecting-a-file)) |
| `uuid` | string | `""` | Single UUID |
| `object_type` | string | `""` | `rule`, `threat`, or `objective` |

Returns the validation report (`ok`, `issues`, `warnings`, `stats`) plus `next_actions`. A rule with `tlp: clearr`:

```json
// call
{ "file": "objects/rules/sentinel-kql-rule.yaml" }

// returns (one issue shown)
{
  "ok": false,
  "issues": [
    {
      "code": "vocab_unknown",
      "severity": "error",
      "object_uuid": "00000000-0000-4000-8003-000000000001",
      "object_type": "rule",
      "file_path": "/work/detections/objects/rules/sentinel-kql-rule.yaml",
      "yaml_line": 7,
      "field_path": ["metadata", "tlp"],
      "message": "Value 'clearr' is not a valid 'tlp::1.0' vocabulary entry",
      "suggestion": "clear",
      "context": { "vocab": "tlp::1.0", "value": "clearr" },
      "path": "objects/rules/sentinel-kql-rule.yaml",
      "line": 8,
      "column": 8,
      "end_column": 14,
      "help": "did you mean 'clear'?",
      "fix": {
        "safe": false,
        "edits": [
          { "line": 8, "column": 8, "end_line": 8, "end_column": 14, "replacement": "clear" }
        ]
      },
      "explain": "opentide explain vocab_unknown"
    }
  ],
  "warnings": [],
  "stats": { "objects_checked": 1 },
  "next_actions": [
    {
      "tool": "explain",
      "arguments": { "code": "vocab_unknown" },
      "command": "opentide explain vocab_unknown",
      "reason": "what vocab_unknown means and how to fix it"
    },
    {
      "tool": "validation_report",
      "arguments": { "file": "objects/rules/sentinel-kql-rule.yaml" },
      "command": "opentide --json validate --file objects/rules/sentinel-kql-rule.yaml",
      "reason": "validate again after applying the fix edits"
    }
  ]
}
```

A report with errors points at `explain` for the first error code, then at `validation_report` again. When any fix is `safe`, that last step's `command` is `opentide --json validate --fix` with the same `--file`, `--uuid` or `--type`, which writes the safe fixes and validates again in one run, and its `reason` is `apply the safe fixes, then validate again`; `validate_rule` does the same with `--uuid`. A clean report has `ok: true` and an empty `next_actions`.

### Diagnostic fields

Each entry of `issues` and `warnings` (and of `validate_rule`'s `issues`) carries the same fields as [`opentide --json validate`](../cli/json-output.md). They are added; every existing key keeps its value.

| Field | Meaning |
|-------|---------|
| `path` | Workspace-relative, `/`-separated. `file_path` stays absolute. |
| `line` | 1-based. `yaml_line` stays 0-based. |
| `object_uuid` | Already on every issue: the object at fault, or `""` |
| `column`, `end_column` | 1-based Unicode code points, best effort; `end_column` is one past the last character. `null` when unknown. |
| `help` | A suggestion in prose (`did you mean 'clear'?`), or `null` |
| `fix` | `{safe, edits: [{line, column, end_line, end_column, replacement}]}` or `null`. Each edit replaces the text from (`line`, `column`) up to (`end_line`, `end_column`). `safe` is `true` only when the value and the replacement spell the same word (they differ in case, spaces, `-` or `_`) and neither has a digit: apply those as they are. Check any other edit against `help` first; `clearr` → `clear` is not safe, and an ATT&CK id or an `invalid_ref` fix never is. See [`validate`](../cli/validate.md). |
| `explain` | `opentide explain <code>`; the `explain` tool returns the same page |

## explain

What a diagnostic code means, an example, and how to fix it: the page `opentide explain <code>` prints. Codes are listed in [Diagnostic codes](../cli/diagnostics.md).

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `code` | string | `""` | An issue's `code`. Empty lists every code |

```json
// call
{ "code": "vocab_unknown" }

// returns
{
  "found": true,
  "code": "vocab_unknown",
  "meaning": "A value is not in the vocabulary its field uses.",
  "markdown": "# vocab_unknown\n\n…"
}
```

An unknown code returns `{"found": false, "code", "message", "suggestion"}`, with the closest code as `suggestion` (or `null`). An empty `code` returns `{"found": true, "codes": [{"code", "meaning"}, …]}`.

One cause is one issue, here and in `validate_rule`: a dangling reference (`detection_model`, `objective.threats`, `threat.chaining[].vector`) is an `invalid_ref`, not also a `vocab_unknown`, with the value in `context.value`. `opentide explain <code>` says what each code means.

## validate_query

Checks a query offline with the analysis engine, the same engine as `opentide validate query` and `opentide lsp`; with `live: true`, the catalogue's rules on the platform's tenants, the same path as `opentide validate query --platform <platform> --live`.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `query` | string | | The query to check offline. The live check reads catalogue rules, not this string |
| `platform` | string | | Platform key: picks the language and its profile (Defender tables for `defender_for_endpoint`, the Carbon Black dialect for `carbon_black_cloud`) |
| `live` | boolean | `false` | `true` calls the tenant |
| `language` | string | `""` | Elastic only: `esql`, `eql`, `kuery` (the default) or `lucene` |
| `stack` | string | `""` | Elastic ES\|QL only: the stack the query must run on, such as `9.5` or `serverless`. Empty: every supported stack |

Offline, the result has `valid` (`false` when the engine found an error), `status`, `language`, `errors`, `warnings`, every finding under `diagnostics` (`code`, `severity`, `message`, `line`, `column`, `end_line`, `end_column` in the query, 1-based, columns in code points; `suggestion`, the language's `reference` and `explain`), and the `engine` versions. Warnings (slow query shapes) leave `valid` true. `next_actions` names the first finding's `explain` page, then the live check.

```json
{
  "supported": true,
  "mode": "offline",
  "platform": "sentinel",
  "language": "kql",
  "valid": false,
  "status": "failed",
  "message": "1 error(s) in the kql query",
  "errors": [
    {
      "code": "kql_unknown_operator",
      "severity": "error",
      "message": "unknown tabular operator 'wher'",
      "line": 1,
      "column": 17,
      "end_line": 1,
      "end_column": 37,
      "suggestion": "where",
      "reference": "https://learn.microsoft.com/kusto/query/",
      "explain": "opentide explain kql_unknown_operator"
    }
  ],
  "warnings": [],
  "diagnostics": [
    {
      "code": "kql_unknown_operator",
      "severity": "error",
      "message": "unknown tabular operator 'wher'",
      "line": 1,
      "column": 17,
      "end_line": 1,
      "end_column": 37,
      "suggestion": "where",
      "reference": "https://learn.microsoft.com/kusto/query/",
      "explain": "opentide explain kql_unknown_operator"
    }
  ],
  "engine": {
    "package": "0.6.0",
    "engine": "0.6.0"
  },
  "next_actions": [
    {
      "tool": "explain",
      "arguments": {
        "code": "kql_unknown_operator"
      },
      "command": "opentide explain kql_unknown_operator",
      "reason": "how to fix it"
    },
    {
      "tool": "validate_query",
      "arguments": {
        "query": "SecurityEvent | wher EventID == 4688",
        "platform": "sentinel",
        "live": true
      },
      "command": "opentide --json validate query --platform sentinel --live",
      "reason": "check the catalogue's sentinel rules: this contacts the sentinel tenant with the configured credentials, so ask a person first"
    }
  ]
}
```

SentinelOne's S1QL has no offline engine: the default refuses and names `live: true`, and an empty `query` is refused too. Neither scans anything (`valid: null`). A missing SDK, a missing plan or a tenant it cannot reach is a failed live check.

**Unsupported platforms** return:

```json
{
  "valid": null,
  "supported": false,
  "mode": "unsupported",
  "message": "query validation not supported for …",
  "errors": []
}
```

Supported: `carbon_black_cloud`, `defender_for_endpoint`, `elastic`, `sentinel`, `sentinel_one`, `splunk` (`QUERY_VALIDATION_PLATFORMS`; the tool description lists the same set); offline, all but `sentinel_one`. The live next action says that it contacts the tenant with the configured credentials: ask a person before following it.

## run_query

Run a read-only query on a platform's tenants and return the rows: the MCP face of the [query command](../cli/query.md). Without `live: true` it refuses and contacts nothing; its next action is the live call. `live: true` uses the configured credentials: ask a person first.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `query` | string | required | Query text in the platform's language (empty with `rule`) |
| `platform` | string | required | Platform key; every platform has a runner |
| `tenant` | string | `""` | A tenant name, several comma-separated, or `all`; empty for the only tenant |
| `live` | boolean | `false` | Send the query; without it nothing is sent |
| `rule` | string | `""` | Run the query this rule (UUID) deploys, instead of `query` |
| `since` | string | `"24h"` | Look-back: `15m`, `24h`, `7d`, `PT1H` |
| `limit` | integer | `100` | Rows per tenant (`MAX_QUERY_ROWS`), at most 5000 |
| `language` | string | `""` | Elastic only: `esql`, `eql`, `lucene` or `kuery` |
| `index` | string | `""` | Elastic index patterns (comma-separated), or a CrowdStrike repository |

Without `live`:

```json
{
  "supported": true,
  "status": "failed",
  "platform": "sentinel",
  "message": "run_query sends the query to the tenant. Pass live: true.",
  "query_preview": "SecurityEvent | take 10",
  "next_actions": [
    {
      "tool": "run_query",
      "arguments": {"query": "SecurityEvent | take 10", "platform": "sentinel", "live": true},
      "command": "opentide --json query --platform sentinel 'SecurityEvent | take 10'",
      "reason": "run it on sentinel: this contacts the tenant with the configured credentials, so ask a person first"
    }
  ]
}
```

With `live: true` the result is the query command's `--json` payload without its envelope, plus `supported: true`: `status` (`completed` or `failed`), `message`, `window`, `tenants`, `row_count`, and `results`, one per tenant (and per sub-query of a SentinelOne correlation rule) with `tenant`, `status` (`ok` or `failed`), `columns`, `rows`, `row_count`, `truncated`, `partial`, `warnings`, and on a failure `error` and `detail`. A call that cannot run (an unknown tenant, no query) has `status: "failed"` and a `message` naming the problem, and sends nothing. An unknown platform returns `supported: false`.

## deploy_rule

Deploy a rule to a platform. Defaults to a dry run — a real deploy requires an explicit `dry_run=false` and platform credentials.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `uuid` | string | required | Rule UUID |
| `platform` | string | required | Platform key |
| `dry_run` | boolean | `true` | Simulate when true |

```json
// call
{ "uuid": "00000000-0000-4000-8003-000000000001", "platform": "sentinel", "dry_run": true }

// returns
{
  "action": "dry-run",
  "tenant": null,
  "rule_id": "00000000-0000-4000-8003-000000000001",
  "status": "STAGING",
  "dry_run": true,
  "platform": "sentinel",
  "message": ""
}
```

`action` is `"dry-run"` or `"deploy"` (or `"error"` when the rule is missing). `status` is the rule’s current deployment status string from the object, not a planned-action label.

A real deploy the deployer refused or failed returns `"action": "error"`, `"status": "failed"` and `"error": "deployment_failed"`, with no vendor call for a refused rule: for example a rule that still carries `rule_id` (`external_id_in_rule`), or a create whose id could not be written (`deployment_state_write_failed`). The server log names the code. Each call starts from a clean outcome, so one failed call does not mark the next as failed.

```json
{
  "action": "error",
  "tenant": null,
  "rule_id": "00000000-0000-4000-8003-000000000001",
  "status": "failed",
  "dry_run": false,
  "platform": "sentinel",
  "message": "Deployment failed: the deployer reported a rule error (see the log for its code, for example external_id_in_rule)",
  "error": "deployment_failed"
}
```

## deployment_status

Per-platform deployment state for a rule. Vendor rule ids come from the rule's [deployment state](../usage/concepts/deployment-state.md) shard, keyed by tenant.

| Parameter | Type | Description |
|-----------|------|-------------|
| `uuid` | string | Rule UUID |

```json
// call
{ "uuid": "00000000-0000-4000-8003-000000000001" }

// returns
{
  "found": true,
  "uuid": "00000000-0000-4000-8003-000000000001",
  "platforms": {
    "defender_for_endpoint": {
      "deployed": true,
      "rule_id": "12345",
      "external_ids": { "contoso": "12345" },
      "tenants": []
    },
    "sentinel": { "deployed": true, "rule_id": null, "external_ids": {}, "tenants": ["contoso"] }
  }
}
```

`deployed` is true once a vendor id is recorded or the block names `tenants`. `external_ids` maps tenant name to the stored id (Defender for Endpoint, SentinelOne, CrowdStrike only). `rule_id` is that id when exactly one tenant is bound, otherwise `null`. A shard that cannot be read adds `state_error` with its `deployment_state_*` code.

## Agent workflows

Chain the tools into safe, end-to-end recipes.

### Add a detection for a technique

```text
search(query="T1059")                     → find or confirm the objective
get_chaining(uuid=<objective>)            → inspect graph + chaining_index
# write objects/rules/<name>.yaml from opentide://templates/rule, detection_model=<objective>
validation_report(file=<new rule file>)   → apply each issue's fix.edits, explain(code) the rest
validation_report(file=<new rule file>)   → repeat until ok is true
# (tenant check: validate_query with live true, or opentide validate query --platform sentinel --live)
deploy_rule(uuid=<new rule>, platform="sentinel", dry_run=true)   → preview
# a person reviews, merges and deploys
```

### Audit coverage

```text
coverage()                                → technique_count + matrix of technique → rule UUIDs
coverage(technique="T1059")               → covered bool + rules list for one technique
search(technique=<gap>)                   → confirm nothing exists
# propose new objective/rule for the gap
# note: tactic= is echoed only; it does not filter the matrix today
```

### Fix a broken reference

```text
validation_report(object_type="rule")     → surface dangling detection_model (invalid_ref)
get_chaining(uuid=<rule>)                 → inspect related objects in chaining_index
# correct the UUID, then re-run validation_report
```

## Agent guidelines

1. Call `validation_report` before suggesting YAML edits, and again after each edit until `ok` is `true`.
2. Apply `fix.edits` from the issue rather than guessing; `safe: true` edits need no review, the others need a look at `help`. Call `explain` for a code you do not know.
3. Use `search` before `get_chaining` when the UUID is unknown.
4. Default to `dry_run=true` for `deploy_rule`; require explicit human approval for a real deploy. People review and merge changes.
5. Never claim query validation for unsupported platforms. `validate_query` refuses unless `live` is true, and that call checks catalogue rules against the tenant. Ask a person before `run_query` with `live: true`, which queries a tenant with real credentials.
6. Do not assume `coverage(tactic=…)` filters results — pass `technique` for a filtered answer.

## Troubleshooting

- **Empty results everywhere** — the server likely started with the wrong `OPENTIDE_REPO_ROOT`, or schemas were never generated. See [Configuration](./configuration.md) and run `opentide generate` in the repo.
- **`validate_query` refuses** — the default does not scan. Pass `live: true` to check the catalogue rules against the tenant. A missing SDK, a missing plan or an unreachable tenant fails that check.
- **A resource returns `{"error": "… not found"}`** — the UUID is wrong or the object type does not match; confirm with `search`.
- **`deploy_rule` crashes, or `deployment_status` says an undeployed rule is deployed** — through 0.6.3 an unknown platform raised `KeyError`, and any authoring config counted as deployed. 0.6.4 returns a structured failure for an unknown platform or a platform with no tenants. `deployed` is false when the config has no `external_id` and no tenants.
