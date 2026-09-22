---
title: MCP tools
description: Tool reference for the OpenTide MCP server — parameters, behaviour, and response shapes.
---

# MCP tools

Registered in `src/opentide/mcp_server/server.py`. Implementations in `src/opentide/mcp_server/tools.py`.

Each tool below lists its parameters, an example call, and an example response so an agent knows exactly what to expect.

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

Return chaining data for a UUID from `OpenTide.Models.chaining`. Use it to understand how an object connects before editing.

| Parameter | Type | Description |
|-----------|------|-------------|
| `uuid` | string | Any object UUID in the chain |

```json
// call
{ "uuid": "00000000-0000-4000-8001-000000000001" }

// returns (threat UUID — chaining index is threat→threat via relation)
{
  "uuid": "00000000-0000-4000-8001-000000000001",
  "found": true,
  "type": "threat",
  "graph": {
    "preceeds": ["00000000-0000-4000-8001-000000000002"]
  },
  "chaining_index": {
    "00000000-0000-4000-8001-000000000001": {
      "preceeds": ["00000000-0000-4000-8001-000000000002"]
    }
  }
}
```

The UUID is matched case-insensitively and trimmed; `uuid` in the response is the object's UUID as written in the repository. When the UUID is missing: `{ "uuid": "…", "found": false, "graph": {} }`. The registry chaining index is `{threat_uuid: {relation: [vector_uuid, …]}}` — not a top-level `nodes`/`edges` graph. Non-threat UUIDs return `found: true` with an empty `graph` when they are not keys in that index.

## coverage

ATT&CK coverage analysis with gap identification. Use it to answer "what do we detect for T1059?" or "where are our gaps?".

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `technique` | string | `""` | When set, return coverage for that technique only |
| `tactic` | string | `""` | Echoed as `tactic_filter` when no technique is set; **does not filter** the matrix today |

Coverage reads the same technique locations as `opentide info coverage --technique`:
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
  "issues": []
}
```

## validation_report

Structured validation report for agents. Full registry by default; narrow with filters.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `file` | string | `""` | Single file path |
| `uuid` | string | `""` | Single UUID |
| `object_type` | string | `""` | `rule`, `threat`, or `objective` |

Prefer this tool for agent workflows — returns `model_dump_json_ready()` issue list.

## validate_query

Offline syntax check, the same engine as `opentide validate query`.

| Parameter | Type | Description |
|-----------|------|-------------|
| `query` | string | Query text |
| `platform` | string | Platform key |

Structural only — delimiter balance, string and comment termination, pipeline
shape, dangling operators. `valid: true` means the query parses; it does not
mean the fields exist or that the query returns rows. Nothing is sent to a
tenant.

```json
{
  "valid": false,
  "supported": true,
  "mode": "offline-syntax",
  "language": "kql",
  "errors": [
    {
      "code": "unterminated_string",
      "message": "Unterminated \" string literal",
      "line": 1,
      "column": 31
    }
  ],
  "message": "KQL syntax check failed with 1 problem(s)",
  "query_preview": "SecurityEvent | where Account == \"oops"
}
```

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

Supported: `sentinel`, `defender_for_endpoint`, `splunk`, `sentinel_one`, `carbon_black_cloud`.

## run_query

> **Not implemented.** The tool never contacts a tenant and never returns rows.
> It exists so an agent that reaches for query execution gets an explicit
> refusal instead of a plausible empty result set.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `query` | string | required | Query text |
| `platform` | string | required | Platform key |
| `tenant` | string | `""` | Optional tenant scope |

```json
{
  "supported": true,
  "stub": true,
  "rows": null,
  "platform": "sentinel",
  "tenant": null,
  "message": "Read-only query execution is not implemented; no query was sent to sentinel. The live path would cap results at 100 rows."
}
```

`rows: null` and `stub: true` are the contract: there is no `results` key to
mistake for data. The live path, when it lands, will cap at **100 rows**
(`MAX_QUERY_ROWS`).

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

## deployment_status

Per-platform deployment state for a rule.

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
    "sentinel": { "deployed": true, "rule_id": "abc-123", "tenants": ["contoso"] }
  }
}
```

## Agent workflows

Chain the tools into safe, end-to-end recipes.

### Add a detection for a technique

```text
search(query="T1059")                     → find or confirm the objective
get_chaining(uuid=<objective>)            → inspect graph + chaining_index
# propose objects/rules/<name>.yaml with detection_model=<objective>
validation_report(uuid=<new rule>)        → must pass before proposing as done
# (real KQL check runs via CLI: opentide validate query --platform sentinel)
deploy_rule(uuid=<new rule>, platform="sentinel", dry_run=true)   → preview
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

1. Call `validation_report` before suggesting YAML edits.
2. Use `search` before `get_chaining` when the UUID is unknown.
3. Default to `dry_run=true` for `deploy_rule`; require explicit human approval for a real deploy.
4. Never claim query validation for unsupported platforms. `validate_query` is a real offline syntax check but proves nothing about results; `run_query` is not implemented at all.
5. Do not assume `coverage(tactic=…)` filters results — pass `technique` for a filtered answer.

## Troubleshooting

- **Empty results everywhere** — the server likely started with the wrong `OPENTIDE_REPO_ROOT`, or schemas were never generated. See [Configuration](./configuration.md) and run `opentide generate` in the repo.
- **`validate_query` passes on a query the platform rejects** — the check is structural. Field names, operators, and table names are not resolved; run the query in the tenant to prove it works.
- **A resource returns `{"error": "… not found"}`** — the UUID is wrong or the object type does not match; confirm with `search`.
