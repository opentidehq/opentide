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

On failure, returns an error dict: `{ "error": "…" }`.

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

When the UUID is missing: `{ "uuid": "…", "found": false, "graph": {} }`. The registry chaining index is `{threat_uuid: {relation: [vector_uuid, …]}}` — not a top-level `nodes`/`edges` graph. Non-threat UUIDs return `found: true` with an empty `graph` when they are not keys in that index.

## coverage

ATT&CK coverage analysis with gap identification. Use it to answer "what do we detect for T1059?" or "where are our gaps?".

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `technique` | string | `""` | When set, return coverage for that technique only |
| `tactic` | string | `""` | Echoed as `tactic_filter` when no technique is set; **does not filter** the matrix today |

```json
// call
{ "technique": "T1059" }

// returns
{
  "technique": "T1059",
  "covered": true,
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

Validate query syntax for supported platforms.

> **Current status:** Stub implementation — returns `valid: true` without parsing. Use CLI `opentide validate query --platform …` for real validation.

| Parameter | Type | Description |
|-----------|------|-------------|
| `query` | string | Query text |
| `platform` | string | Platform key |

**Unsupported platforms** return:

```json
{
  "valid": null,
  "supported": false,
  "message": "query validation not supported for …",
  "errors": []
}
```

Supported: `sentinel`, `defender_for_endpoint`, `splunk`, `sentinel_one`, `carbon_black_cloud`.

## run_query

Execute a read-only platform query.

> **Current status:** Stub implementation — returns empty results with a dry-run message. Does not call live platform APIs yet.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `query` | string | required | Query text |
| `platform` | string | required | Platform key |
| `tenant` | string | `""` | Optional tenant scope |

Results capped at **100 rows** (`MAX_QUERY_ROWS`).

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
4. Never claim query validation for unsupported platforms, and remember `validate_query`/`run_query` are stubs — use the CLI for real syntax checks.
5. Do not assume `coverage(tactic=…)` filters results — pass `technique` for a filtered answer.

## Troubleshooting

- **Empty results everywhere** — the server likely started with the wrong `OPENTIDE_REPO_ROOT`, or schemas were never generated. See [Configuration](./configuration.md) and run `opentide generate` in the repo.
- **`validate_query` always passes** — it is a stub; use `opentide validate query` (CLI).
- **A resource returns `{"error": "… not found"}`** — the UUID is wrong or the object type does not match; confirm with `search`.
