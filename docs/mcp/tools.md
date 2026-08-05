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
    "name": "Credential Access Objective"
  }
]
```

On failure, returns an error dict: `{ "error": "…" }`.

## get_chaining

Return the threat → objective → rule chaining graph for any UUID in the chain. Use it to understand how an object connects before editing.

| Parameter | Type | Description |
|-----------|------|-------------|
| `uuid` | string | Any object UUID in the chain |

```json
// call
{ "uuid": "00000000-0000-4000-8002-000000000001" }

// returns: graph dict with nodes and edges
{
  "nodes": [
    { "uuid": "…8001…", "type": "threat",    "name": "Simulated Actor" },
    { "uuid": "…8002…", "type": "objective", "name": "Credential Access Objective" },
    { "uuid": "…8003…", "type": "rule",      "name": "Sentinel KQL Rule" }
  ],
  "edges": [
    { "from": "…8003…", "to": "…8002…", "via": "detection_model" },
    { "from": "…8002…", "to": "…8001…", "via": "objective.threats" }
  ]
}
```

## coverage

ATT&CK coverage analysis with gap identification. Use it to answer "what do we detect for T1059?" or "where are our gaps?".

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `technique` | string | `""` | Filter to one technique |
| `tactic` | string | `""` | Filter to one tactic |

```json
// call
{ "technique": "T1059" }

// returns
{
  "technique": "T1059",
  "objectives": 1,
  "rules": 1,
  "covered": true
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
  "action": "create_or_update",
  "status": "planned",
  "platform": "sentinel",
  "message": "would create/update 'Sentinel KQL Rule'",
  "dry_run": true
}
```

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
get_chaining(uuid=<objective>)            → check it has no rule yet
# propose objects/rules/<name>.yaml with detection_model=<objective>
validation_report(uuid=<new rule>)        → must pass before proposing as done
# (real KQL check runs via CLI: opentide validate query --platform sentinel)
deploy_rule(uuid=<new rule>, platform="sentinel", dry_run=true)   → preview
```

### Audit coverage

```text
coverage(tactic="credential-access")      → list covered vs gap techniques
search(technique=<gap>)                   → confirm nothing exists
# propose new objective/rule for the gap
```

### Fix a broken reference

```text
validation_report(object_type="rule")     → surface dangling detection_model
get_chaining(uuid=<rule>)                 → find the intended objective
# correct the UUID, then re-run validation_report
```

## Agent guidelines

1. Call `validation_report` before suggesting YAML edits.
2. Use `search` before `get_chaining` when the UUID is unknown.
3. Default to `dry_run=true` for `deploy_rule`; require explicit human approval for a real deploy.
4. Never claim query validation for unsupported platforms, and remember `validate_query`/`run_query` are stubs — use the CLI for real syntax checks.

## Troubleshooting

- **Empty results everywhere** — the server likely started with the wrong `OPENTIDE_REPO_ROOT`, or schemas were never generated. See [Configuration](./configuration.md) and run `opentide generate` in the repo.
- **`validate_query` always passes** — it is a stub; use `opentide validate query` (CLI).
- **A resource returns `{"error": "… not found"}`** — the UUID is wrong or the object type does not match; confirm with `search`.
