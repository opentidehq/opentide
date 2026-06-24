---
title: MCP tools
description: Tool reference for the OpenTide MCP server — parameters, behaviour, and response shapes.
---

# MCP tools

Registered in `src/opentide/mcp_server/server.py`. Implementations in `src/opentide/mcp_server/tools.py`.

## search

Search the catalogue by keyword, UUID, or ATT&CK technique.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `query` | string | required | Search term |
| `type` | string | `""` | Object type filter: `rule`, `threat`, `objective` |
| `platform` | string | `""` | Platform filter |
| `status` | string | `""` | Rule status filter |
| `technique` | string | `""` | ATT&CK technique ID |
| `actor` | string | `""` | Threat actor filter |

**Returns:** list of match dicts, or error dict.

## get_chaining

Return threat → objective → rule chaining graph for a UUID.

| Parameter | Type | Description |
|-----------|------|-------------|
| `uuid` | string | Any object UUID in the chain |

**Returns:** graph dict with nodes and edges.

## coverage

ATT&CK coverage analysis with gap identification.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `technique` | string | `""` | Filter to one technique |
| `tactic` | string | `""` | Filter to one tactic |

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

Deploy a rule to a platform.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `uuid` | string | required | Rule UUID |
| `platform` | string | required | Platform key |
| `dry_run` | boolean | `true` | Simulate when true |

**Returns:** action, status, platform, message, dry_run flag.

## deployment_status

Per-platform deployment state for a rule.

| Parameter | Type | Description |
|-----------|------|-------------|
| `uuid` | string | Rule UUID |

**Returns:** `platforms` map with `deployed`, `rule_id`, `tenants`; `found` boolean.

## Agent guidelines

1. Call `validation_report` before suggesting YAML edits.
2. Use `search` before `get_chaining` when UUID is unknown.
3. Default to `dry_run=true` for `deploy_rule`.
4. Never claim query validation for unsupported platforms.
