---
title: MCP resources
description: opentide:// resource URIs for catalogue indexes, objects, schemas, templates, and vocabularies.
---

# MCP resources

Read-only JSON resources registered on the OpenTide MCP server.

## URI catalogue

| URI | Description |
|-----|-------------|
| `opentide://index` | Full index snapshot |
| `opentide://rules` | All rules (model dump) |
| `opentide://rules/{uuid}` | Single rule body |
| `opentide://threats` | All threats |
| `opentide://threats/{uuid}` | Single threat body |
| `opentide://objectives` | All objectives |
| `opentide://objectives/{uuid}` | Single objective body |
| `opentide://schemas/{object_type}` | JSON Schema for `rule`, `threat`, or `objective` |
| `opentide://templates/{object_type}` | Template metadata for object type |
| `opentide://vocabularies` | Vocabulary index |
| `opentide://vocabularies/{name}` | Named vocabulary entries |
| `opentide://platforms` | Platform capability list |

## When to read which

| Goal | Resource |
|------|----------|
| Orient in an unfamiliar repo | `opentide://index` |
| Read one object in full | `opentide://{rules,threats,objectives}/{uuid}` |
| Check a field's allowed values | `opentide://vocabularies/{name}` |
| See a template before authoring | `opentide://templates/{object_type}` |
| Decide if a platform can validate queries | `opentide://platforms` |

Prefer a **single-object** URI (`.../rules/{uuid}`) over the collection URI when you only need one — the collection resources return every object and can be large.

## Response format

All resources return **indented JSON strings** suitable for agent context windows.

Missing objects return:

```json
{ "error": "Rule <uuid> not found" }
```

## Size and performance

- Collection resources (`opentide://rules`, `opentide://threats`, `opentide://objectives`, `opentide://index`) dump every object and grow with the repo. On large catalogues they can be big — read a single-object URI, or use the `search` tool to narrow, before pulling a full collection into context.
- There is no pagination; resources return the full payload. If a collection is too large for your context window, use `search` (tool) and then fetch specific objects by UUID.
- Resources reflect the runtime index built at `OpenTide.initialise()`. If they look empty or stale, regenerate schemas (`opentide generate schemas`) and restart the server.

## platforms resource shape

```json
[
  {
    "name": "sentinel",
    "enabled": true,
    "can_deploy": true,
    "can_validate": true
  }
]
```

Use this resource to decide whether `validate_query` is applicable before calling the tool.

## Schema and template resources

`object_type` accepts `rule`, `threat`, `objective` (aliases normalised internally).

Resources reflect the runtime index after `OpenTide.initialise()` — run `opentide generate schemas` in the client repo if schemas are empty.

## SDK equivalent

```python
from opentide import OpenTide

OpenTide.initialise()
OpenTide.Index
OpenTide.JsonSchemas.Index
OpenTide.Vocabularies.Index
OpenTide.Platforms.items()
```

See [SDK registry](../sdk/registry.md).

## Source

`src/opentide/mcp_server/resources.py`
