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

## Response format

All resources return **indented JSON strings** suitable for agent context windows.

Missing objects return:

```json
{ "error": "Rule <uuid> not found" }
```

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
