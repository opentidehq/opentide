---
title: MCP resources
description: opentide:// resource URIs for catalogue indexes, objects, schemas, templates, and vocabularies.
---

# MCP resources

Read-only resources registered on the opentide MCP server. Each is served as `text/plain`: a JSON document, or for a template its YAML as a JSON string.

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
| `opentide://vocabularies` | Vocabulary index: `{name: {metadata, entry_count, uri}}` — entries are **not** inlined |
| `opentide://vocabularies/{+name}` | Named vocabulary: `{metadata, entries}`. `{+name}` keeps the `&` in `att&ck` literal |
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

`opentide://vocabularies` lists which vocabularies exist and how many entries each has; follow its `uri` to read the entries of the one you need. The bundled entries together are several megabytes, so the index deliberately leaves them out.

## Response format

All resources return **indented JSON strings** suitable for agent context windows.

Missing objects return:

```json
{ "error": "Rule <uuid> not found" }
```

## Size and performance

- Collection resources (`opentide://rules`, `opentide://threats`, `opentide://objectives`, `opentide://index`) dump every object and grow with the repo. On large catalogues they can be big — read a single-object URI, or use the `search` tool to narrow, before pulling a full collection into context.
- There is no pagination; resources return the full payload. If a collection is too large for your context window, use `search` (tool) and then fetch specific objects by UUID.
- Resources reflect the workspace the server read. If they look empty or stale, regenerate schemas (`opentide generate schemas`) and restart the server.

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

The registry keys generated schemas by **schema id** (`rule::1.0`, `threat::1.0`,
`objective::1.0`, `visibility::1.0`). The resource accepts any of these forms and
resolves them to the highest matching version:

| Requested | Resolves to |
|-----------|-------------|
| `rule` | `rule::1.1` (highest registered rule schema) |
| `rules` | `rule::1.1` |
| `rule.1.1` | `rule::1.1` |
| `rule::1.0` | `rule::1.0` when that schema file is in the index |

When nothing matches, the resource returns a diagnostic rather than an empty object:

```json
{
  "error": "No JSON Schema generated for \"rule\"",
  "available": [],
  "hint": "run 'opentide generate schemas'"
}
```

Resources reflect the workspace the server read — run `opentide generate schemas` in the client repo if schemas are empty.

`opentide://templates/{object_type}` accepts the same forms. A family (`rule`,
`rules`) is the template of its newest revision, the one `opentide new rule`
starts from (`rule::1.1`); a revision (`rule::1.0`, `rule.1.1`) is that
revision's generated template (`.opentide/templates/rule.1.0.template.yaml`).
A revision with no generated template, such as `rule::9.9`, returns an `error`
with the `available` templates. Run `opentide generate templates` if the
template list is empty.

## Vocabulary resources

Vocabularies are `model_dump()`-ed to JSON objects, not `repr()` strings:

```json
{
  "actors": {
    "metadata": { "name": "Threat Actors", "field": "actors", "…": "…" },
    "entries": { "att&ck::G0006": { "…": "…" } }
  }
}
```

An unknown name returns `{ "error": "Unknown vocabulary \"…\"", "available": [...] }`.

## SDK equivalent

```python
from opentide import Workspace

ws = Workspace.open(".")
ws.info()       # the index: counts, platforms and their capabilities
ws.catalog()    # every object, with its path and references
```

See the [SDK's Workspace](../sdk/workspace.md).

## Source

`crates/opentide-cli/src/mcp/resources.rs`
