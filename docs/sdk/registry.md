---
title: Registry API
description: OpenTide registry lifecycle, typed object access, configuration accessors, and lookup.
---

# Registry API

`OpenTide` is a module-level singleton of `OpenTideRegistry` with explicit initialisation.

```python
from opentide import OpenTide

OpenTide.initialise()   # load index
OpenTide.reload()       # refresh index and clear object caches
```

## Lifecycle

| Method / property | Description |
|-------------------|-------------|
| `initialise()` | Load index; objects load lazily on first access |
| `reload()` | Refresh index and clear cached rules/threats/objectives |
| `is_initialised` | Whether index has been loaded |

## Typed collections

Access loads and parses all objects of that type:

```python
rules = OpenTide.Rules          # dict[str, DetectionRule]
threats = OpenTide.Threats      # dict[str, ThreatVector]
objectives = OpenTide.Objectives  # dict[str, DetectionObjective]
```

Rules are `bind_registry()`'d and support delegation methods (`deploy`, `validate`, `validate_query`, `document`).

## Lookup

```python
obj = OpenTide.lookup(uuid)  # DetectionRule | DetectionObjective | ThreatVector | None
```

## Index and configuration

```python
index = OpenTide.Index

OpenTide.Configuration.Global
OpenTide.Configuration.Documentation
OpenTide.Configuration.Deployment
OpenTide.Configuration.Visibility
OpenTide.Configuration.Systems

OpenTide.Vocabularies.Index
OpenTide.JsonSchemas.Index      # alias: OpenTide.Schemas
OpenTide.TideSchemas.Index      # alias: OpenTide.MetaSchemas
OpenTide.Templates.Index
OpenTide.Models.rules           # raw dict view
```

## Rule helpers on registry

```python
OpenTide.validate_rule(rule) -> ValidationResult
OpenTide.render_rule(rule) -> str
OpenTide.document_rule(rule) -> str
```

## Platforms

```python
OpenTide.Platforms.items()
OpenTide.Platforms["sentinel"].can_deploy
OpenTide.Platforms["sentinel"].can_validate
```

See [Platforms](./platforms.md).

## Lazy loading and performance

`initialise()` loads the **index** only; individual objects parse lazily on first access, and parsed objects are cached until `reload()`.

- Accessing a typed collection (`OpenTide.Rules`, `.Threats`, `.Objectives`) parses **every** object of that type. On large repos this is the expensive step — do it once and reuse the dict.
- `OpenTide.lookup(uuid)` and `OpenTide.Rules[uuid]` parse and cache a single object; prefer them when you need one object, not the whole collection.
- `OpenTide.Models.rules` is a raw dict view (unparsed) — cheaper when you only need indexed metadata, not full validated models.
- Call `reload()` after mutating YAML on disk to refresh the index and clear caches; otherwise you will read stale objects.

```python
OpenTide.initialise()
rules = OpenTide.Rules          # parse-all: do once
subset = {u: r for u, r in rules.items() if r.status == "PRODUCTION"}
```

## Runtime flags

```python
OpenTide.debug   # DEBUG env
OpenTide.ci      # CI detection
OpenTide.root    # repository root Path
```

## MCP parity

MCP resources expose the same index and model dumps as JSON — see [MCP resources](../mcp/resources.md).

## Source

`src/opentide/core/registry.py`, `src/opentide/__init__.py`
