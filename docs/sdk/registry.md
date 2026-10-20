---
title: Registry API
description: opentide registry lifecycle, typed object access, configuration accessors, and lookup.
---

# Registry API

`Opentide` is a module-level singleton of `OpentideRegistry` with explicit initialisation.

```python
from opentide import Opentide

Opentide.initialise()   # load index
Opentide.reload()       # refresh index and clear object caches
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
rules = Opentide.Rules          # dict[str, DetectionRule]
threats = Opentide.Threats      # dict[str, ThreatVector]
objectives = Opentide.Objectives  # dict[str, DetectionObjective]
```

Rules are `bind_registry()`'d and support delegation methods (`deploy`, `validate`, `validate_query`, `document`).

## Lookup

```python
obj = Opentide.lookup(uuid)  # DetectionRule | DetectionObjective | ThreatVector | None
```

## Index and configuration

```python
index = Opentide.Index

Opentide.Configuration.Global
Opentide.Configuration.Documentation
Opentide.Configuration.Deployment
Opentide.Configuration.Visibility
Opentide.Configuration.Systems

Opentide.Vocabularies.Index
Opentide.JsonSchemas.Index      # alias: Opentide.Schemas
Opentide.TideSchemas.Index      # alias: Opentide.MetaSchemas
Opentide.Templates.Index
Opentide.Models.rules           # raw dict view
```

## Rule helpers on registry

```python
Opentide.validate_rule(rule) -> ValidationResult
Opentide.render_rule(rule) -> str
Opentide.document_rule(rule) -> str
```

## Platforms

```python
Opentide.Platforms.items()
Opentide.Platforms["sentinel"].can_deploy
Opentide.Platforms["sentinel"].can_validate
```

See [Platforms](./platforms.md).

## Lazy loading and performance

`initialise()` loads the **index** only; individual objects parse lazily on first access, and parsed objects are cached until `reload()`.

- Accessing a typed collection (`Opentide.Rules`, `.Threats`, `.Objectives`) parses **every** object of that type. On large repos this is the expensive step — do it once and reuse the dict.
- `Opentide.lookup(uuid)` and `Opentide.Rules[uuid]` parse and cache a single object; prefer them when you need one object, not the whole collection.
- `Opentide.Models.rules` is a raw dict view (unparsed) — cheaper when you only need indexed metadata, not full validated models.
- Call `reload()` after mutating YAML on disk to refresh the index and clear caches; otherwise you will read stale objects.

```python
Opentide.initialise()
rules = Opentide.Rules          # parse-all: do once
subset = {u: r for u, r in rules.items() if r.status == "PRODUCTION"}
```

## Runtime flags

```python
Opentide.debug   # DEBUG env
Opentide.ci      # CI detection
Opentide.root    # detection workspace root Path (not necessarily the git top level)
```

## MCP parity

MCP resources expose the same index and model dumps as JSON — see [MCP resources](../mcp/resources.md).

## Source

`src/opentide/core/registry.py`, `src/opentide/__init__.py`
