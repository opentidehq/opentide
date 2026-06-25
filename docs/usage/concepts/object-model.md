---
title: Object model
description: Threat vectors, detection objectives, and MDR rules — paths, relationships, and chaining.
---

# Object model

OpenTide organises detection content into three core object families under `objects/`.

## Core objects

| Object | Directory | Schema identifier | Role |
|--------|-----------|-------------------|------|
| Threat | `objects/threats/` | `threat::1.0` | Threat vector (TVM) definitions |
| Objective | `objects/objectives/` | `objective::1.0` | Detection objectives and signals |
| Rule | `objects/rules/` | `rule::1.0` | MDR rules with platform configurations |

Each YAML file includes top-level `name` plus a `metadata` block:

```yaml
name: "Example rule"
metadata:
  schema: rule::1.0      # structural revision — selects Pydantic model
  version: 1.2.0         # business semver for the instance
  uuid: "<uuid>"
  tlp: clear
```

Normative field definitions: [Metadata spec](/docs/specifications/specs/metadata/), [Rule object spec](/docs/specifications/specs/objects/rule-1.0/).

## Chaining

Objects reference each other forming a graph:

```
Threat ──► Objective ──► Rule
```

Inspect chaining via:

```bash
opentide info
# MCP: get_chaining(uuid)
```

Validation includes cross-object reference and chaining checks when running the full pipeline.

## Typed Python access

```python
from opentide import OpenTide

OpenTide.initialise()
rule = OpenTide.Rules["<uuid>"]
objective = OpenTide.Objectives["<uuid>"]
threat = OpenTide.Threats["<uuid>"]

# Cross-type lookup
obj = OpenTide.lookup("<uuid>")
```

Rules loaded through the registry support delegation methods: `validate()`, `validate_query(platform)`, `deploy()`, and `document()`.

## Generated artifacts

After `opentide generate`:

| Artifact | Location |
|----------|----------|
| JSON Schema | `.opentide/schemas/{family}.{major}.{minor}.schema.json` |
| Template | `.opentide/templates/{family}.{major}.{minor}.template.yaml` |
| IDE router | `.opentide/schemas/opentide.schema.json` |

## Documentation output

`opentide generate docs` renders markdown per object under configured docs folders (rules, objectives, threats) with Mermaid diagrams for relationships and ATT&CK coverage.

## Further reading

- [Schema revision](./schema-revision.md) — `metadata.schema` vs `metadata.version`
- [Platforms](./platforms.md)
- [SDK models](../../sdk/models.md)
- [Threat spec](/docs/specifications/specs/objects/threat-1.0/) · [Objective](/docs/specifications/specs/objects/objective-1.0/) · [Rule](/docs/specifications/specs/objects/rule-1.0/)
