---
title: Models
description: Pydantic models for rules, objectives, threats, metadata, and validation results.
---

# Models

Core object types are Pydantic v2 models with explicit schema identifiers.

## Core objects

| Model | Schema ID | Module |
|-------|-----------|--------|
| `DetectionRule` | `rule::1.0` | `opentide.models.rule` |
| `DetectionObjective` | `objective::1.0` | `opentide.models.objective` |
| `ThreatVector` | `threat::1.0` | `opentide.models.threat` |

## Schema registration

Models register via `opentide.models.schema_registry`:

```python
from opentide.models.rule import DetectionRule

DetectionRule.__schema_identifier__  # "rule::1.0"
```

Schema revisions coexist — see [Schema revision](../usage/concepts/schema-revision.md).

## DetectionRule delegation

Rules loaded through the registry support instance methods:

```python
rule.validate() -> ValidationResult
rule.validate_query(platform) -> ValidationResult
rule.deploy(platform, dry_run=False) -> DeploymentResult
rule.document() -> str
# or: OpenTide.render_rule(rule)
```

`OpenTide.promote_rule()` raises `NotImplementedError` — use deployment-time promotion via `opentide deploy` and `.opentide/configurations/` promotion settings.

These delegate to the bound registry when `_registry` is set (normal load path).

## Metadata and references

```python
from opentide.models.metadata import ObjectMetadata, ObjectReferences
```

Every object carries:

```yaml
metadata:
  schema: rule::1.0
  version: 1.0.0
  uuid: "..."
  name: "..."
```

## Results

```python
from opentide.models.results import ValidationResult, DeploymentResult
```

## Base type

```python
from opentide.models.base import TideModel
```

Shared validation, alias handling, and schema identifier conventions.

## Loading without registry

```python
from opentide.loading.rule_loader import load_rule_from_dict
from opentide.loading.object_loader import load_object_for_validation
```

Prefer registry access for interactive work; loaders are used internally by validation and indexing.

## Source

`src/opentide/models/`
