---
title: Schema revision
description: How metadata.schema selects validation models and how schema revisions coexist with instance versions.
---

# Schema revision

OpenTide separates **structural schema revisions** from **object instance versions**.

## Two metadata fields

| Field | Example | Meaning |
|-------|---------|---------|
| `metadata.schema` | `rule::1.0` | Which Pydantic model / JSON Schema applies |
| `metadata.version` | `1.2.0` | Business semver for the object instance |

- **Schema revision** selects the validation model and generated `rule.1.0.schema.json` artifact.
- **Instance version** tracks content evolution; git is the authoritative history.

Do not use `metadata.version` to pick a JSON Schema file.

## Filename conventions

| Layer | Format | Example |
|-------|--------|---------|
| Schema identifier | `{family}::{major}.{minor}` | `rule::1.0` |
| Schema file | `.opentide/schemas/{family}.{major}.{minor}.schema.json` | `rule.1.0.schema.json` |
| Template file | `.opentide/templates/{family}.{major}.{minor}.template.yaml` | `rule.1.0.template.yaml` |
| IDE router | `.opentide/schemas/opentide.schema.json` | routes `objects/**/*.yaml` by `metadata.schema` |

## Runtime routing

1. **Registry** — `schema_registry.py` maps `rule::1.0` → `DetectionRule`.
2. **Load** — `load_object()` reads `metadata.schema`, resolves the model, optionally migrates via `SchemaVersionChain`, then validates with Pydantic.
3. **Validate** — `opentide validate` checks every object against its declared schema identifier.
4. **Index** — `RegistryBuilder` scans `.opentide/schemas/*.schema.json` into the runtime index.

## Multi-version coexistence

When `rule::1.1` ships:

1. Add a new Pydantic model with `__schema_identifier__ = "rule::1.1"`.
2. Register the model and a `SchemaVersionChain` migration from `1.0` → `1.1`.
3. Run `opentide generate schemas`.
4. Objects opt in by setting `metadata.schema: rule::1.1`; older objects keep `rule::1.0` until migrated.

Concurrent schema files in `.opentide/schemas/` are expected.

## Generation

`opentide generate schemas` emits:

- One JSON Schema per registered core-object identifier.
- `visibility::1.0` for configuration validation.
- `opentide.schema.json` IDE router with `const` discrimination on `metadata.schema`.

## Source references

- `src/opentide/models/schema_registry.py`
- `src/opentide/registry/artifacts.py`
- `src/opentide/models/version.py`
- `src/opentide/data/configurations/paths.toml`

## SDK

Programmatic schema access via `OpenTide.JsonSchemas`, `OpenTide.Templates`, and `OpenTide.TideSchemas` — see [SDK registry](../../sdk/registry.md).

## Normative reference

[Versioning spec](/docs/specifications/specs/versioning/) · [Metadata spec](/docs/specifications/specs/metadata/)
