# Schema revision contract

OpenTide separates **structural schema revisions** from **object instance versions**. This document describes how routing, artifacts, and migrations work.

## Two metadata fields

| Field | Example | Meaning |
|-------|---------|---------|
| `metadata.schema` | `rule::1.0` | Which Pydantic model / JSON Schema applies |
| `metadata.version` | `1.2.0` | Business semver for the object instance |

- **Schema revision** (`metadata.schema`) selects the validation model and generated `rule.1.0.schema.json` artifact.
- **Instance version** (`metadata.version`) tracks content evolution; git is the authoritative history (no `revisions.json` indexer).

Do not use `metadata.version` to pick a JSON Schema file.

## Identifier and filename conventions

| Layer | Format | Example |
|-------|--------|---------|
| Schema identifier | `{family}::{major}.{minor}` | `rule::1.0` |
| Schema file | `.opentide/schemas/{family}.{major}.{minor}.schema.json` | `rule.1.0.schema.json` |
| Template file | `.opentide/templates/{family}.{major}.{minor}.template.yaml` | `rule.1.0.template.yaml` |
| IDE router | `.opentide/schemas/opentide.schema.json` | routes `objects/**/*.yaml` by `metadata.schema` |

Helpers live in [`src/opentide/registry/artifacts.py`](../../src/opentide/registry/artifacts.py) and [`src/opentide/models/version.py`](../../src/opentide/models/version.py).

Paths are configured in bundled [`paths.toml`](../../src/opentide/data/configurations/paths.toml) under `[paths.opentide]`.

## Client workspace layout

What `opentide setup` scaffolds and what a healthy detection repo looks like after `opentide generate`:

```
detection-repo/
├── objects/
│   ├── threats/
│   ├── objectives/
│   └── rules/
├── docs/
│   ├── rules/
│   ├── threats/
│   └── objectives/
├── .opentide/
│   ├── configurations/
│   │   └── platforms/
│   ├── schemas/              # opentide generate schemas
│   ├── templates/              # opentide generate templates
│   ├── exports/                # opentide generate exports
│   └── inflight/               # empty until CI publishes PR previews (follow-up)
├── .vscode/
├── .github/workflows/
├── README.md
└── .gitignore
```

Client configuration overrides live only under `.opentide/configurations/`. Package defaults ship in the PyPI wheel (`get_data_root()`).

## Runtime routing

1. **Registry** — [`schema_registry.py`](../../src/opentide/models/schema_registry.py) maps `rule::1.0` → `DetectionRule` (single source of truth).
2. **Load** — [`load_object()`](../../src/opentide/loading/object_loader.py) reads `metadata.schema`, resolves the model, optionally migrates via `SchemaVersionChain`, then validates with Pydantic.
3. **Validate** — `opentide validate` uses `load_object_for_validation()` so every object is checked against its declared schema identifier. Vocabulary and deprecation walks resolve metaschema by `metadata.schema`.
4. **Index** — [`RegistryBuilder`](../../src/opentide/registry/builder.py) scans `.opentide/schemas/*.schema.json` into `framework_schemas` (by identifier) and `json_schemas` (by identifier). Runtime `metaschemas` are built per registered identifier, not latest-only.

## Multi-version coexistence

When `rule::1.1` ships:

1. Add `DetectionRuleV11` (or bump model) with `__schema_identifier__ = "rule::1.1"`.
2. `register_model(DetectionRuleV11)` in the schema registry bootstrap (or decorator).
3. Register `SchemaVersionChain` migration `rule::1.0` → `rule::1.1`.
4. Run `opentide generate schemas` — emits `rule.1.1.schema.json` and updates `opentide.schema.json`.
5. Objects opt in by setting `metadata.schema: rule::1.1`; older objects keep `rule::1.0` until migrated.

Concurrent files in `.opentide/schemas/` are expected. The router adds one `if`/`then` branch per registered identifier.

## Generation

`opentide generate schemas` emits:

- One JSON Schema per **registered core-object identifier** (not per folder type).
- `visibility::1.0` for configuration validation.
- `opentide.schema.json` from [`registered_identifiers()`](../../src/opentide/models/schema_registry.py).

Each per-version schema pins `metadata.schema` as a JSON Schema `const` for IDE discrimination.

## Non-goals

- **Git history export** — `revisions.export.json` is a snapshot export, not a schema revision system.
- **Bulk migrate CLI** — deferred (`opentide migrate objects`).
- **TypeAdapter unions** — deferred until multiple versions must coexist in one typed API surface.
- **Committed `staging.json`** — replaced by git-diff scoped CI and (future) `.opentide/inflight/` shards.

## Adding a new revision (checklist)

1. Implement Pydantic model with new `__schema_identifier__`.
2. Register model + migration chain step.
3. Run `opentide generate schemas` and `opentide generate templates`.
4. Update client objects' `metadata.schema` (or run a one-off migration script).
5. Add tests in `tests/test_models/test_schema_revision.py` pattern.
