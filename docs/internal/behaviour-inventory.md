---
title: Behaviour inventory
description: Behaviour inventory — FieldInfo YAML templates (0.2.0) plus CoreTide schema/validation baseline.
---

# Behaviour Inventory

Template generation (section 2) is the **0.2.0 FieldInfo** renderer. Other sections remain the Phase 3/4 CoreTide baseline used to gate schema and validation ports.

**Sources analysed**

| Concern | Primary modules | Lines (approx.) |
|---------|-----------------|-----------------|
| Template generation | `src/opentide/generation/pydantic_skeleton.py` | FieldInfo walker |
| JSON Schema generation | `Engines/framework/json_schemas.py` | 870 |
| VS Code snippets | `src/opentide/generation/vscode_snippets.py` | copies YAML templates |
| Schema validation | `Engines/validation/tide_schema.py` | 101 |
| Indexing | `Engines/indexing/indexer.py`, `objects_indexer.py` | 416 + 137 |

---

## 1. JSON Schema generation (`json_schemas.py`)

### 1.1 `EnumResolver` vocabulary resolution

| ID | Behaviour | Location |
|----|-----------|----------|
| JS-01 | Ingest core vocabulary from `VOCAB_INDEX`; honour `vocab.search_hints` metadata | `EnumResolver.Vocabulary._ingest` |
| JS-02 | Merge `schema.toml` vocabulary extensions; normalise extension keys via `entry_key_field` | `_ingest_extensions` |
| JS-03 | Model vocab: emit rule UUID keys; scoped stages prefix `stage::key` (list-normalised stages) | `_process` (model branch) |
| JS-04 | Non-model vocab: optional stage filter; scoped multi-stage emits one enum per stage | `_process` (non-model branch) |
| JS-05 | De-duplicate enum values; skip duplicates with INFO log | `_emit` |
| JS-06 | Empty enum becomes `[""]` before return | `_finalise` |
| JS-07 | Append search hints to enum + descriptions when hints enabled | `_finalise` |
| JS-08 | Hint abbreviations when `no_wrap` false and hint length > 60 | `_search_hint` |
| JS-09 | Dropdown markdown: icon, title-cased display name, criticality block for object types | `_dropdown` |
| JS-10 | Stage documentation from vocabulary `stages` metadata | `_stage_doc` |
| JS-11 | **Phase 3 fix:** hint descriptions stored in `_hint_descriptions`, not `extend(self)` | `_finalise` |
| JS-12 | **Phase 3 fix:** `isinstance(field_types, str)` for type normalisation | `gen_json_schema` |

### 1.2 Metaschema → JSON Schema walk (`gen_json_schema`)

| ID | Behaviour | Notes |
|----|-----------|-------|
| JS-13 | Depth-first walk; copy keys before mutation | `dict_foo = dictionary.copy()` |
| JS-14 | Resolve `tide.vocab` → enum + `markdownEnum` via `EnumResolver` | inline in walk |
| JS-15 | Resolve `tide.meta.definition` references from definitions index | inline |
| JS-16 | Resolve `recomposition` blocks via `recomposition_handler` | object properties |
| JS-17 | Strip `tide.*` keys recursively via `strip_framework_keywords` | post-process |
| JS-18 | Config-driven required fields via `fetch_config_template` | template keywords |
| JS-19 | Icon injection on titled fields | `get_icon` |
| JS-20 | `run()` writes schemas under configured paths; logs per object type | `run` |

### 1.3 Recomposition (`recomposition_handler`)

| ID | Behaviour |
|----|-----------|
| JS-21 | Load enabled platform/system entries from `CONFIG_INDEX` |
| JS-22 | Support both `tide.enabled` and `platform.enabled` config shapes |
| JS-23 | Merge subschema YAML from `Sub Schemas/` folder |

---

## 2. Template generation (`pydantic_skeleton.py`)

YAML skeletons are rendered from Pydantic `FieldInfo` (`render_model_template`). The JSON Schema walker `gen_template` is gone. JSON Schema generation (`schema_pipeline.py`) is a separate pipeline.

| ID | Behaviour | Function |
|----|-----------|----------|
| TP-01 | Omit `Path` fields and fields with `tide.template.hide` | `_render_field` |
| TP-02 | Nested `TideModel` fields recurse via `model_fields` (no `$ref` / `$defs`) | `_render_model` |
| TP-03 | Optional `FieldInfo`: insert `#` once at the field indent on every subtree line; nested optionals stay live under that prefix (no stacked `#`) | `_comment_at_indent` |
| TP-04 | `tide.template.required` overrides `FieldInfo.is_required()` (rule `response` / `configurations`) | `_field_is_required` |
| TP-05 | `RuleConfigurations` optional platform slots are commented stubs with nested `query: \|` — never `configurations: {}` | `RuleConfigurations` walk |
| TP-06 | `dict` fields emit one sample key (`1` for int keys, `key` otherwise) | `_render_dict` |
| TP-07 | `list` fields emit one sample element | `_render_list` |
| TP-08 | Typed placeholders: empty `str`, `YYYY-MM-DD`, `\|` + `...`, `https://`, `3`, `false` — never YAML `null` | `_scalar_placeholder` |
| TP-09 | `VocabField` / `tide.vocab` → empty scalar (no enum dump) | `_scalar_placeholder` |
| TP-10 | Non-null default is the placeholder (`STAGING`); still commented if optional | `_concrete_default` |
| TP-11 | Boolean placeholder is `false` unless a default is set | `_scalar_placeholder` |
| TP-12 | `tide.template.spacer` inserts a blank line before the field | `_wants_spacer` |
| TP-13 | `serialization_alias` / `alias` is the YAML key (`att&ck`, `schema`) | `_yaml_key` |
| TP-14 | Platform templates are emitted at indent 2 from `write_model_template` | `write_model_template` |
| TP-15 | `run()` writes FieldInfo YAML for core objects and enabled platforms | `template_renderer.run` |
| TP-16 | `remove_blanks` leftover file helper (not on the generate path) | `remove_blanks` |
| TP-17 | `replace_strings_in_file` leftover helper (not on the generate path) | `replace_strings_in_file` |
| TP-18 | Uncommented keys = `FieldInfo.is_required()` or `tide.template.required`; schema id from the owning model's `schema_identifier()` | `_field_is_required` |

---

## 3. VS Code snippets (`vscode_snippets.py`)

| ID | Behaviour |
|----|-----------|
| VS-01 | Read template line-by-line preserving indentation into JSON string array |
| VS-02 | Leading blank lines via `blanks` parameter |
| VS-03 | Strip trailing `\n` per line for snippet body |
| VS-04 | Prefix triggers are short names (`tide-rule`, `tide-threat`, `tide-sentinel`, …), with `scope: yaml`, `description`, and tabstops on empty values |
| VS-05 | `run()` writes `.code-snippets` under configured snippet path |

---

## 4. Validation (`tide_schema.py`)

| ID | Behaviour |
|----|-----------|
| VA-01 | Per-object-type iteration over `JSONSCHEMAS_INDEX` |
| VA-02 | `Draft7Validator` against compiled schema |
| VA-03 | Coerce metadata `created` / `modified` to strings before validation |
| VA-04 | Strip `references.public` for validator (int keys), validate separately |
| VA-05 | Tabulated error output via `tabulate` |
| VA-06 | Aggregate stats per schema type |

---

## 5. Indexing (`indexer.py`, `objects_indexer.py`)

| ID | Behaviour |
|----|-----------|
| IX-01 | Resolve configurations (core + optional parent `Configurations/`) | `resolve_configurations` |
| IX-02 | Index vocabularies, schemas, metaschemas, definitions, templates, subschemas | `indexer` |
| IX-03 | Load DOM/MDR objects; apply `Tide2Patching` where configured | `indexer` |
| IX-04 | Build `objects`, `files`, `paths`, `configurations` index sections | `indexer` |
| IX-05 | Inline object enum generation for model vocabularies | `objects_indexer.py` |
| IX-06 | Staging reconciliation merges higher-version MDRs | `IndexManager.reconcile_staging` |

---

## 6. Phase 4 scope mapping

| Sub-phase | Inventory sections | Replacement target |
|-----------|-------------------|-------------------|
| 4.7 JSON Schema | §1 | `TideSchemaGenerator` + `EnumRegistry` in `opentide.models` |
| 4.8 Templates | §2 | `TemplateRenderer` from Pydantic fields |
| 4.9 Validation | §4 | `model_validate()` pipeline |
| 4.10 Indexing | §5 | Typed `model_validate` during index build |

**Phase 4 PR #1 (this branch)** lands foundation models in `src/opentide/models/` without removing legacy generators. Behaviour IDs above become Phase 9 (#71) preservation tests.

---

## 7. Verification commands

```bash
# Regenerate artefacts (LocalDebug)
TERM_PROGRAM=vscode python Orchestration/generate.py
git diff --stat Schemas/ Framework/

# Inventory present
test -f docs/migration/behaviour-inventory.md

# New model package imports
python -c "from opentide.models import DetectionRule, ThreatVector, DetectionObjective"
```

---

*Last updated: Phase 4 worker — derived from opentide `development` + Phase 3 merge.*
