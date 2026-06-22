# Behaviour Inventory — Pre-Pydantic Migration Baseline

Derived from the **current code** in `Engines/` on branch `development` after Phase 3 merge (`8fd1fd1`). This document gates Phase 4+ work: regenerated schemas/templates must remain byte-equivalent unless an intentional Phase 3 fix changes them.

**Sources analysed**

| Concern | Primary modules | Lines (approx.) |
|---------|-----------------|-----------------|
| Template generation | `Engines/framework/templates.py`, `Engines/templates/dom.py`, `mdr.py`, `models.py` | 457 + ~240 |
| JSON Schema generation | `Engines/framework/json_schemas.py` | 870 |
| VS Code snippets | `Engines/framework/vscode_snippets.py` | 133 |
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

## 2. Template generation (`templates.py`)

| ID | Behaviour | Function |
|----|-----------|----------|
| TP-01 | Skip fields with `tide.template.hide` | `gen_template` |
| TP-02 | Expand `tide.meta.definition` inline (forced or referenced) | `gen_template` |
| TP-03 | Prefix optional object keys with `#` when not required | `gen_template` |
| TP-04 | Config-gated optional sections via `tide.template.config.required` | `gen_template` |
| TP-05 | Recomposition placeholders as `#{entry}: blank` for enabled systems | `gen_template` |
| TP-06 | `additionalProperties` object templates recurse or emit `blank` | `gen_template` |
| TP-07 | Array templates: optional → `#key` + `"Comment out"` | `gen_template` |
| TP-08 | Sentinel strings: `blank`, `no-space`, `force_space`, `Comment out` | `gen_template` |
| TP-09 | Vocabulary placeholders from enum first value | `gen_template` |
| TP-10 | Example values from metaschema `example` keyword | `gen_template` |
| TP-11 | Boolean defaults to `false` / example | `gen_template` |
| TP-12 | Insert blank lines from `tide.template.spacer` / `force_space` | `make_spaces` |
| TP-13 | Strip `no-space` / `force_space` sentinel markers from output | `make_spaces` |
| TP-14 | Re-indent entire template by N spaces | `indent_template` |
| TP-15 | `run()` pipeline: generate → spaces → indent → remove blanks | `run` |
| TP-16 | `remove_blanks` strips trailing empty YAML lines | `remove_blanks` |
| TP-17 | `replace_strings_in_file` post-processing for template paths | `replace_strings_in_file` |
| TP-18 | `get_required` merges metaschema `required` + `tide.template.force-required` | `get_required` |

---

## 3. VS Code snippets (`vscode_snippets.py`)

| ID | Behaviour |
|----|-----------|
| VS-01 | Read template line-by-line preserving indentation into JSON string array |
| VS-02 | Leading blank lines via `blanks` parameter |
| VS-03 | Strip trailing `\n` per line for snippet body |
| VS-04 | Prefix triggers from platform/object short names |
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
