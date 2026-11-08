---
title: "0001: The Tide model is Rust code"
description: How the Tide model is written in Rust (serde, garde, schemars, PyO3, one struct per revision) and the conventions every model in opentide-schema follows.
---

# 0001: The Tide model is Rust code

| | |
|---|---|
| Status | Proposed |
| Date | 2026-11-07 (the plan's decision), recorded 2026-11-08 |
| Decision | D-2, with the schema conventions of UC-1.1 |
| Issues | [#807](https://github.com/opentidehq/opentide/issues/807) (UC-1.1), phase [#792](https://github.com/opentidehq/opentide/issues/792), epic [#790](https://github.com/opentidehq/opentide/issues/790); plan PR [#789](https://github.com/opentidehq/opentide/pull/789) |
| Code | [`crates/opentide-schema`](https://github.com/opentidehq/opentide/tree/development/crates/opentide-schema) |

It records decision D-2 of the [Unified core plan](https://github.com/opentidehq/opentide/blob/docs/unified-core-plan/docs/internal/unified-core.md), which is not merged yet: the ADR stays Proposed until a maintainer approves the plan ([index](./index.md)).

## Context

The Tide model is Pydantic code today (`src/opentide/models`, opentide 0.23.0). It decides what `opentide validate` accepts, and the JSON Schemas, templates, snippets and the language server's field catalog are generated from it (`src/opentide/generation`). The Rust engine reads a copy of that catalog, so the CLI and the editor disagree whenever the copy and the models drift ([plan §2](https://github.com/opentidehq/opentide/blob/docs/unified-core-plan/docs/internal/unified-core.md#2-evidence): of 80 injected faults, 14 are reported differently and 5 by neither).

The plan moves every implementation into one Rust workspace (D-1). The model comes first: every later crate reads it. What it must reproduce, counted on the oracle with the script under [Evidence](#evidence):

| Measure | Count | Where |
|---------|------:|-------|
| Pydantic classes | 176 | `src/opentide/models`: 74 in `platform_configs`, 63 in `configuration/`, 11 in `platform`, 7 in `objective`, 5 in `visibility`, 4 in `metadata`, 3 each in `response` and `threat`, 2 each in `rule` and `results`, 1 each in `base` and `version` |
| Fields | 785 | `model_fields` of those classes, inherited fields counted on each class (632 declared) |
| Closed classes | 168 | `extra="forbid"`; 5 configuration classes are `extra="allow"`, 3 internal ones are open (`results`, `version`) |
| Frozen classes | 174 | `frozen=True` (all but the two `results` classes) |
| Revisions | 5 | `objective::1.0`, `rule::1.0`, `rule::1.1`, `threat::1.0`, `visibility::1.0` |
| `tide.*` metadata keys | 23 | [the table below](#the-tide-metadata-keys) |
| Validators | 21 | 15 decorated (10 `field_validator`, 5 `model_validator`; one of them, `VocabularyEntry._coerce_stages`, in `generation/vocabulary.py`) and 6 `Annotated` (3 `AfterValidator`, 3 `BeforeValidator`) |

These are the numbers issue #807 states (176 classes, 785 fields, 23 keys, 21 validators); the "architecture review" it cites is the plan's companion page, which is private, so the counts were redone here from the code. Two of them depend on how they are counted: 785 counts inherited fields once per class (632 are declared), and 21 counts `Annotated` validators and one validator outside `models/` (14 decorated validators live in `models/`).

## Decision

The Tide model is Rust code in the `opentide-schema` crate (plan §4, "The model"). Each model is a plain struct, each concern a derive, and every artifact that is generated from the Pydantic models today is generated from the structs. Python keeps the classes it has under the same names (UC-1.9, [#815](https://github.com/opentidehq/opentide/issues/815)), built from the structs.

### The derive stack

| Concern | Derive | Notes |
|---------|--------|-------|
| Shape, field order, closure | `serde::{Deserialize, Serialize}` | `#[serde(deny_unknown_fields)]`, `rename`, `alias`, `default` |
| Constraints, custom validators | `garde::Validate` with `#[garde(context(Pins))]` | [`Pins`](https://github.com/opentidehq/opentide/tree/development/crates/opentide-schema/src/pins.rs) carries the vocabulary versions the revision pins (RFC 0003); every field has a rule or `#[garde(skip)]`, sub-structs `#[garde(dive)]` |
| JSON Schema | `schemars::JsonSchema` (schemars 1.x, draft 2020-12) | reads serde's and garde's attributes; the `tide.*` keys are `#[schemars(extend(...))]` |
| Python class | `#[cfg_attr(feature = "python", pyo3::pyclass(frozen, get_all))]` | PyO3 0.30, `abi3-py310`, as `analysis/` is built |
| TypeScript types | behind the `wasm` feature (and `node`, with the napi-rs binding) | UC-5.3 ([#838](https://github.com/opentidehq/opentide/issues/838)); the skeleton's `wasm` feature adds no code, CI builds it for `wasm32-unknown-unknown` |
| Structural errors | `opentide-schema-derive` (UC-1.2, [#808](https://github.com/opentidehq/opentide/issues/808)) | serde stops at the first error; the derive converts the saphyr node tree and collects every structural error with its span, as Pydantic reports every error. serde keeps the happy path and serialisation |

`crates/opentide-schema/src/sample.rs` carries every derive and every convention below on a two-revision family, with tests: YAML → struct → YAML byte for byte (`tests/roundtrip.rs`), the derived schema (`tests/json_schema.rs`, an insta snapshot), and the class from Python (`tests/python.rs`, feature `python`).

### Revisions

- **One concrete struct per revision:** `RuleV1_0`, `RuleV1_1`, and an alias for the newest, `pub type Rule = RuleV1_1`. `metadata.schema` selects the struct (UC-1.7, [#813](https://github.com/opentidehq/opentide/issues/813)).
- **No generic model.** `#[pyclass]` accepts no generic parameters, so `Rule<V>` cannot be a Python class. `crates/opentide-schema/tests/ui/pyclass_generic.rs` is a compile-fail case (trybuild) that records PyO3's error: "`#[pyclass] cannot have generic parameters`".
- **Shared fields are written once.** The `revisions!` macro (`src/revision.rs`) repeats a family's shared fields into each revision struct where its body says `@shared,`. A sub-struct that does not change between revisions is one struct, used by every revision.
- **Naming.** A revision struct is the family's Rust name plus `V<major>_<minor>`. The Python class keeps today's name (`DetectionRule`, `DetectionRule_v1_1`) with `#[pyclass(name = "...")]` (UC-1.9).
- **Migrations** are `From` impls along a forward one-step chain, applied in memory. Files change only through `opentide migrate`.

### The `tide.*` metadata keys

Each key keeps its name, so a field's derived schema holds the same key with the same value as Pydantic's `json_schema_extra`, and the generation pipeline (UC-1.8, [#814](https://github.com/opentidehq/opentide/issues/814)) reads it where the Python pipeline does. The editor schemas `opentide generate` writes carry none of these keys (`strip_framework_keywords`), so keeping the names is what keeps those files byte-identical. The keys are the constants of `opentide_schema::keys` in this order; `crates/opentide-schema/tests/adr.rs` fails when this table and `keys::ALL` differ.

The 23 keys are every `tide.*` string literal in `src/opentide` that names metadata: 27 such literals, less the four highlight captures (`tide.keyword`, `tide.property`, `tide.schema`, `tide.uuid`). Origin says where the oracle sets the key:

- **Field:** a model field declares it (`TideField(schema_extra=...)`, `VocabField`).
- **Pipeline:** `generation/pydantic_metaschema.py` or `models/platform_schema.py` adds it to a field's schema.
- **ReadOnly:** the pipeline reads it but nothing sets it at the oracle; the reader is ported with the key.
- **Lookup:** not a schema key, a request in `lookup_schema_extra`.
- **VocabularyEntry:** a key of a `*.vocab.toml` entry or of the object vocabulary the index builds.

| # | Key | Origin | Attribute | Example | At the oracle |
|---|-----|--------|-----------|---------|---------------|
| 1 | `tide.template.multiline` | Field | `#[schemars(extend("tide.template.multiline" = true))]` | `pub query: String` on `RuleResponse`: templates write `query: \|` | `models/response.py`, 22 fields |
| 2 | `tide.template.spacer` | Field | `#[schemars(extend("tide.template.spacer" = true))]` | `pub metadata: ObjectMetadata` on rules and objectives: a blank line before `metadata:` | `models/rule.py`, 11 fields |
| 3 | `tide.template.required` | Field | `#[schemars(extend("tide.template.required" = true))]` | `pub response: Option<RuleResponse>`: written in the template although optional | `models/rule.py`, 4 fields |
| 4 | `tide.template.hide` | Field | `#[schemars(extend("tide.template.hide" = true))]` | `pub file: Option<String>` on `DetectionRule`: left out of templates and the field catalog | `models/rule.py`, 2 fields |
| 5 | `tide.vocab` | Field | `#[schemars(extend("tide.vocab" = "alert_severity"))]`, or `= true` for the field's own name | `pub severity: String` on `DetectionSignal` | `models/base.py` `VocabField`, 14 fields |
| 6 | `tide.vocab.scoped` | Field | `#[schemars(extend("tide.vocab" = true, "tide.vocab.scoped" = true))]` | `pub entities: Vec<String>`: values such as `Host::Process` | `models/base.py` `VocabField(scoped=True)`, 3 fields |
| 7 | `tide.field.role` | Field | `#[schemars(extend("tide.field.role" = "techniques"))]` | `pub mitre_attack: …` on `ObjectiveBody` | `models/base.py` `FIELD_ROLE_KEY`, 6 fields |
| 8 | `tide.config.responders` | Field | `#[schemars(extend("tide.config.responders" = true))]` | `pub responders: Option<String>` on `RuleResponse` | `models/response.py` |
| 9 | `tide.config.visibility.logsource-names` | Field | `#[schemars(extend("tide.config.visibility.logsource-names" = true))]` | `pub logsources: Option<Vec<String>>` on `SignalData` | `models/objective.py` |
| 10 | `tide.meta.definition` | Pipeline | `#[schemars(extend("tide.meta.definition" = true))]` on the root's `metadata` and `references` | `"metadata": {"tide.meta.definition": true}` | `generation/pydantic_metaschema.py` `_CORE_ROOT_EXTRAS_BASE` |
| 11 | `tide.vocab.pins` | Pipeline | none on a field: the pin transform sets it from `Pins` (UC-1.6, UC-1.8) | `"tide.vocab.pins": {"tlp": "tlp::1.0"}` under `metadata` | `generation/pydantic_metaschema.py` `apply_pin_map` |
| 12 | `tide.config.statuses` | Pipeline | `#[schemars(extend("tide.config.statuses" = true))]` on a platform block's `status` | `status: PREVIEW`, from the platform's configured statuses | `models/platform_schema.py` `_PROPERTY_EXTRAS` |
| 13 | `tide.config.system.tenants` | Pipeline | `#[schemars(extend("tide.config.system.tenants" = "sentinel"))]` on each platform block's `tenants` | `tenants: [prod]`, from `platforms/sentinel.toml` | `models/platform_schema.py` |
| 14 | `tide.meta.deprecation` | ReadOnly | `#[schemars(extend("tide.meta.deprecation" = "message"))]` | `"tide.meta.deprecation": "use query"`, read into the catalog's deprecations | `generation/schema_pipeline.py`, `generation/lsp_catalog.py` |
| 15 | `tide.vocab.hints.no-wrap` | ReadOnly | `#[schemars(extend("tide.vocab.hints.no-wrap" = true))]` | `"tide.vocab.hints.no-wrap": true`: a vocabulary value's hover text is not wrapped | `generation/schema_pipeline.py`, `validation/field_vocab.py` |
| 16 | `tide.config.visibility.detectors` | ReadOnly | `#[schemars(extend("tide.config.visibility.detectors" = true))]` | `detectors: [EDR]`, values from `visibility.toml`'s `[[detectors]]` | `generation/schema_pipeline.py` |
| 17 | `tide.config.parameter-list` | ReadOnly | `#[schemars(extend("tide.config.parameter-list" = "name"))]` | `"tide.config.parameter-list": "name"`: values from that configuration list | `generation/schema_pipeline.py` |
| 18 | `tide.config.systems::enabled` | ReadOnly | `#[schemars(extend("tide.config.systems::enabled" = true))]` | `systems: [sentinel, splunk]`, values from the enabled platforms | `generation/schema_pipeline.py` |
| 19 | `tide.mdr.parameter` | ReadOnly | `#[schemars(extend("tide.mdr.parameter" = "name"))]` | `"tide.mdr.parameter": "query_frequency"`: the key renamed in the platform payload | `generation/framework.py` `rename_param_nest` |
| 20 | `tide.meta` | Lookup | none: `keys::META`, the request for a scope's property map | `lookup_schema_extra(schema, scope, "tide.meta")` | `generation/pydantic_metaschema.py` |
| 21 | `tide.vocab.stages` | VocabularyEntry | `#[serde(rename = "tide.vocab.stages")]` on the vocabulary entry struct (UC-1.6) | `"tide.vocab.stages" = [ "Host", "Cloud",]` | `data/vocabulary/*.vocab.toml`, `generation/vocabulary.py` |
| 22 | `tide.vocab.relation.type` | VocabularyEntry | `#[serde(rename = "tide.vocab.relation.type")]` on the vocabulary entry struct (UC-1.6) | `"tide.vocab.relation.type" = "from"` | `data/vocabulary/chaining_relations.vocab.toml` |
| 23 | `tide.object.parent` | VocabularyEntry | `#[serde(rename = "tide.object.parent")]` on the object-vocabulary entry (UC-2.4) | `"tide.object.parent": "<objective uuid>"` on a signal entry | `indexing/object_vocab.py` |

The six ReadOnly keys have readers and no writer at the oracle: UC-1.8 ports each reader, or removes it as an approved diff.

### Optional versus defaulted, and field order

Pydantic's three cases, and their exact Rust equivalents (counts over the 785 fields):

| Pydantic | Count | Missing key | `null` | Rust | Written |
|----------|------:|-------------|--------|------|---------|
| `x: T` (required) | 249 | error (`missing`) | error | `pub x: T`, no serde default | always |
| `x: T \| None = None` | 375 | `None` | `None` | `#[serde(default, skip_serializing_if = "Option::is_none")] pub x: Option<T>` | omitted when `None` |
| `x: T = value` | 161 | the default | error, unless `T` admits `None` | `#[serde(default = "path")] pub x: T` (schemars emits `"default"`) | always |

- **No required-nullable field exists** (`x: T | None` without a default: 0 of 785). serde reads a missing `Option` as `None` even without `#[serde(default)]`, so such a field, if one is added, needs a deserializer that rejects a missing key.
- **`None` is not written**: struct serialisation equals `model_dump(exclude_none=True)`, which round-trips object files. The four `model_dump(exclude_none=False)` sites (`deployment/planning.py`, `platforms/elastic/{deployer,validator}.py`) are compile and connector code; their ports (UC-3.1, UC-4.x) build the null-filled view they need.
- **Field order** is declaration order, which is serde's order, the template order and the serialisation order. A field is declared where Pydantic declares it, inherited fields first as in Pydantic's MRO.
- **Aliases.** A Pydantic `alias` with `populate_by_name=True` (12 fields: `schema_id`, `platform_schema`, serialised `schema`) is `#[serde(rename = "schema", alias = "schema_id")]`; the Rust and Python attribute keeps Pydantic's name.
- **Lax scalars.** Pydantic reads object YAML in lax mode (a `bool` accepts `"yes"`, an `int` accepts `"3"`), except `StrictInt` fields (2) and the configuration models (`strict=True`). serde reads canonical forms only, so a lax field gets a deserializer with Pydantic's coercion table for its type, and the fault catalogue (UC-0.6) records each coercion.

### Closure

`#[serde(deny_unknown_fields)]` on exactly the 168 classes that are `extra="forbid"`. The 5 `extra="allow"` configuration classes keep their extra keys (`#[serde(flatten)] extra: BTreeMap<String, Value>` in UC-1.5); the 3 open internal classes are not file models. An unknown revision is checked against the newest of its family without the unknown-key check, with a finding (plan §4).

### Errors

Every error is an `opentide_schema::SchemaError`: an `ErrorKind`, the path (`PathSegment::Key` or `Index`, Pydantic's `loc`) and the message in Pydantic's wording. `ErrorKind::pydantic_type()` is Pydantic's error type (`missing`, `extra_forbidden`, `string_type`, `value_error`, …), which the differential runner compares, and `SchemaError::code(surface)` is the code the CLI prints, the same codes as today, none new:

| Kind | Object file | Configuration file |
|------|-------------|--------------------|
| `Syntax` | `yaml_parse` | `config_parse` |
| `Missing` | `schema_validation` | `missing_field` |
| `UnknownKey` | `schema_validation` | `unknown_key` |
| `InvalidType(type)`, `InvalidValue(type)` | `schema_validation` | `schema_validation` |

`invalid_ref` and `vocab_unknown` are derived from a schema error by the workspace (`validation/errors.py`, UC-2.2), not by the model. The enum is `non_exhaustive`: UC-1.2 adds the structural kinds with their Pydantic types.

### Identifiers

Identifiers (`metadata.uuid`, `metadata.schema`, references, external ids) stay `String`: the model reads and writes the text the file holds. A format check stays where the oracle has it: `metadata.uuid` is a plain `str` in Pydantic and `invalid_uuid` is a workspace check, so the model never rejects a malformed UUID. A string becomes a new type only where that changes neither what is accepted nor what is written (`SchemaId` parsing `family::major.minor` for dispatch, for example).

### Validators

The 21 validators and their Rust form. The plan counts 14 constraints or Tide keywords, 2 that disappear, 3 named checks and 2 internal; the item that ports each model decides the exact rule.

| Validator | Where | Rust |
|-----------|-------|------|
| `_validate_schema_identifier`, `_validate_reviewed`, `_require_vocab_list`, `_registered_platform_schema`, `_name_not_empty`, `_unique_per_system`, `_no_legacy_keys`, `_only_connector_arrays` | `metadata.py`, `threat.py`, `platform.py`, `visibility.py`, `configuration/sharing.py` | garde constraints or `custom` validators with `Pins` (8) |
| `_query_not_blank` (`QueryText`), `_single_vocab_name` (`VocabName`), `check_sentinel_technique` (`SentinelTechnique`) | `platform.py`, `threat.py`, `sentinel_attack.py` | garde `custom` on the field type (3) |
| `_status_strategy` (`StatusStrategyName`), `_run_strategy` (`RunStrategyName`), the `FlavorName` lambda | `configuration/base.py`, `configuration/documentation.py` | serde `deserialize_with` on the enum (3) |
| `_coerce_dates`, `_coerce_reviewed` | `metadata.py` | none: YAML 1.2 (saphyr) reads a date as a string (2) |
| `_validate_raw_elastic_block`, `_validate_raw_sysdig_block`, `_columns_fit_system` | `platform.py`, `visibility.py` | named checks `elastic_rule_shape`, `sysdig_rule_shape`, `columns_fit_system` (3) |
| `SchemaVersion._normalise_family`, `VocabularyEntry._coerce_stages` | `version.py`, `generation/vocabulary.py` | internal code (2) |

## Consequences

- **One model, three hosts.** The same structs build for the native target, CPython (abi3-py310) and `wasm32-unknown-unknown`; CI's `schema` job builds all three and tests the Python class.
- **Artifacts become build outputs.** JSON Schemas, the router, field hints, templates and snippets are generated from the structs (UC-1.8), with byte parity against `opentide generate` or approved diffs.
- **What the derived schema does not do yet**, seen in the sample's snapshot (`crates/opentide-schema/tests/snapshots/json_schema__sample_schema.snap`), each a UC-1.8 transform: properties come out sorted, not in field order (schemars orders them through serde_json's map, and its `preserve_order` feature turns on `serde_json/preserve_order` for the whole workspace, which changes the key order of every JSON document the engine writes); fields have no `title` (Pydantic adds `"title": "Name"`); `Option<T>` is `"type": ["T", "null"]`, not Pydantic's `anyOf` with `"default": null`; integers carry `"format": "int64"`.
- **Two Pythons for a while.** Until UC-1.9 the Pydantic models stay the CLI's authority (`crates/AGENTS.md`); the Rust model is checked against them, never the other way round.
- **Costs.** Three proc-macro dependencies (serde, garde, schemars) and PyO3 behind a feature; every model change is a Rust change, reviewed under the workspace lints.

## Alternatives considered

- **Keep Pydantic and generate Rust from it.** Keeps two implementations and a generator between them, which is the drift D-1 removes.
- **Generic revision structs (`Rule<V>`).** Rejected: `#[pyclass]` cannot take them (the compile-fail case above).
- **`validator` instead of garde.** No context parameter, so vocabulary pins could not reach a custom validator; garde's context is the `Pins` the plan names.
- **`eserde` for collect-all errors.** It covers JSON and TOML, not YAML; UC-1.2 writes the conversion from the saphyr tree.

## Evidence

- The counts above, on the oracle's models (opentide 0.23.0, `uv sync --group dev`):

  ```python
  import importlib, inspect, pkgutil
  from pydantic import BaseModel
  root = importlib.import_module("opentide.models")
  modules = [root] + [importlib.import_module(m.name) for m in pkgutil.walk_packages(root.__path__, "opentide.models.")]
  classes = [c for m in modules for c in vars(m).values()
             if inspect.isclass(c) and issubclass(c, BaseModel) and c.__module__ == m.__name__]
  print(len(classes), sum(len(c.model_fields) for c in classes))   # 176 785
  ```

- The skeleton's verification, run in CI's `schema` job: `cargo build -p opentide-schema --features python`, `cargo build -p opentide-schema --target wasm32-unknown-unknown --features wasm`, `cargo nextest run -p opentide-schema --features python`, `cargo xtask check-layers`.
- PyO3 on generics: <https://pyo3.rs/v0.30.1/class.html#no-generic-parameters>, and `crates/opentide-schema/tests/ui/pyclass_generic.stderr`.
- Plan §4, "The model", and §5.5, "Code rules" (typed errors mapped to stable codes).
