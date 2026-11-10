---
title: "0011: The Rust models in Python"
description: "UC-1.9: the Tide models are frozen PyO3 classes under their Pydantic names, in opentide._native.models, with the Pydantic methods SDK code calls and generated stubs; opentide.models keeps the Pydantic classes until the CLI stops reading them."
---

# 0011: The Rust models in Python

| | |
|---|---|
| Status | Proposed |
| Date | 2026-11-10 |
| Decision | UC-1.9 |
| Issues | [#815](https://github.com/opentidehq/opentide/issues/815), epic [#790](https://github.com/opentidehq/opentide/issues/790) |

## Context

The Tide model is Rust code ([ADR 0001](./0001-tide-model-as-rust-code.md)): `opentide-schema` holds every object model and platform block (UC-1.3, UC-1.4). Python reaches them nowhere yet. Invariant 7 of the plan keeps the SDK's import paths for one deprecation cycle, `opentide.models.*` among them, and UC-1.9 is the item that puts the Rust structs behind those names.

What SDK code calls on a model, found by searching `docs/sdk`, `tests/` and `src/opentide` (opentide 0.23):

| Pydantic surface | Where it is used |
|------------------|------------------|
| Field access, nested models, `metadata.schema` and a block's `.schema` (read-only aliases of `schema_id` and `platform_schema`) | `docs/sdk/models.md`, everywhere |
| `model_validate(dict)`, raising `ValidationError` with `errors()` | 28 test calls, 17 in `src` (the loaders, validation) |
| `model_dump(by_alias=..., exclude_none=...)` | 4 in tests, 16 in `src`; `docs/sdk/models.md` documents `model_dump(by_alias=True)["schema"]` |
| `model_copy(update=..., deep=...)` | 11 in `src` (`bind_registry`, migrations, fixes) |
| `model_json_schema()` | 4 in tests, 6 in `src` (the generation pipeline) |
| `model_fields` (`FieldInfo`: annotation, default, `json_schema_extra`, docstring) | 13 in tests, 18 in `src` (generation, `core.object_fields` roles, `platform_statuses`) |
| `__schema_identifier__`, `schema_identifier()` | `docs/sdk/models.md`, the registry |
| Equality, hashing (frozen models), `repr`, pickling (`multiprocessing` in validation) | tests, `validation/session.py` |
| `DetectionRule.platform_statuses`, `displayed_severity`, `alert_severity` (properties), `platform_configs()` | deploy, documentation |
| Delegation: `bind_registry`, `validate`, `validate_query`, `run_query`, `deploy`, `document`, `promote`, `from_yaml_dict` | `docs/sdk/models.md`, `Opentide.Rules[...]` |
| `isinstance(rule, DetectionRule_v1_1)` → also a `DetectionRule` (Pydantic subclass) | `platforms/plugins.py`, plugins |

The Python CLI is still built on the Pydantic classes: 126 modules of `src/opentide` import `opentide.models`, the validation pipeline reads Pydantic's `ValidationError`, and the generation pipeline (`generation/`, 5.2k lines) reads `model_fields` and Pydantic's JSON Schema. `crates/AGENTS.md` keeps Pydantic as the CLI's authority for Tide objects until the workspace (UC-2) and the CLI (UC-3) move to Rust.

## Decision

1. **The classes.** Every object model, metadata model and platform block of `opentide-schema` (103 classes) is `#[pyclass(frozen, get_all, eq, name = "<Pydantic name>", module = "opentide._native.models")]` behind the crate's `python` feature: `DetectionRule`, `DetectionRule_v1_1`, `DetectionObjective`, `ThreatVector`, `ObjectMetadata`, `RuleMetadata`, `RuleConfigurations`, `SentinelConfig`, … Each one's attributes are Pydantic's, in Pydantic's order, under Pydantic's names (`objective.type`: the Rust field is `r#type`), which `tests/test_models/test_native_models.py` checks class by class. The binding (`analysis/`) exports them as `opentide._native.models`, registered in `sys.modules`.
2. **The methods** (`crates/opentide-schema/src/python.rs`, one macro for every class, so no class differs):

   | Pydantic | Rust class |
   |----------|------------|
   | field access | `get_all`: a nested model is its class, a union member that is a model is its class (`ElasticConfig.severity`), anything free-form is plain Python data (`dict` in the document's order, `list`, `str`, `int`, `float`, `bool`, `None`) |
   | `.schema` aliases | `__getattr__`: any serialised name that is not the attribute's reads the attribute |
   | `model_validate(obj)` | the structural conversion (UC-1.2): every error, with Pydantic's `type`, `loc` and `msg`; raises `opentide._native.models.ValidationError`, a `ValueError` with `errors()`, `error_count()` and `title`. A `date` or `datetime` reads as `core.io` writes it (ISO 8601, a UTC offset as `Z`); a model (Rust or Pydantic) reads as its `model_dump(by_alias=True, exclude_none=True)` |
   | `model_validate_json(text)` | `json.loads`, then `model_validate` |
   | `model_dump(by_alias=, exclude_none=)`, `model_dump_json(..., indent=)` | the same dictionaries as Pydantic's (`mode="python"`), checked on every fixture object |
   | `model_copy(update=, deep=)` | the dump with `update` applied, **validated** (Pydantic does not validate `update`); an unknown field is a `ValueError`. `deep` changes nothing: the models are immutable |
   | `model_json_schema()` | schemars' schema (draft 2020-12), the one UC-1.8 generates from; it is not Pydantic's |
   | `__schema_identifier__`, `schema_identifier()` | on the four object revisions and the nine platform blocks |
   | `==`, `hash`, `repr`, pickling | by value: `hash` is consistent with `==` (mappings in another order are equal and hash alike, as `dict`s); `repr` is Pydantic's text, field by field; pickling rebuilds through `model_validate` |
   | `platform_statuses`, `displayed_severity`, `alert_severity`, `platform_configs()` | the same, on `DetectionRule` and `DetectionRule_v1_1` |
   | `model_fields` | not provided: `__tide_fields__` lists each field's attribute and serialised name; the field metadata is in `model_json_schema()` |

3. **The stubs are generated.** PyO3 compiles a description of every class into the extension when its `experimental-inspect` feature is on (`opentide-native`'s `stubs` feature, never in a wheel); `cargo xtask stubs` builds that extension, reads it back with `pyo3-introspection` (the crate `maturin generate-stubs` uses) and writes `src/opentide/_native/models.pyi`. `src/opentide/_native.pyi` became `src/opentide/_native/__init__.pyi` (still written by hand for the engine's functions) so that the generated module has a file of its own. `ty` reads the stub; CI's `schema` workflow runs `cargo xtask stubs --check`.
4. **`opentide.models` keeps the Pydantic classes for now.** Rebinding `opentide.models.DetectionRule` to the Rust class while the CLI imports it would move the CLI's validation, generation and registry onto an API they were not written for, in one step, with no golden to compare it against. The names move in two steps:
   - **This item:** the Rust classes exist under their Pydantic names, compared with the Pydantic classes on every fixture object and every case of the schema crate's oracle tables, and typed by generated stubs.
   - **The flip** (a maintainer's decision, below): `opentide.models.*` re-exports the Rust classes; the Pydantic classes move to a private module the remaining Python CLI code imports until UC-2 and UC-3 retire it; each Pydantic method SDK code calls and the Rust classes do not have (`model_fields`, `model_construct`, `model_rebuild`, `model_post_init`) gets a deprecation shim for one minor release, with an **Upgrade** entry in the changelog. The delegation helpers (`bind_registry`, `deploy`, `validate`, `document`, `run_query`, `promote`, `from_yaml_dict`) stay a thin Python layer: a Python subclass of the frozen class needs `#[pyclass(subclass)]`, or the helpers move to the facade (`Opentide.render_rule(rule)` already exists).

## Consequences

- SDK users see no change in this item: `opentide.models` imports as before, and `import opentide.models` still costs Pydantic's import (about 200 ms). `import opentide._native.models` takes about 6 ms, so the 30 ms budget is met once the names flip.
- Differences from the Pydantic classes, each tested:
  - `DetectionRule_v1_1` is not a subclass of `DetectionRule` (a PyO3 class can extend another only by embedding its struct, and the two revisions' `metadata` types differ); `isinstance(rule, (DetectionRule, DetectionRule_v1_1))` replaces `isinstance(rule, DetectionRule)`.
  - `DetectionRule.file` is a `str`, where Pydantic holds a `Path`.
  - `model_copy(update=...)` validates the copy.
  - `model_json_schema()` is schemars' document, not Pydantic's (UC-1.8 owns the generated schemas).
  - `ValidationError` is not Pydantic's: `errors()` holds `type`, `loc`, `msg`, and `input` and `ctx` where the Rust model records them; Pydantic's `url` is not there.
  - Free-form mappings (`platforms`, Sentinel's and Defender's `let`, Elastic's `meta`, `query`, `notify`, `respond`, `filters`, `references.internal`, threat `chaining`) are ordered maps (`IndexMap`) in Rust too, so they read back in the document's order, as a Python `dict` does; they were `BTreeMap`s, sorted by key.
- ValidationError is a `create_exception!` type: abi3 cannot subclass an exception with a Rust class, so `errors()`, `error_count()` and `title` are attributes of the instance, and PyO3's introspection cannot describe it, so the generated stub ends with a module `__getattr__` (an incomplete stub, the typing guidance's convention) instead of declaring it.
- The stub build compiles PyO3 a second time with another feature set, in the `develop` profile `uv sync` uses, so locally only PyO3, `opentide-schema` and the extension rebuild.

## Needs a maintainer

The flip in decision 4: when `opentide.models.*` re-exports the Rust classes, and whether the Pydantic classes move to a private module for the CLI until UC-2 and UC-3, or stay until then. Either way the acceptance criteria of #815 that depend on the flip (the SDK test suite and the `docs/sdk` snippets against the Rust classes, the 30 ms import of `opentide.models`, the deprecation shims) are met in the change that flips.

## Evidence

- Plan §3 invariant 7, §4 "The model", D-2; [ADR 0001](./0001-tide-model-as-rust-code.md).
- `tests/test_models/test_native_models.py`: every Rust class against its Pydantic class (names, fields, serialised names, identifiers); every object file under `tests/fixtures` (50) read by both, with equal `model_dump` in four modes and equal `repr`; 221 cases of `objects_cases.toml` and `platform_cases.toml` with identical errors (`type`, `loc`, `msg`).
- `crates/opentide-schema/tests/python_models.rs`: the classes in an embedded CPython: frozen (a compile-time assertion and `setattr`), equality and hashing, pickling, copies, every error at once.
- Import time, `python -X importtime -c "import opentide._native.models"`: 6.4 ms to 7.2 ms (warm); `import opentide.models`: about 200 ms (Pydantic).
- PyO3 type stubs: <https://pyo3.rs/v0.30.1/type-stub.html>; abi3 and exception subclasses: <https://pyo3.rs/v0.30.1/building-and-distribution.html#py_limited_apiabi3>.
