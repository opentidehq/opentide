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
| `model_dump(mode="json", ...)` | a platform block's in `deployment/preview.py`; 4 in tests (`test_flatten_mapping.py`) |
| `model_copy(update=..., deep=...)` | 11 in `src` (`bind_registry`, migrations, fixes) |
| `model_json_schema()`, `model_json_schema(by_alias=True)` | 4 in tests (`test_threat.py` passes `by_alias=True`), 6 in `src` (the generation pipeline) |
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
   | `.schema` aliases | a read-only `schema` property on the eleven classes whose serialised name differs from the attribute (`ObjectMetadata`, `RuleMetadata`, the nine platform blocks); the Python suite checks that every such field has one. No `__getattr__`: a misspelt attribute is an `AttributeError` at run time and an error for `ty` |
   | `model_validate(obj)` | the structural conversion (UC-1.2): every error, with Pydantic's `type`, `loc` and `msg`; raises `opentide._native.models.ValidationError`, a `ValueError` with `errors()`, `error_count()` and `title`. A `date` or `datetime` reads as `core.io` writes it (ISO 8601, a UTC offset as `Z`); a model (Rust or Pydantic) reads as its `model_dump(by_alias=True, exclude_none=True)`. A value no document can hold is a `ValidationError` too, at its location, never an `OverflowError` or a `TypeError`: an `int` outside 64 bits (`int_parsing_size`), a `str` with lone surrogates (`string_unicode`, Pydantic's), any other type (`is_instance_of`), a value nested past the reader's depth limit or holding itself (`recursion_loop`); the other errors of the input are still reported |
   | `model_validate_json(text)` | `json.loads`, then `model_validate` |
   | `model_dump(mode=, by_alias=, exclude_none=)`, `model_dump_json(..., indent=)` | the same dictionaries as Pydantic's, checked on every fixture object. `mode="json"` and `mode="python"` give the same values: every field already holds what JSON holds (`DetectionRule.file` is a `str`, dates are the loader's text); another mode is a `ValueError`. `model_dump_json` keeps non-ASCII text as it is |
   | `model_copy(update=, deep=)` | the dump with `update` applied, **validated** (Pydantic does not validate `update`); an unknown field is a `ValueError`. `deep` changes nothing: the models are immutable |
   | `model_json_schema(by_alias=True, mode="validation")` | schemars' schema (draft 2020-12), the one UC-1.8 generates from; it is not Pydantic's. It names fields by their serialised names, which is Pydantic's default `by_alias=True`; `by_alias=False` is a `ValueError`. `mode` is `"validation"` or `"serialization"`, which describe the same document |
   | `__schema_identifier__`, `schema_identifier()` | on the four object revisions and the nine platform blocks |
   | `==`, `hash`, `repr`, pickling | by value: `hash` is consistent with `==` (mappings in another order are equal and hash alike, as `dict`s); `repr` is Pydantic's text, field by field; pickling rebuilds through `model_validate` |
   | `platform_statuses`, `displayed_severity`, `alert_severity`, `platform_configs()` | the same, on `DetectionRule` and `DetectionRule_v1_1` |
   | `model_fields` | not provided: `__tide_fields__` lists each field's attribute and serialised name; the field metadata is in `model_json_schema()` |

3. **The stubs are generated.** PyO3 compiles a description of every class into the extension when its `experimental-inspect` feature is on (`opentide-native`'s `stubs` feature, never in a wheel); `cargo xtask stubs` builds that extension, reads it back with `pyo3-introspection` (the crate `maturin generate-stubs` uses) and writes `src/opentide/_native/models.pyi`. The stub is complete: it declares every class and `ValidationError`, has an `__all__`, and no `__getattr__` on the module or a class, so `ty` reports a misspelt attribute or an import of a name the module does not have. `src/opentide/_native.pyi` became `src/opentide/_native/__init__.pyi` (still written by hand for the engine's functions) so that the generated module has a file of its own. `ty` reads the stub; CI's `schema` workflow runs `cargo xtask stubs --check`.
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
  - A value no document can hold (above) reports Pydantic's location, with the type and message of the Rust reader: Pydantic accepts an integer of any size, and names the expected type of the field rather than the value's.
  - `model_json_schema(by_alias=False)` is refused: the schema is generated with the serialised names.
- ValidationError is a `create_exception!` type: abi3 below Python 3.12 cannot subclass an exception with a Rust class, so `errors()`, `error_count()` and `title` are attributes of the instance, and PyO3's introspection cannot describe the class. The module exports it through a value whose type is `type[ValueError]` (`ValidationErrorClass` in `python.rs`), so the stub declares `ValidationError: Final[type[ValueError]]`: `except ValidationError` type-checks, and `errors()` on the caught error is an attribute a type checker does not see (the Python suite reads it with a `ty: ignore` and its reason).
- `isinstance(rule, DetectionRule)` for a `DetectionRule_v1_1` cannot be shimmed: an `isinstance` override needs a metaclass, which a PyO3 class cannot have. It is a difference, listed above, and an **Upgrade** entry at the flip.
- The stub build compiles PyO3 a second time with another feature set, in the `develop` profile `uv sync` uses, so locally only PyO3, `opentide-schema` and the extension rebuild.

## Needs a maintainer

The flip in decision 4: when `opentide.models.*` re-exports the Rust classes, and whether the Pydantic classes move to a private module for the CLI until UC-2 and UC-3, or stay until then. Either way the acceptance criteria of #815 that depend on the flip (the SDK test suite and the `docs/sdk` snippets against the Rust classes, the 30 ms import of `opentide.models`, the deprecation shims, the delegation helpers) are met in the change that flips.

Why the flip is not only a re-export:

- The `docs/sdk` snippets read objects through the facade (`Opentide.Rules[uuid]`, `docs/sdk/models.md`), which the Python registry builds with the Pydantic loaders. Re-exporting the names leaves those objects Pydantic ones, so the criterion "the snippets pass against the Rust models" needs the registry and the loaders to build Rust objects: the workspace's work (UC-2).
- The delegation helpers (`rule.deploy()`, `rule.validate()`, `rule.document()`, `bind_registry`) reach the registry, deploy and documentation code, which reads Pydantic's `model_fields` and `ValidationError`. On the Rust classes they need either `#[pyclass(subclass)]` and a Python subclass per class, or the facade (`Opentide.render_rule`); which one is the SDK's public shape.
- SDK code that catches `pydantic.ValidationError` from `model_validate` stops catching it: `opentide._native.models.ValidationError` is a `ValueError`, not Pydantic's. That is a breaking change for one release's **Upgrade** notes, not a mechanical one.

## Evidence

- Plan §3 invariant 7, §4 "The model", D-2; [ADR 0001](./0001-tide-model-as-rust-code.md).
- `tests/test_models/test_native_models.py`: every Rust class against its Pydantic class (names, fields, serialised names, identifiers); every object file under `tests/fixtures` (50) read by both, with equal `model_dump` in four modes and equal `repr`; 221 cases of `objects_cases.toml` and `platform_cases.toml` with identical errors (`type`, `loc`, `msg`).
- `crates/opentide-schema/tests/python_models.rs`: the classes in an embedded CPython: frozen (a compile-time assertion and `setattr`), equality and hashing, pickling, copies (an update names attributes: `schema` is refused before validation), every error at once, the message's count and `<root>`, `input` and `ctx`, values no document holds, `mode` and `by_alias`, non-ASCII JSON.
- `tests/test_models/test_native_models.py` also compares each error's `input` and `ctx` with Pydantic's on the oracle cases, and checks the stub is complete (no `__getattr__`, `ValidationError` declared, `__all__`).
- `cargo test -p xtask stubs`: `--check` passes on the generated text only; a stale or missing stub is reported with the diff from the file to the generated text.
- Import time, `python -X importtime -c "import opentide._native.models"`: 6.4 ms to 7.2 ms (warm); `import opentide.models`: about 200 ms (Pydantic).
- PyO3 type stubs: <https://pyo3.rs/v0.30.1/type-stub.html>; abi3 and exception subclasses: <https://pyo3.rs/v0.30.1/building-and-distribution.html#py_limited_apiabi3>.
