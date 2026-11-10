# opentide-schema — agent guide

The Tide model as Rust code (plan D-2): object, platform and configuration models as plain structs
with serde, garde, schemars and PyO3 derives, from which the JSON Schemas, field hints, templates,
snippets, `.pyi` and `.d.ts` are generated. Today it holds the skeleton (UC-1.1, #807): the
conventions, the `Pins` validation context, the typed errors, the 23 `tide.*` metadata keys and
`sample`, their worked example; the vocabularies and pins (UC-1.6, `vocab`); and the object models
(UC-1.3, `objects`). The conventions are decided in
[ADR 0001](../../docs/internal/adr/0001-tide-model-as-rust-code.md); read it before adding a model.

## Place

foundation, top tier (`xtask/layers.toml`), as the plan's table orders it: it may depend on
opentide-core, -syntax, -highlight and the query crates, and none of them may depend on it. Today it
depends on opentide-core (`codes`, `suggest`). Not published yet (`publish = false` in `Cargo.toml`, with the reason).

## Layout

| Path | What |
| --- | --- |
| `src/keys.rs` | The 23 `tide.*` keys as constants, each with where the oracle sets it (`Origin`) |
| `src/error.rs` | `SchemaError`, `ErrorKind` (Pydantic's error type) and `code(Surface)` (the CLI's code) |
| `src/pins.rs` | `Pins`: the contracts a revision pins, by field path (`contract`) and by vocabulary (`version`), garde's context; `PinTable`: every revision's, from `src/opentide/data/pins/*.toml` (`bundled`) |
| `src/vocab/` | Vocabularies (UC-1.6, #812): `Vocabulary` (a `*.vocab.toml` document), `Vocabularies` (the bundle, parsed per file on first use, or a data root's files, plus a workspace's object vocabularies), `Selector`/`Resolved` (what a field accepts: pins, stages, scoped values; `is_valid`, `suggest`, `check` → `Unknown`, the `vocab_unknown` finding), `attack` (the ATT&CK matrix of `info catalog`), `sentinel` (Sentinel's ATT&CK v18 list) |
| `src/vocab/bundled.rs` | The bundled documents, one `include_str!` each; `tests.rs` fails when it and `src/opentide/data/vocabulary` differ |
| `src/revision.rs` | `revisions!`: one struct per revision, shared fields written once, in groups `@0,` … `@3,` around overridden fields |
| `src/sample.rs` | Every derive and field convention on a two-revision family; not part of the model |
| `src/objects/` | The object models (UC-1.3, #809): `metadata` (`ObjectMetadata`, `RuleMetadata`, `ObjectReferences`, `Organisation`), `response`, `threat` (`ThreatVectorV1_0`), `objective` (`ObjectiveV1_0`), `rule` (`RuleV1_0`, `RuleV1_1`, `RuleConfigurations`), `role` (`FieldRole`), `any` (an unchecked value), `checks` (the validators, run by the conversion and by garde), `tests.rs` (the ported `tests/test_models/` tests) |
| `src/node.rs` | The YAML node tree (UC-1.2): saphyr-parser's events, saphyr's YAML 1.2 core-schema scalars, every node's position; `node/locate.rs` places a field path (span, `yaml_line`), `node/dump.rs` writes a model (serde-saphyr) |
| `src/from_node.rs` | `FromNode` and what `#[derive(FromNode)]` (`opentide-schema-derive`) expands to: every structural error collected, with its path and position |
| `YAML.md` | Generated: every YAML case read by the oracle (PyYAML, YAML 1.1) and by `node` (YAML 1.2), with each difference and its reason |
| `tests/yaml_table.rs` | `tests/oracle/yaml_cases.toml` against the oracle (`yaml_table.json`, from `yaml_table.py`); writes `YAML.md` |
| `tests/from_node_table.rs` | `tests/oracle/from_node_cases.toml` against the oracle (`from_node_table.json`, from `from_node_table.py`); the Rust results are the insta snapshot |
| `src/objects/table.rs` (a unit test: rules read under `cfg(test)`) | `tests/oracle/objects_cases.toml` and every object file of `tests/fixtures/tide_corpus` and the VS Code fixture against the oracle (`objects_table.json`, from `objects_table.py`); the Rust results are the insta snapshot |
| `tests/round_trip_property.rs`, `tests/from_node_api.rs`, `tests/fuzz_regressions.rs` | proptest round trip, the API, and the `from_node` fuzz target's seeds and saved crashes |
| `tests/roundtrip.rs` | YAML → struct → YAML byte for byte; optional, defaulted, alias, closure, pins |
| `tests/json_schema.rs` | The derived schema (insta snapshot) and its `tide.*` keys |
| `tests/adr.rs` | ADR 0001's key table matches `keys::ALL` |
| `tests/python.rs` | Feature `python`: the class from Python, frozen, attribute access |
| `tests/ui.rs`, `tests/ui/` | Feature `python`: compile-fail cases (trybuild), e.g. no generic `#[pyclass]` |

## Invariants

- The Pydantic models in `src/opentide/models` at the frozen tag are the oracle. A model here is
  the same shape: field names, serialised names, order, optional and defaulted fields, closure,
  constraints, metadata keys. A difference is an approved diff (`tests/golden/APPROVED_DIFFS.toml`)
  or a bug.
- One concrete struct per revision; no generic model (`#[pyclass]` cannot take one).
- A `tide.*` key keeps its name and value: `#[schemars(extend("tide.…" = …))]`, and the key is in
  `keys::ALL`. A new key is a new row in the ADR's table and in `keys.rs` (`tests/adr.rs` checks).
- Identifiers stay `String`, checked where the oracle checks them (`invalid_uuid` is a workspace
  check, not a schema error).
- Errors are `SchemaError`; codes are the CLI's, as constants (`error::codes`, which re-exports
  `opentide_core::codes::SCHEMA_VALIDATION`): never mint one, never a second string at a call site.
- No `std::fs` in `src/` (`scripts/engine/check-io-free.sh`). The derives compile for wasm32.
- Suggestions are `opentide_core::suggest`'s (strsim), never a port of Python's `difflib`: where
  one differs from the oracle's on a corpus value, `tests/golden/vocab/APPROVED.toml` lists it and
  `cargo xtask vocab diff --against python` checks it. Accepted values and validity never differ.
- YAML is YAML 1.2, read by the saphyr crates; never re-implement a YAML 1.1 rule to match the
  oracle. A case where the oracle reads YAML differently names a `[[difference]]` in
  `tests/oracle/yaml_cases.toml` (reason, CHANGELOG lead); `YAML.md` shows them all.
- A field takes its declared type, without Pydantic's lax coercion; a case of
  `tests/oracle/from_node_cases.toml` or `objects_cases.toml` where the result differs from the
  oracle names its `[[difference]]`.
- A validator is written once (`objects::checks`) and run by both hosts: the structural
  conversion (`#[from_node(with = ...)]`, so its error sits among the others in Pydantic's order)
  and garde (`#[garde(custom(...))]`).
- The platform blocks are UC-1.4's: until then a block is an `UncheckedBlock`, and the rule models
  read only with the `unchecked-platform-blocks` feature, which xtask turns on, or in the crate's
  unit tests (`cfg(test)`); its integration tests cannot read a rule. Nothing that ships may.

## Test

```bash
cargo nextest run -p opentide-schema                       # native, no Python
cargo nextest run -p opentide-schema --features python     # + the Python class and trybuild
cargo build -p opentide-schema --target wasm32-unknown-unknown --features wasm
cargo nextest run -p opentide-schema vocab                 # the vocabularies, 13k misspellings
cargo xtask vocab diff --against python                    # against the oracle, every corpus
cargo nextest run -p opentide-schema objects::table        # the object models against the oracle's table
cargo xtask schema diff --against python                   # JSON Schemas and every corpus, live
cargo xtask corpus faults --check --engine rust --only objects
```

`tests/python.rs` embeds CPython: it links the shared libpython of `PYO3_PYTHON` (or `python3`),
which must be 3.10 or later; put its `LIBDIR` on `LD_LIBRARY_PATH` if the loader cannot find it.
The oracle tables are regenerated with the oracle's interpreter (`tests/golden/ORACLE`):
`<oracle python> tests/oracle/yaml_table.py`, `from_node_table.py` and `objects_table.py`; after a change to what the
loader reads, `UPDATE_YAML_TABLE=1 cargo test -p opentide-schema --test yaml_table` rewrites
`YAML.md`. After an intended schema change, `cargo insta review`; after a compiler message change,
`TRYBUILD=overwrite cargo test -p opentide-schema --features python --test ui`. The
`.stderr` quotes PyO3's documentation URL with its exact version, so a PyO3 bump regenerates it in
the same change.

## Do not

- Turn on schemars' `preserve_order` here without checking the workspace: it enables
  `serde_json/preserve_order` for every crate, which changes the key order of every JSON document
  the engine writes (ADR 0001, "Consequences").
- Parse an identifier into a new type where that changes what is accepted or written.
- Start a later Phase 1 item here before UC-0.5, UC-0.6 and UC-0.7 are merged (epic #790).

## Work items that change this crate

UC-1.2 (#808) collect-all structural errors from the saphyr tree (`opentide-schema-derive`); UC-1.3
(#809) object models; UC-1.4 (#810) platform blocks; UC-1.5 (#811) configuration models; UC-1.6
(#812) vocabularies and pins; UC-1.7 (#813) revisions and migrations; UC-1.8 (#814) generated
artifacts; UC-1.9 (#815) Python exposure; UC-5.3 (#838) TypeScript types behind `wasm`.

## Every engine crate

- Lints, tests, snapshots and the layer rule: [`crates/AGENTS.md`](../AGENTS.md); the Rust
  conventions (errors, `OnceLock` catalogs, dependencies): the
  [rust-engine](../../.agents/skills/rust-engine/SKILL.md) skill.
