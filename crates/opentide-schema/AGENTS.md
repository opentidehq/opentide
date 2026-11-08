# opentide-schema — agent guide

The Tide model as Rust code (plan D-2): object, platform and configuration models as plain structs
with serde, garde, schemars and PyO3 derives, from which the JSON Schemas, field hints, templates,
snippets, `.pyi` and `.d.ts` are generated. Today it is the skeleton (UC-1.1, #807): the
conventions, the `Pins` validation context, the typed errors, the 23 `tide.*` metadata keys and
`sample`, their worked example. The conventions are decided in
[ADR 0001](../../docs/internal/adr/0001-tide-model-as-rust-code.md); read it before adding a model.

## Place

foundation, tier 1 (`xtask/layers.toml`): it may depend on opentide-core; it depends on no
workspace crate today. Not published yet (`publish = false` in `Cargo.toml`, with the reason).

## Layout

| Path | What |
| --- | --- |
| `src/keys.rs` | The 23 `tide.*` keys as constants, each with where the oracle sets it (`Origin`) |
| `src/error.rs` | `SchemaError`, `ErrorKind` (Pydantic's error type) and `code(Surface)` (the CLI's code) |
| `src/pins.rs` | `Pins`: the vocabulary versions a revision pins, garde's context |
| `src/revision.rs` | `revisions!`: one struct per revision, shared fields written once (`@shared,`) |
| `src/sample.rs` | Every derive and field convention on a two-revision family; not part of the model |
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
- Errors are `SchemaError`; codes are the CLI's (`yaml_parse`, `schema_validation`,
  `missing_field`, `unknown_key`): never mint one here.
- No `std::fs` in `src/` (`scripts/engine/check-io-free.sh`). The derives compile for wasm32.

## Test

```bash
cargo nextest run -p opentide-schema                       # native, no Python
cargo nextest run -p opentide-schema --features python     # + the Python class and trybuild
cargo build -p opentide-schema --target wasm32-unknown-unknown --features wasm
```

`tests/python.rs` embeds CPython: it links the shared libpython of `PYO3_PYTHON` (or `python3`),
which must be 3.10 or later; put its `LIBDIR` on `LD_LIBRARY_PATH` if the loader cannot find it.
After an intended schema change, `cargo insta review`; after a compiler message change,
`TRYBUILD=overwrite cargo test -p opentide-schema --features python --test ui`.

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
