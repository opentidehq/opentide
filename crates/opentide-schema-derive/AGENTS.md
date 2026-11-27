# opentide-schema-derive — agent guide

`#[derive(FromNode)]`, the proc-macro behind opentide-schema's structural conversion of a model
from the YAML node tree, every error collected (UC-1.2, #808; ADR 0001, "The derive stack"). It
reads the serde attributes the models already carry (`deny_unknown_fields`, `rename`, `alias`,
`default`, `rename_all`) and its own `#[from_node(...)]` ones (`model`, `before`, `after`,
`tolerate`, `with`, `literal`, `union`); the table of what each does is the crate's doc
(`src/lib.rs`). A struct also gets `opentide_schema::from_node::Model`.

## Place

foundation, tier 0: depends on no workspace crate (`syn`, `quote`, `proc-macro2`). Its expansion
names opentide-schema's paths, so only opentide-schema uses it (`xtask/layers.toml`).

## Invariants

- The generated code reports errors as Pydantic did (`extra_forbidden`, "Field required",
  `literal_error`, ...): a change to the expansion is a change to what `opentide validate`
  reports.
- A wrong attribute is a compile error with a span (`syn::Error`), never a panic.

## Test

```bash
cargo nextest run --profile fast -p opentide-schema-derive -p opentide-schema
```

The expansion's own unit tests are in `src/lib.rs`; the derive is held through the models that use
it by `crates/opentide-schema/tests/from_node_table.rs` (the conversion against the recorded oracle
table) and `tests/from_node_api.rs`.

## Every engine crate

- Lints, tests, snapshots and the layer rule: [`crates/AGENTS.md`](../AGENTS.md); the Rust
  conventions: the [rust-engine](../../.agents/skills/rust-engine/SKILL.md) skill.
