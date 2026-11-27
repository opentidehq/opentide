# opentide-exabeam — agent guide

The Exabeam Query Language engine (Exabeam New-Scale SIEM: `configurations.exabeam.sequences[].query`,
hunts with `system: exabeam`, `.exabeam` files). Exabeam's guides call the language "EQL";
opentide never does, because `eql` is Elastic's: the language id is `exabeam`. Exabeam publishes no
grammar and no parser, so the verdicts come from `check.rs`, a step-for-step port of the reference
checker of opentidehq/specifications' `exabeam-1.0`; the fields, subjects, activity types and
outcomes from Exabeam's Common Information Model (`data/catalogs/exabeam/`,
`scripts/engine/sync_exabeam_catalog.py`). A tree on opentide-parse (`cst.rs`) drives highlighting.
Two profiles: `rule` and `search`. Design and conformance: `docs/engine/EXABEAM.md`.

## Place

foundation, tier 2: depends on opentide-core, -dataset, -highlight and -parse; on no other query
engine (`xtask/layers.toml`). Used by opentide-tide (the block constraints, in `src/lib.rs`) and
-analysis.

## Invariants

- I/O-free: no `std::fs` in `src/`; the catalogs are embedded (`opentide_dataset::text!`) and
  parsed once.
- `check.rs` follows the reference checker step for step; its verdict on every conformance query
  is recorded in `crates/testdata/conformance/exabeam/reference.json`
  (`scripts/engine/sync_exabeam_conformance.py`) and the engine must agree.
- Regular expressions are RE2's: read with `regex-syntax`, after RE2's own rules and refusals.
- The SQL-like operators (`SELECT`, `GROUP-BY`, ...) belong to this language's advanced grammar and
  to no generic SQL support, which opentide does not have.

## Test

```bash
cargo nextest run --profile fast -p opentide-exabeam
```

`tests/reference.rs` and `tests/conformance.rs` hold the engine to the reference checker;
`tests/trees.rs` (snapshots), `tests/captures.rs` and `tests/keywords.rs` the tree and its
highlighting; `tests/long_runs.rs` the length guards. `tests/content_hub.rs` measures Exabeam's
published correlation rules, which may not be redistributed: it is ignored and reads a local
checkout.

## Do not

- Call the language "EQL" in code, codes or docs.
- Reshape `check.rs` for style: it mirrors the reference checker so that a diff against it stays
  readable.

## Every engine crate

- Lints, tests, snapshots and the layer rule: [`crates/AGENTS.md`](../AGENTS.md); the Rust
  conventions (errors, `OnceLock` catalogs, dependencies): the
  [rust-engine](../../.agents/skills/rust-engine/SKILL.md) skill.
