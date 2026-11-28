# opentide-spl — agent guide

The Splunk SPL engine: parse, the command, field, macro and CIM data model catalogs
(`data/catalogs/spl/`), declared datasets, diagnostics, highlighting, hover and completion.

## Place

foundation, tier 2: depends on opentide-core, -syntax, -highlight. Used by opentide-tide, -analysis and -lsp.

## Invariants

- I/O-free: no `std::fs` in `src/`; the catalogs are compiled in (`include_str!`) and parsed once (`OnceLock`).
- SPL findings are `opentide_core::Diagnostic`s with codes from `opentide_core::codes`; no error enum of its own.
- Unknown commands are never silently eaten: an unknown command is a diagnostic.
- Highlighting tokenizes the **authored** text: an implicit leading `| search` is not a source rewrite.

## Test

```bash
cargo nextest run --profile fast -p opentide-spl
```

`tests/grammar_forms.rs` covers the grammar's forms; CIM data models come from
`scripts/engine/sync_cim_datamodels.py`. The Splunk oracle runs through `scripts/engine/ci-oracle.sh`.

## Do not

- Rewrite the user's query before highlighting it.

## Work items that change this crate

- UC-2.5 (#820): query analysis wired through `opentide-workspace`.
- UC-0.3 (#801): the Splunk oracle in one CI.

## Every engine crate

- Lints, tests, snapshots and the layer rule: [`crates/AGENTS.md`](../AGENTS.md); the Rust
  conventions (errors, `OnceLock` catalogs, dependencies): the
  [rust-engine](../../.agents/skills/rust-engine/SKILL.md) skill.
- Items of the plan (`docs/internal/unified-core.md`, §6) that reach every engine crate: UC-0.3
  (#801) one CI with nextest; UC-X.1 (#843) unsafe policy, cargo-deny and fuzzing in CI; UC-X.2
  (#844) coverage gates per crate; UC-5.5 (#840) the lockstep release train.
