# opentide-kuery — agent guide

The Kibana Query Language (`kuery`) engine: parse as Kibana's `grammar.peggy` does, Kibana's
literal rules (an unquoted literal ends at an unescaped `not` and whitespace), Lucene syntax that
KQL reads as plain text, ECS checks, highlighting, hover and completion. `kuery` is Elastic's KQL;
Kusto is `opentide-kql`.

## Place

foundation, tier 2: depends on opentide-core, -ecs, -parse, -highlight, and -syntax (only for the
Lucene cross-check of `kuery_looks_like_lucene`). Used by opentide-tide and -analysis.

EXPERIMENT (exp/pure-rust-parser-kuery, never merged): the parser is pure Rust: `src/syntax.rs`
(kinds, logos lexer), `src/parser.rs` (grammar functions over opentide-parse), a rowan tree;
highlighting maps kinds to HighlightSpec captures in `capture()`. `tests/differential.rs` holds
it to the tree-sitter implementation, kept verbatim in `tests/legacy/`.

## Invariants

- I/O-free: no `std::fs` in `src/`; the catalogs are compiled in (`include_str!`) and parsed once (`OnceLock`).
- Kibana KQL findings are `opentide_core::Diagnostic`s with codes from `opentide_core::codes`; no error enum of its own.
- Never confuse `kuery` with Microsoft KQL (`kql`): different crates, catalogs and codes.

## Test

```bash
cargo nextest run --profile fast -p opentide-kuery
```

`tests/kibana_oracle.rs` holds recorded Kibana verdicts; `tests/opensearch_dashboards_cases.rs`
ports OpenSearch Dashboards' cases.

## Do not

- Share a parser or a code with `opentide-kql`.

## Work items that change this crate

- UC-2.5 (#820): query analysis wired through `opentide-workspace`.

## Every engine crate

- Lints, tests, snapshots and the layer rule: [`crates/AGENTS.md`](../AGENTS.md); the Rust
  conventions (errors, `OnceLock` catalogs, dependencies): the
  [rust-engine](../../.agents/skills/rust-engine/SKILL.md) skill.
- Items of the plan (`docs/internal/unified-core.md`, §6) that reach every engine crate: UC-0.3
  (#801) one CI with nextest; UC-X.1 (#843) unsafe policy, cargo-deny and fuzzing in CI; UC-X.2
  (#844) coverage gates per crate; UC-5.5 (#840) the lockstep release train.
