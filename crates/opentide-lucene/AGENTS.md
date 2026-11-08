# opentide-lucene — agent guide

The Lucene classic query syntax as Elasticsearch's `query_string` reads it (Elastic rules with
`language: lucene`) and as Carbon Black Cloud uses it (the Carbon Black dialect, its field
catalog in `data/catalogs/carbon_black/`), with Lucene's own regular-expression grammar for
`/regexp/` bodies (`regexp`).

## Place

foundation, tier 2: depends on opentide-core, -ecs, -syntax, -highlight. Used by opentide-esql, -eql, -tide and -analysis.

## Invariants

- I/O-free: no `std::fs` in `src/`; the catalogs are compiled in (`include_str!`) and parsed once (`OnceLock`).
- Lucene findings are `opentide_core::Diagnostic`s with codes from `opentide_core::codes`; no error enum of its own.
- Boolean operators are upper case only; clauses have no precedence; escapes drop one backslash at a time. These are Lucene's rules, checked after the grammar.
- `regexp` follows Lucene's `RegExp` and its determinization limit, not PCRE.

## Test

```bash
cargo nextest run --profile fast -p opentide-lucene
```

`tests/lucene_queryparser_cases.rs` and `tests/regexp_oracle.rs` hold Lucene's own cases and
recorded verdicts; `tests/external_carbon_black.rs` runs the converted SigmaHQ corpus;
`tests/sigma_sweep.rs` is an opt-in sweep (`OPENTIDE_SIGMA_LUCENE`).

## Do not

- Treat a lower-case `and` or `or` as an operator.

## Work items that change this crate

- UC-2.5 (#820): query analysis wired through `opentide-workspace`.

## Every engine crate

- Lints, tests, snapshots and the layer rule: [`crates/AGENTS.md`](../AGENTS.md); the Rust
  conventions (errors, `OnceLock` catalogs, dependencies): the
  [rust-engine](../../.agents/skills/rust-engine/SKILL.md) skill.
- Items of the plan (`docs/internal/unified-core.md`, §6) that reach every engine crate: UC-0.3
  (#801) one CI with nextest; UC-X.1 (#843) unsafe policy, cargo-deny and fuzzing in CI; UC-X.2
  (#844) coverage gates per crate; UC-5.5 (#840) the lockstep release train.
