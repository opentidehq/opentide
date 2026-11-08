# opentide-esql — agent guide

The ES|QL engine for Elastic Security `esql` rules: parse, Elastic's generated function and
command catalog (`data/catalogs/esql/`, `scripts/engine/sync_esql_catalog.py`), stack-version
checks (`analyze_for` with a `StackTarget`), output columns, indices and ECS checks,
highlighting, hover, completion and signature help.

## Place

foundation, tier 3: depends on opentide-core, -ecs, -lucene, -syntax, -highlight. Used by opentide-tide and -analysis.

## Invariants

- I/O-free: no `std::fs` in `src/`; the catalogs are compiled in (`include_str!`) and parsed once (`OnceLock`).
- ES|QL findings are `opentide_core::Diagnostic`s with codes from `opentide_core::codes`; no error enum of its own.
- A name the catalog does not know is a diagnostic, not a parse error (Kibana drops an unknown command and runs the rest).
- `analyze` checks every stack elastic-1.0 supports; a target narrows it to one.

## Test

```bash
cargo nextest run --profile fast -p opentide-esql
```

The engine's ES|QL corpus tests are in `opentide-analysis` (`elastic_corpus`, `external_elastic`,
`live_elasticsearch_probes`).

## Do not

- Turn an unknown function or command into a parse error.

## Work items that change this crate

- UC-2.5 (#820): query analysis wired through `opentide-workspace`.

## Every engine crate

- Lints, tests, snapshots and the layer rule: [`crates/AGENTS.md`](../AGENTS.md); the Rust
  conventions (errors, `OnceLock` catalogs, dependencies): the
  [rust-engine](../../.agents/skills/rust-engine/SKILL.md) skill.
- Items of the plan (`docs/internal/unified-core.md`, §6) that reach every engine crate: UC-0.3
  (#801) one CI with nextest; UC-X.1 (#843) unsafe policy, cargo-deny and fuzzing in CI; UC-X.2
  (#844) coverage gates per crate; UC-5.5 (#840) the lockstep release train.
