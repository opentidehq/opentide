# opentide-eql — agent guide

The EQL engine for Elastic Security `eql` rules: parse, the checks Elasticsearch's EQL builder
makes after the grammar (`LogicalPlanBuilder.java`: `maxspan` units, `runs`, sequence and
sample sizes, pipes, Endgame syntax), the Verifier's literal type checks (`semantics`), the
function catalog (`data/catalogs/eql/`, `scripts/engine/sync_eql_catalog.py`), highlighting,
hover, completion and signature help.

## Place

foundation, tier 3: depends on opentide-core, -ecs, -lucene, -syntax, -highlight. Used by opentide-tide and -analysis.

## Invariants

- I/O-free: no `std::fs` in `src/`; the catalogs are compiled in (`include_str!`) and parsed once (`OnceLock`).
- EQL findings are `opentide_core::Diagnostic`s with codes from `opentide_core::codes`; no error enum of its own.
- `lexical` follows Elasticsearch's lexer where the grammar cannot (nested block comments, the expression-depth pre-scan).

## Test

```bash
cargo nextest run --profile fast -p opentide-eql
```

The engine's EQL corpus tests are in `opentide-analysis` (`elastic_corpus`, `external_elastic`).

## Do not

- Accept syntax Elasticsearch's builder rejects.

## Work items that change this crate

- UC-2.5 (#820): query analysis wired through `opentide-workspace`.

## Every engine crate

- Lints, tests, snapshots and the layer rule: [`crates/AGENTS.md`](../AGENTS.md); the Rust
  conventions (errors, `OnceLock` catalogs, dependencies): the
  [rust-engine](../../.agents/skills/rust-engine/SKILL.md) skill.
- Items of the plan (`docs/internal/unified-core.md`, §6) that reach every engine crate: UC-0.3
  (#801) one CI with nextest; UC-X.1 (#843) unsafe policy, cargo-deny and fuzzing in CI; UC-X.2
  (#844) coverage gates per crate; UC-5.5 (#840) the lockstep release train.
