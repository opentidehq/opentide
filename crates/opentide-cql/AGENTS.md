# opentide-cql — agent guide

The CrowdStrike Query Language (CQL) engine of Falcon LogScale and Falcon Next-Gen SIEM
(`configurations.crowdstrike.query`, hunts with `system: crowdstrike`, `.cql` files): the
tree-sitter grammar (`grammars/tree-sitter-opentide-cql`, with an external scanner) is the parser,
`check` runs CrowdStrike's compile-time rules on the tree, and `assist` gives hover, completion and
signature help. Catalogs: `data/catalogs/cql/` (`scripts/engine/sync_cql_catalog.py`). Design:
`docs/engine/CQL.md`.

## Place

foundation, tier 2: depends on opentide-core, -syntax, -highlight. Used by opentide-tide and -analysis.

## Invariants

- I/O-free: no `std::fs` in `src/`; the catalogs are compiled in (`include_str!`) and parsed once (`OnceLock`).
- CQL findings are `opentide_core::Diagnostic`s with `cql_*` codes from `opentide_core::codes`; no error enum of its own.
- Errors are what LogScale refuses to compile; a field, saved search, lookup file or repository is never reported unknown: they live in the tenant.
- A correlation rule (`Context::CORRELATION_RULE`) adds `cql_correlate_aggregate`; a hunt or a `.cql` file does not.
- CrowdStrike is in `OFFLINE_QUERY_LANGUAGES` (`src/opentide/validation/query_platforms.py`), so `opentide validate`, `opentide validate query --platform crowdstrike`, `opentide lint` and MCP `validate_query` report the `cql_*` codes offline, as the editor and `opentide tui` do. `--live` stays `supported: false` for CrowdStrike: there is no live validation.

## Test

```bash
cargo nextest run --profile fast -p opentide-cql
cargo nextest run -p opentide-analysis --test external_cql
```

`src/tests.rs` (the checks), `crates/opentide-syntax/tests/corpus_gate.rs` (one valid and one invalid
fixture per production in `crates/testdata/corpus/cql/`) and `crates/opentide-analysis/tests/external_cql.rs`
(CrowdStrike's public queries, each clean, and a twin with one injected fault). No oracle runs in CI:
CQL is closed source (`scripts/engine/oracles/README.md`).

## Do not

- Hand-edit `data/catalogs/cql/`: regenerate it with the sync script, which refuses a function without a summary written for this repository.
- Copy CrowdStrike's documentation text: the catalogs hold facts only (`NOTICE`).

## Every engine crate

- Lints, tests, snapshots and the layer rule: [`crates/AGENTS.md`](../AGENTS.md); the Rust
  conventions (errors, `OnceLock` catalogs, dependencies): the
  [rust-engine](../../.agents/skills/rust-engine/SKILL.md) skill.
- Items of the plan (`docs/internal/unified-core.md`, §6) that reach every engine crate: UC-0.3
  (#801) one CI with nextest; UC-X.1 (#843) unsafe policy, cargo-deny and fuzzing in CI; UC-X.2
  (#844) coverage gates per crate; UC-5.5 (#840) the lockstep release train.
