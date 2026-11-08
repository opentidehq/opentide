# opentide-kql — agent guide

The Microsoft Kusto (KQL) engine for Sentinel and Defender rules: parse, HIR, the operator,
function and table catalogs (`data/catalogs/kql/`, Azure Monitor and ASIM tables), profiles
(core, Sentinel, Defender), diagnostics, highlighting, hover and completion. `kql` is Kusto;
Kibana's KQL is `opentide-kuery`.

## Place

foundation, tier 2: depends on opentide-core, -syntax, -highlight. Used by opentide-tide, -analysis and -lsp.

## Invariants

- I/O-free: no `std::fs` in `src/`; the catalogs are compiled in (`include_str!`) and parsed once (`OnceLock`).
- KQL findings are `opentide_core::Diagnostic`s with codes from `opentide_core::codes`; no error enum of its own.
- Control commands (`.show`, `.create`) parse, so that the engine can report `kql_control_command_unsupported`.
- `position_to_offset` here is a thin wrapper over opentide-core's (#178): never index the source with an LSP `character`.

## Test

```bash
cargo nextest run --profile fast -p opentide-kql
```

`tests/oracle_probes.rs` holds the recorded verdicts of Microsoft's own KQL parser;
`scripts/engine/ci-oracle.sh` re-runs that oracle where its reference is installed. The crate's
package is licence-scanned for oracle names (`scripts/engine/license-scan.sh`): never name the
oracle's library in a file the crate ships. Catalog syncs:
`scripts/engine/sync_kql_learn_signatures.py`, `sync_azure_monitor_tables.py`,
`sync_asim_schemas.py`.

## Do not

- Hand-edit a generated catalog file under `data/catalogs/kql/`: rerun its sync script.

## Work items that change this crate

- UC-2.5 (#820): query analysis wired through `opentide-workspace`; `validate query` offline.
- UC-0.3 (#801): the KQL oracle in one CI.

## Every engine crate

- Lints, tests, snapshots and the layer rule: [`crates/AGENTS.md`](../AGENTS.md); the Rust
  conventions (errors, `OnceLock` catalogs, dependencies): the
  [rust-engine](../../.agents/skills/rust-engine/SKILL.md) skill.
- Items of the plan (`docs/internal/unified-core.md`, §6) that reach every engine crate: UC-0.3
  (#801) one CI with nextest; UC-X.1 (#843) unsafe policy, cargo-deny and fuzzing in CI; UC-X.2
  (#844) coverage gates per crate; UC-5.5 (#840) the lockstep release train.
