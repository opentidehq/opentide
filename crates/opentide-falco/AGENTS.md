# opentide-falco — agent guide

The Falco rule condition engine (Sysdig Secure, `configurations.sysdig`): a step-for-step port of
libsinsp's filter parser (`parser`), libsinsp's compile checks (`compile`), Falco's rule-loader
checks (lists, macros, tunings, deprecated fields), output templates, highlighting, hover and
completion. Catalogs: `data/catalogs/falco/` (`scripts/engine/sync_falco_catalog.py`). Design:
`docs/engine/FALCO.md`.

## Place

foundation, tier 2: depends on opentide-core, -syntax, -highlight. Used by opentide-tide and -analysis.

## Invariants

- I/O-free: no `std::fs` in `src/`; the catalogs are compiled in (`include_str!`) and parsed once (`OnceLock`).
- Falco findings are `opentide_core::Diagnostic`s with codes from `opentide_core::codes`; no error enum of its own.
- `parser` follows libsinsp's `parser.cpp` step for step, error messages included; libs' own parser and compiler tests (`crates/testdata/conformance/libsinsp/`) all agree.
- What depends on the agent is a warning; what Falco refuses to load is an error.

## Test

```bash
cargo nextest run --profile fast -p opentide-falco
```

`tests/libsinsp_parser.rs`, `tests/libsinsp_compiler.rs` (libs' tests) and
`tests/tree_sitter_agreement.rs` (inputs libsinsp accepts highlight without an error node); the Falco
oracle runs through `scripts/engine/ci-oracle.sh`.

## Do not

- Reshape the parser for style: it mirrors libsinsp so that a diff against upstream stays readable.

## Work items that change this crate

- UC-2.5 (#820): query analysis wired through `opentide-workspace`.
- UC-4.2 (#832): the Sysdig connector deploys what this crate checks.

## Every engine crate

- Lints, tests, snapshots and the layer rule: [`crates/AGENTS.md`](../AGENTS.md); the Rust
  conventions (errors, `OnceLock` catalogs, dependencies): the
  [rust-engine](../../.agents/skills/rust-engine/SKILL.md) skill.
- Items of the plan (`docs/internal/unified-core.md`, §6) that reach every engine crate: UC-0.3
  (#801) one CI with nextest; UC-X.1 (#843) unsafe policy, cargo-deny and fuzzing in CI; UC-X.2
  (#844) coverage gates per crate; UC-5.5 (#840) the lockstep release train.
