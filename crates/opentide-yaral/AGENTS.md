# opentide-yaral — agent guide

The YARA-L 2.0 engine (Google Security Operations: `configurations.google_secops`, hunts with
`system: google_secops`, `.yaral` and `.yl2` files). Google publishes no grammar and no offline
compiler, so the engine approximates the tenant's compiler (`verifyRuleText`): it reports what
Google's pages say the compiler refuses and never claims a compile. A text goes through the
pure-Rust parser (`lexer`, `parser/`, `yaral.ungram`, on opentide-parse: a lossless rowan tree,
ADR 0012) and `analysis::checker::Checker` on the typed tree. Two profiles: a rule and a search
(a hunt). Catalogs (UDM, functions): `data/catalogs/yaral/` (`scripts/engine/sync_yaral_catalogs.py`).
Design, and each code with Google's page and its test: `docs/engine/YARAL.md`.

## Place

foundation, tier 2: depends on opentide-core, -dataset, -highlight and -parse; on no other query
engine (`xtask/layers.toml`). Used by opentide-tide and -analysis.

## Invariants

- I/O-free: no `std::fs` in `src/`; the catalogs are embedded (`opentide_dataset::text!`) and
  parsed once.
- An offline result is never reported as a tenant check: the live check is
  `opentide validate query --live` (`verifyRuleText`).
- Reference lists, data tables, composite producer names and curated rules live in the tenant: they
  are never reported unknown.
- Keywords are case-insensitive and reserved: a keyword is never a name.
- The typed AST (`src/generated/ast.rs`) is written by `cargo xtask codegen` from `yaral.ungram`:
  never edit it by hand. The kinds and the typed AST are public but hidden, for the crate's tests;
  they are no API.

## Test

```bash
cargo nextest run --profile fast -p opentide-yaral
```

`tests/parser_corpus.rs`, `tests/trees.rs` (snapshots), `tests/parser_mutations.rs` and
`tests/parser_verdicts.rs` (the verdicts of the tree-sitter grammar the parser replaced) hold the
parser; `tests/codes.rs` the checker; `tests/google_examples.rs` Google's own examples
(`crates/testdata/conformance/google-yaral/`, each with its codes); `tests/external_corpus.rs`
chronicle/detection-rules' community rules (left out of the fast profile); `tests/long_runs.rs` the
depth and length guards.

## Do not

- Claim a compile, or name a check the tenant did not run, from an offline result.
- Share code, catalogue or grammar with `opentide-yara`: YARA shares only the name.

## Every engine crate

- Lints, tests, snapshots and the layer rule: [`crates/AGENTS.md`](../AGENTS.md); the Rust
  conventions (errors, `OnceLock` catalogs, dependencies): the
  [rust-engine](../../.agents/skills/rust-engine/SKILL.md) skill; the parser on opentide-parse: the
  [parser](../../.agents/skills/parser/SKILL.md) skill.
