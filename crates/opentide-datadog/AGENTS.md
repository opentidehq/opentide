# opentide-datadog — agent guide

The Datadog log search syntax engine (`datadog`): the queries of Datadog Cloud SIEM detection
rules (the API's `event_query`) and `.datadog` files. The contract is
[`docs/internal/rfc-datadog-cloud-siem.md`](../../docs/internal/rfc-datadog-cloud-siem.md), §6;
the reference and the conformance results are [`docs/engine/DATADOG.md`](../../docs/engine/DATADOG.md).

| File | What |
|------|------|
| `src/lexer.rs` | The logos lexer: small pieces (words, escapes, phrases, punctuation) that the parser glues where they touch. Words, escapes and phrases are scanned by callbacks, never by a repeated regex class (the 1 MB stack) |
| `src/parser.rs` | The grammar on `opentide-parse`: modifiers bind tightest, then AND (written or implied), then OR, the same inside a value group. Runs of AND and of OR are one flat node; only a group is a level of `MAX_DEPTH` (1,000) |
| `src/datadog.ungram`, `src/generated/ast.rs` | The tree's shape, and the typed AST `cargo xtask codegen` writes from it |
| `src/check.rs` | The checks of RFC §6.7 and the highlight of §6.8 in one walk (`walk`, ADR 0014 §5a) |
| `src/catalog.rs` | The reserved and standard attributes (`data/catalogs/datadog/`, `scripts/engine/sync_datadog_catalog.py`), for hover and completion |
| `src/assist.rs` | Hover and completion |

## Place

foundation, tier 2: depends on opentide-core, -dataset, -parse, -highlight. Used by
opentide-tide and -analysis.

## Invariants

- I/O-free: no `std::fs` in `src/`; the catalogue is pre-parsed by `build.rs` (#1743).
- Findings are `datadog_*` codes from `opentide_core::codes`, with the RFC's severities. A query
  that does not parse gets its first syntax error only (`datadog_range` inside a range,
  `datadog_parse_error` elsewhere): advice on a tree recovery rebuilt is noise.
- Profiles: `rule` (a detection rule's query: `*:term` and `#name` are warnings) and `search`
  (a `.datadog` file, a hunt, `opentide query`). A raw file is `search`.
- The precedence (AND tighter than OR) is VRL's, unverified on Cloud SIEM (RFC open question 2):
  `datadog_mixed_boolean` says so in its message, and stays a warning.
- An attribute the catalogue lacks is never a finding: pipelines remap attributes (RFC §14).
  `datadog_unknown_attribute` is a hint on a dotted bare key only.
- No platform embeds the language yet: the `datadog` platform row is phase 2 of the RFC.
  `xtask/tests/language_wiring.rs` lists it in `AWAITING_A_PLATFORM` until then.

## Test

```bash
cargo nextest run --profile fast -p opentide-datadog
cargo test -p opentide-analysis --test corpus_gate --test parser_baseline --test deep_queries
```

`src/tests.rs` (the grammar, every code with its RFC example, the single walk's visit count),
`tests/published.rs` (Datadog's 2,895 published queries: no error but `EXCEPTIONS.toml`'s, the
count of each code pinned), `tests/parser_depth.rs` (a million characters of every token class
on a 1 MB stack), `tests/long_runs.rs` (growth, never absolute time), `tests/trees.rs` and
`tests/ast_conformance.rs`. The VRL oracle is `scripts/engine/oracles/datadog/`.

## Do not

- Hand-edit `data/catalogs/datadog/` or `src/generated/ast.rs`: regenerate them.
- Copy Datadog's documentation text into the catalogue: it holds facts only (`NOTICE`).
- Vendor VRL's grammar: the oracle fetches it at a pinned commit, and nothing VRL-derived ships.

## Every engine crate

- Lints, tests, snapshots and the layer rule: [`crates/AGENTS.md`](../AGENTS.md); the Rust
  conventions (errors, `OnceLock` catalogs, dependencies): the
  [rust-engine](../../.agents/skills/rust-engine/SKILL.md) skill.
