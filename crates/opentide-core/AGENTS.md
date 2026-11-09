# opentide-core — agent guide

Shared, I/O-free types every engine crate uses: `LanguageId`, positions, ranges and spans
(`ByteSpan`, `Range`, `position_to_offset`, `span_to_range`), `Diagnostic`, `Severity`,
`CompletionItem`, the diagnostic codes (`codes`), and the declared datasets of a workspace's
`visibility.toml` (`datasets`).

## Place

foundation, tier 0 (`xtask/layers.toml`): it depends on no workspace crate, and every other
crate depends on it.

## Invariants

- No `std::fs` in `src/` (`scripts/engine/check-io-free.sh`).
- LSP `character` counts UTF-16 code units. Ranges sent to a client go through `span_to_range` / `offset_to_position`; inbound positions through `position_to_offset`, which returns a char boundary. Do not add another converter.
- A diagnostic code is a constant in `codes`, listed in `codes::ALL`, with a sentence in `codes::describe` and a section in `docs/cli/diagnostics.md` (`tests/diagnostics_docs.rs`). Never a second string at the call site.
- `LanguageId` changes `as_str`, `parse` and `Display` together; a new language follows the add-language skill.
- Codes, severities, field paths and position rules are invariant 3 of the plan: a change is a recorded decision, not a refactor.

## Test

```bash
cargo nextest run --profile fast -p opentide-core
```

`tests/diagnostics_docs.rs` reads `docs/cli/diagnostics.md` (`OPENTIDE_DIAGNOSTICS_DOCS` names
another copy). CI's Windows job runs this crate's tests too.

## Do not

- Rename or remove a code, or change its severity, to make a test pass.
- Add a dependency on another workspace crate: core is the bottom of the graph.

## Work items that change this crate

- UC-2.2 (#817): validation and the one diagnostic model the CLI and the editor share.
- UC-1.1 (#807) and UC-1.2 (#808): `opentide-schema` builds on these types.

## Every engine crate

- Lints, tests, snapshots and the layer rule: [`crates/AGENTS.md`](../AGENTS.md); the Rust
  conventions (errors, `OnceLock` catalogs, dependencies): the
  [rust-engine](../../.agents/skills/rust-engine/SKILL.md) skill.
- Items of the plan (`docs/internal/unified-core.md`, §6) that reach every engine crate: UC-0.3
  (#801) one CI with nextest; UC-X.1 (#843) unsafe policy, cargo-deny and fuzzing in CI; UC-X.2
  (#844) coverage gates per crate; UC-5.5 (#840) the lockstep release train.
