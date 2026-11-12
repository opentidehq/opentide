# opentide-core — agent guide

Shared, I/O-free types every engine crate uses: `LanguageId`, positions, ranges and spans
(`ByteSpan`, `Range`, `position_to_offset`, `span_to_range`), `Diagnostic`, `Severity`,
`CompletionItem`, the diagnostic codes (`codes`), the declared datasets of a workspace's
`visibility.toml` (`datasets`), the Elastic duration grammar (`duration`) and Falco's terms for the
Sysdig block's constraints (`falco`: operators, modifiers, priorities, keywords, the name rule,
Python's `strip()`), each the one copy opentide-schema's model and opentide-tide's findings share,
the one "did you mean" rule every caller shares (`suggest`:
the same word without case or `-`/`_` wins, otherwise the fewest edits, strsim's OSA distance),
and the YAML node tree (`node`: saphyr-parser's events, saphyr's YAML 1.2 core-schema scalars,
every node's position), the one YAML reader of the workspace: `validate`, the models
(`opentide_schema::node` re-exports it) and opentide-tide read YAML with it (#850).

## Place

foundation, tier 0 (`xtask/layers.toml`): it depends on no workspace crate, and every other
crate depends on it.

## Invariants

- No `std::fs` in `src/` (`scripts/engine/check-io-free.sh`).
- LSP `character` counts UTF-16 code units. Ranges sent to a client go through `span_to_range` / `offset_to_position`; inbound positions through `position_to_offset`, which returns a char boundary. Do not add another converter.
- A diagnostic code is a constant in `codes`, listed in `codes::ALL`, with a sentence in `codes::describe` and a section in `docs/cli/diagnostics.md` (`tests/diagnostics_docs.rs`). Never a second string at the call site.
- `LanguageId` changes `as_str`, `parse` and `Display` together; a new language follows the add-language skill.
- Suggestions go through `suggest` (vocabulary values, configuration choices, CLI commands and
  options, every engine crate's "did you mean"), never a second similarity rule. It uses strsim;
  never port a Python library instead. A check that reports only near misses (whether it reports
  at all, or at which severity, is invariant 3) may keep its own threshold, measured with strsim,
  and picks among the names within it with `suggest::best`.
- `duration` and `falco` are the one copy of the rules both Sysdig and Elastic engines judge by
  (opentide-schema's `elastic_rule_shape` and `sysdig_rule_shape`, opentide-tide's `elastic` and
  `sysdig`); never a second table in either crate. `xtask/tests/sysdig_engines.rs` runs both
  Sysdig engines on the model's oracle cases.
- YAML is read with `node` only: never `serde_yaml`, `serde_yml` or a second parser (#850).
  What it reads differently from the oracle is `crates/opentide-schema/YAML.md`.
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
