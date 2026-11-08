# opentide-syntax — agent guide

The tree-sitter bindings: one grammar per query language (KQL, SPL, ES|QL, EQL, kuery, Lucene,
Falco), compiled from the vendored `grammars/*/src/parser.c` by `build.rs`, and the tree helpers
the engines share (`parse`, `first_error`, `walk_with_ancestors`, `node_span`, `query_captures`).

## Place

foundation, tier 1: depends on opentide-core. The query engines (tiers 2 and 3) depend on it.
One of the two crates allowed `unsafe`: its `[lints]` copy the workspace's with
`unsafe_code = "deny"`.

## Invariants

- The only `unsafe` is the FFI to the grammars' `tree_sitter_opentide_*()` entry points and `Language::from_raw`; each item allows it with a reason and each block has a `// SAFETY:` comment.
- No `std::fs` in `src/`. `build.rs` may read the grammars.
- `build.rs` watches each grammar's `src/`; never print `rerun-if-changed` for a path that may not exist (every crate would rebuild on every run).
- Every required named grammar rule has a production sample in `crates/testdata/corpus/<language>/` tagged `prod:<rule>` (`tests/corpus_gate.rs`).

## Test

```bash
cargo nextest run --profile fast -p opentide-syntax
bash scripts/engine/check-grammars.sh     # after a grammar edit: tree-sitter-cli 0.25.10
cargo run -p opentide-lsp -- generate-highlights --check
```

## Do not

- Hand-edit `grammars/**/src/parser.c`, `grammar.json` or `node-types.json`: regenerate them (tree-sitter skill).
- Add `unsafe` beyond the grammar FFI, or call `from_raw` with a pointer that is not a grammar's.

## Work items that change this crate

- UC-X.1 (#843): the unsafe policy and fuzzing of every parser.
- UC-0.3 (#801): the grammar regeneration check in one CI.

## Every engine crate

- Lints, tests, snapshots and the layer rule: [`crates/AGENTS.md`](../AGENTS.md); the Rust
  conventions (errors, `OnceLock` catalogs, dependencies): the
  [rust-engine](../../.agents/skills/rust-engine/SKILL.md) skill.
- Items of the plan (`docs/internal/unified-core.md`, §6) that reach every engine crate: UC-0.3
  (#801) one CI with nextest; UC-X.1 (#843) unsafe policy, cargo-deny and fuzzing in CI; UC-X.2
  (#844) coverage gates per crate; UC-5.5 (#840) the lockstep release train.
