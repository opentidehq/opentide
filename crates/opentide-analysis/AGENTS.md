# opentide-analysis — agent guide

The engine's public entry point: an I/O-free orchestrator behind `WorkspaceHost`
(`MemoryWorkspace` in tests) with `analyze`, `analyze_blocks`, `analyze_query`,
`index_workspace`, `highlight`,
`semantic_tokens`, `hover`, `completions`, the catalogs a host installs, and the placement of the
host's configuration findings (`config`). The types its functions use are re-exported, so a host
needs no other engine crate. The language server, the browser build and the Python binding
depend on it.

## Place

domain, tier 1: depends on opentide-core, -highlight, -ecs, -tide and every query engine. Used
by opentide-lsp, opentide-wasm and opentide-native. The plan folds it into `opentide-workspace`.

## Invariants

- No `std::fs` in `src/`: the filesystem is the host's, behind `WorkspaceHost`.
- Configuration TOML is checked by the host, never here: the engine only places the host checker's findings.
- `analyze` of a Tide object is what an editor publishes beside `opentide validate`'s findings:
  the queries, the highlighting and the symbols, and no other object of the workspace is read
  for it. A platform block's own findings are `analyze_blocks`, which `opentide lint` reads
  (UC-2.6, #821): never fold them back into `analyze`, or the editor shows a fault twice.
- The README's example is a doctest (`ReadmeDoctests`): keep it compiling.

## Test

```bash
cargo nextest run --profile fast -p opentide-analysis
cargo nextest run --profile ci -p opentide-analysis      # adds the corpora and tide_corpus
cargo test -p opentide-analysis --doc
cargo bench -p opentide-analysis --bench analyze         # informational
```

`tests/tide_corpus.rs` runs this checkout's Pydantic models through `.venv` (`uv sync --group
dev`, or `OPENTIDE_PYTHON`). `tests/snapshots.rs` holds insta snapshots (`tests/snapshots/`).
`tests/elastic_detection_rules.rs` is an opt-in sweep (`OPENTIDE_DETECTION_RULES`).

## Do not

- Read a file or an environment variable in `src/`.
- Edit a snapshot or a golden by hand: rerun with `INSTA_UPDATE=always` or `UPDATE_GOLDENS=1` and review the diff.

## Work items that change this crate

- UC-2.1 (#816), UC-2.5 (#820), UC-2.6 (#821): the workspace, query analysis and the server move to `opentide-workspace`.
- UC-0.8 (#806): benchmarks with budgets (`benches/analyze.rs`).
- UC-5.1 (#836): the facade re-exports what hosts use instead of this crate.

## Every engine crate

- Lints, tests, snapshots and the layer rule: [`crates/AGENTS.md`](../AGENTS.md); the Rust
  conventions (errors, `OnceLock` catalogs, dependencies): the
  [rust-engine](../../.agents/skills/rust-engine/SKILL.md) skill.
- Items of the plan (`docs/internal/unified-core.md`, §6) that reach every engine crate: UC-0.3
  (#801) one CI with nextest; UC-X.1 (#843) unsafe policy, cargo-deny and fuzzing in CI; UC-X.2
  (#844) coverage gates per crate; UC-5.5 (#840) the lockstep release train.
