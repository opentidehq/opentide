# opentide-lsp — agent guide

The opentide language server, as a library (`run_stdio`, `serve`, `MessageSession` for a host
without stdio) and as the `opentide-lsp` binary: the stdio (and TCP) LSP host on `lsp-server` 0.10
and `lsp-types` 0.97, and a CLI (`analyze`, `highlight`, `generate-highlights`) that prints plain
JSON or text. The Python package serves it as `opentide lsp start`.

## Place

application: depends on opentide-core, -analysis, -highlight, -kql, -spl, -tide, -workspace
and -schema. Used by opentide-wasm, opentide-native and xtask (`lsp parity`). `publish = false`
while opentide-workspace and opentide-schema are (ADR 0010's addendum).

## Invariants

- Synchronous, no async runtime: wasip1 and the PyO3 thread run it unchanged. Do not add tower-lsp or async-lsp.
- Only `--stdio` and `--listen` speak JSON-RPC; while serving, nothing else writes to stdout.
- Positions are UTF-16 at the protocol edge, converted once in `handlers.rs` (`offset`).
- The `opentide/*` custom requests are a cross-repository contract (plan §3, invariant 4).
- It may read files (it is the native host); the engines it calls may not.
- Tide object diagnostics are `validate`'s (`src/checks.rs`): each root's `Workspace` over the
  disk and the open buffers (`OverlayFs`), kept current with `Workspace::invalidate`; never add
  an object check here or in the engine. Configuration buffers are checked with
  `opentide_schema::configuration::checks::buffer_issues`.

## Test

```bash
cargo nextest run --profile fast -p opentide-lsp        # in-process MessageSession tests, trycmd CLI
cargo nextest run --profile ci -p opentide-lsp          # adds the stdio server tests
cargo run -p opentide-lsp -- generate-highlights --check
cargo xtask lsp parity --corpus faults                  # published diagnostics = validate's
```

`tests/cli.rs` runs `tests/cmd/*.trycmd`. `tests/e2e_stdio.rs`, `protocol.rs`, `catalog.rs` and
`lint_toml.rs` drive the binary over stdio (`tests/common/`). CI also runs this crate on Windows
and the `scripts/engine/clients` pytest-lsp and Neovim checks.

## Do not

- Write `Content-Length` frames from a CLI subcommand.
- Change a custom request's shape without the decision recorded and the clients updated.

## Work items that change this crate

- UC-2.6 (#821): the server on `opentide-workspace`, duplicate checks removed (done; lint's
  findings wait for #905).
- UC-3.6 (#828): `opentide lsp start` and `serve` in the Rust CLI.
- UC-5.3 (#838): the fate of `@opentide/lsp-client` and `@opentide/lsp-worker`.

## Every engine crate

- Lints, tests, snapshots and the layer rule: [`crates/AGENTS.md`](../AGENTS.md); the Rust
  conventions (errors, `OnceLock` catalogs, dependencies): the
  [rust-engine](../../.agents/skills/rust-engine/SKILL.md) skill.
- Items of the plan (`docs/internal/unified-core.md`, §6) that reach every engine crate: UC-0.3
  (#801) one CI with nextest; UC-X.1 (#843) unsafe policy, cargo-deny and fuzzing in CI; UC-X.2
  (#844) coverage gates per crate; UC-5.5 (#840) the lockstep release train.
