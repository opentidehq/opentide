# opentide-wasm — agent guide

The wasm32-unknown-unknown build for browsers (wasm-bindgen): `highlight()`, `legend()`,
`version()` and the language server itself (`LanguageServer`, over opentide-lsp's
`MessageSession`) for a browser worker. Not published as a crate (`publish = false`): it ships as
the `opentide-wasm-web` zip on each GitHub Release.

## Place

bindings: depends on the facade, `opentide` (`analysis` and `lsp`). Nothing depends on it. It
inherits the workspace's lints, `unsafe_code = "forbid"` included.

## Invariants

- Never mix WASI into this artifact: it imports nothing but wasm-bindgen's glue (`build-wasm.sh` checks). The engine is pure Rust, so no C toolchain or libc is linked.
- No logic here: each export wraps one engine call.
- The host is JavaScript: no files, no clock (parse timeouts never fire).

## Test

```bash
cargo nextest run --profile fast -p opentide-wasm        # native unit tests
bash scripts/engine/build-wasm.sh browser                # the real artifact (no C toolchain)
bash scripts/engine/build-wasm.sh clippy                 # clippy for wasm32 (and wasip1 lsp)
```

Code under `cfg(target_arch = "wasm32")` is linted only by clippy for that target: `build-wasm.sh
clippy` runs it (and the wasip1 language server and command line; wasi-sdk only for the command
line's `ring`). CI's `engine-lint` job runs it, and the `wasm` job builds the artifact with
`-Dwarnings` and smoke-tests it in Node.

## Do not

- Add `unsafe` (the workspace forbids it), a C dependency, or a WASI import.

## Work items that change this crate

- UC-5.3 (#838): `@opentide/wasm`; the crate becomes `bindings/wasm` over the facade (D-5, UC-5.1 #836).

## Every engine crate

- Lints, tests, snapshots and the layer rule: [`crates/AGENTS.md`](../AGENTS.md); the Rust
  conventions (errors, `OnceLock` catalogs, dependencies): the
  [rust-engine](../../.agents/skills/rust-engine/SKILL.md) skill.
- Items of the plan (`docs/internal/unified-core.md`, §6) that reach every engine crate: UC-0.3
  (#801) one CI with nextest; UC-X.1 (#843) unsafe policy, cargo-deny and fuzzing in CI; UC-X.2
  (#844) coverage gates per crate; UC-5.5 (#840) the lockstep release train.
