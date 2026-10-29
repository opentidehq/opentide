---
name: wasm-hosts
description: Build opentide highlight hosts. Covers wasm32-unknown-unknown with wasm-bindgen 0.2 (never mixed with WASI), a separate wasm32-wasip1 artifact, and createOpentideClient. Use when editing crates/opentide-wasm, packages/lsp-client, or packages/lsp-worker.
license: EUPL-1.2
metadata:
  author: opentidehq
---

# WASM and language hosts

Three hosts share the engine. They do not share one binary.

| Host | Target | Entry |
| --- | --- | --- |
| Native CLI / stdio | host triple | `opentide-lsp` |
| Browser worker (Monaco) | `wasm32-unknown-unknown` | `opentide-wasm` `highlight` and `legend` |
| vscode.dev | `wasm32-wasip1` | the same CLI binary, built for WASI, **without** wasm-bindgen |

`wasm-bindgen` 0.2 imports `__wbindgen_placeholder__` symbols that only a JS glue file provides. WASI runtimes (wasmtime) do not define them. Putting `#[wasm_bindgen]` in a crate that is also linked into the WASI artifact makes instantiation fail with an unknown import. The split in this repo is the crate boundary: `opentide-wasm` depends on `wasm-bindgen` and `js-sys`; `opentide-lsp` does not.

Guide: <https://wasm-bindgen.github.io/wasm-bindgen/reference/rust-targets.html>. wasm-bindgen targets `wasm32-unknown-unknown`. It does not support `wasm32-unknown-emscripten`.

## opentide-wasm

`crates/opentide-wasm` is `crate-type = ["cdylib", "rlib"]`. Exports:

- `legend() -> js_sys::Array` of capture names from `HighlightSpec::load`
- `highlight(language_id: &str, bytes: &[u8]) -> Result<JsValue, JsValue>`

The body calls `opentide_analysis::highlight` and serializes with `serde_json`, then `js_sys::JSON.parse`. That avoids a `serde-wasm-bindgen` dependency and keeps the JSON shape identical to the CLI. Do not return a hand-built `JsValue` object with different field names (`languageId` vs `language_id`).

Unknown language ids become `Err(JsValue)`. Invalid UTF-8 becomes `Err`. Do not `unwrap` user bytes.

`std::fs` is not available on `wasm32-unknown-unknown` (it returns an error). The wasm crate must not grow a filesystem API. Workspace text stays in the host.

Native tests in this crate call `opentide_analysis::highlight` directly. They do not need a browser. `cargo test -p opentide-wasm` runs on the host. Do not add `wasm-bindgen-test` unless a browser harness exists.

Build both artifacts with `scripts/build-wasm.sh` (CI job `wasm`, and the release). tree-sitter, the grammars, and the ES|QL comment scanner are C, so a plain `cargo build --target wasm32-unknown-unknown` fails on missing libc headers. The script pins wasi-sdk, compiles the C with its clang and wasi-libc headers, links wasi-libc's `libc.a`, and smoke-tests each artifact (`scripts/wasm-smoke.mjs`):

- browser: the module imports nothing but wasm-bindgen glue, and `highlight()` works for every language through `wasm-bindgen --target nodejs`;
- wasi: the CLI runs `analyze` under `node:wasi`.

libc's stdio and clock code can reach seven WASI syscalls. `crates/opentide-wasm/src/libc_syscalls.rs` defines their import symbols inside the module (no files, clock 0), so the browser artifact still has no WASI imports. That is libc for the C parsers, not a WASI mix-in: the rule below stands.

```bash
bash scripts/build-wasm.sh            # both; needs node, and wasm-bindgen-cli 0.2.128 for the highlight() check
bash scripts/build-wasm.sh browser
```

Do not `cargo build -p opentide-wasm --target wasm32-wasip1`. That target must not link this crate.

## WASI

`wasm32-wasip1` (the renamed `wasm32-wasi`) is for vscode.dev running the CLI-style binary. Build `opentide-lsp`, not `opentide-wasm` (`scripts/build-wasm.sh wasi`). Do not cfg-gate `#[wasm_bindgen]` into the lsp crate "so one artifact does both". Two artifacts.

## TypeScript client

`packages/lsp-client` exports `createOpentideClient`. There is no `createOtideClient` except the throwing stub `scripts/check-names.sh` allows. Transports are `"stdio" | "worker" | "wasi"`.

- `stdio` starts `opentide-lsp --stdio` once and calls `opentide/analyze` and `opentide/highlight` over JSON-RPC. `dispose()` sends `shutdown` and `exit`.
- `worker` calls the `module` option: `opentide-wasm`'s `highlight(languageId, Uint8Array)` and `legend()`, loaded with `loadHighlightModule` from `@opentide/lsp-worker`. `analyze` rejects: the browser module has no analyzer.
- `wasi` runs the `wasm32-wasip1` CLI (`wasi` option) under `node:wasi`, one `analyze` or `highlight` per call. vscode.dev hosts it with its own WASI runtime.

A transport that cannot answer (no artifact, a failed spawn, an unknown language id) rejects. It never returns `tokens: []` or `diagnostics: []` in place of a result: that is fake validation. `legend()` comes from the engine, never a copy, so it cannot drift from `highlights/generated/legend.json`.

The host tests run against built artifacts named by environment variables: `OPENTIDE_LSP_BIN` (default `target/debug/opentide-lsp` when it exists), `OPENTIDE_WASI_BIN` and `OPENTIDE_WASM_GLUE` (`wasm-bindgen --target nodejs` output). CI sets each one in the job that builds it; a test whose artifact is absent is skipped.

`packages/lsp-worker` is the worker wrapper. Its package description says not to mix WASI. Keep that true.

Node tests use the built-in runner, not Jest:

```bash
node --experimental-strip-types --test packages/lsp-client/src/index.test.ts
```

The client is TypeScript ESM (`"type": "module"`). Do not add a compile step or a bundler config to this repo for a one-line change.

## Packaging

This repository publishes no Python package. The Python bindings and the `opentide` command that wraps the server live in `opentidehq/opentide`. Do not add `pyproject.toml`, maturin, or PyO3 here.

The native binary ships on crates.io (`cargo install opentide-lsp`) and as per-target binaries on each GitHub Release. CI job `package` runs `scripts/release.py vendor` and `cargo package --workspace`, which builds every crate from its packaged sources. A crate that reads a file outside `OPENTIDE_ASSETS` fails that job.

Cutting a release, and the opentide pin PR that finishes one, is `skills/release/SKILL.md`.

## Names

Package names: `@opentide/lsp-client`, `@opentide/lsp-worker`. Rust crate: `opentide-wasm`. Never `otide`.
