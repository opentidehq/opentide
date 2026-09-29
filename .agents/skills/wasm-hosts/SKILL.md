---
name: wasm-hosts
description: Build OpenTide highlight hosts. Covers wasm32-unknown-unknown with wasm-bindgen 0.2 (never mixed with WASI), a separate wasm32-wasip1 artifact, maturin, and createOpentideClient. Use when editing crates/opentide-wasm, packages/lsp-client, packages/lsp-worker, or pyproject.toml.
license: EUPL-1.2
metadata:
  author: OpenTideHQ
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

Native tests in this crate call `opentide_analysis::highlight` directly. They do not need a browser. `cargo test -p opentide-wasm` runs on the host. A wasm smoke test is a separate `cargo build -p opentide-wasm --target wasm32-unknown-unknown` once the target is installed. Do not add `wasm-bindgen-test` unless a browser harness exists.

Build the browser artifact with the target explicitly:

```bash
rustup target add wasm32-unknown-unknown
cargo build -p opentide-wasm --target wasm32-unknown-unknown --release
```

Do not `cargo build -p opentide-wasm --target wasm32-wasip1`. That target must not link this crate.

## WASI

`wasm32-wasip1` (the renamed `wasm32-wasi`) is for vscode.dev running the CLI-style binary. Build `opentide-lsp`, not `opentide-wasm`. Do not cfg-gate `#[wasm_bindgen]` into the lsp crate "so one artifact does both". Two artifacts.

## TypeScript client

`packages/lsp-client` exports `createOpentideClient`. There is no `createOtideClient` except the throwing stub `scripts/check-names.sh` allows. Transports are `"stdio" | "worker" | "wasi"`.

- `stdio` spawns the native binary. `highlight` may call the CLI `highlight` subcommand (plain JSON on stdout), not a JSON-RPC frame.
- `worker` calls the wasm `highlight(languageId, Uint8Array)` when the global is present.
- `wasi` is the vscode.dev path.

`packages/lsp-worker` is the worker wrapper. Its package description says not to mix WASI. Keep that true.

Node tests use the built-in runner, not Jest:

```bash
node --experimental-strip-types --test packages/lsp-client/src/index.test.ts
```

The client is TypeScript ESM (`"type": "module"`). Do not add a compile step or a bundler config to this repo for a one-line change.

## maturin

`pyproject.toml` builds the **native** binary with maturin `>=1.7,<2`:

```toml
[tool.maturin]
manifest-path = "crates/opentide-lsp/Cargo.toml"
bindings = "bin"
```

`maturin build` produces a Python package that ships `opentide-lsp`. It is not a PyO3 extension module. Do not add `pyo3` or `bindings = "pyo3"` to make `import opentide_lsp` work; the Python extra that calls the engine lives in `OpenTideHQ/opentide` (`#16`), not here.

CI job `package` runs `pip install "maturin>=1.7,<2"` and `maturin build`. A change that breaks the lsp manifest as a bin crate fails that job.

## Names

Package names: `@opentide/lsp-client`, `@opentide/lsp-worker`. Rust crate: `opentide-wasm`. Never `otide`.
