---
title: VS Code on WASI
description: The handoff for UC-6.1 — how the VS Code extension runs opentide.wasm under @vscode/wasm-wasi with @opentide/wasi-host — the module, the launch contract, mounts, environment, the three processes and the size budget.
---

# VS Code on WASI: the handoff

The extension's move to the WASI build is paused until the release candidates
([UC-6.1](./unified-core.md), filed as
[opentidehq/vscode-extension#75](https://github.com/opentidehq/vscode-extension/issues/75)). This page is
what the extension needs to start it: what the module is, which release asset it is and how to pin
it, how to launch it, and what it does and does not do. The decision is [ADR 0007's amendment](./adr/0007-vscode-extension-stays-separate.md#amendment-2026-11-13-the-extension-is-wasi-native).

## What is done

| Unit | What | Where |
|------|------|-------|
| W1 ([#1097](https://github.com/opentidehq/opentide/pull/1097)) | The `opentide` CLI on `wasm32-wasip1`, held to the goldens under wasmtime; git read with gix (no `git` program) | `scripts/engine/build-wasm.sh cli`, ci.yml `wasm` |
| W2 ([#1103](https://github.com/opentidehq/opentide/pull/1103)) | Tenant requests made by the client: `opentide/fetch`, and its extension-host half | `docs/cli/serve.md`, `packages/wasi-host` |

## The module

- **Build:** `scripts/engine/build-wasm.sh cli` builds `opentide-cli` without default features (no
  terminal UI) in the `wasi` profile, at `target/wasm32-wasip1/wasi/opentide.wasm`. A release ships
  one module for every platform; the extension pins one release's module, so its coupling to
  opentide is one version number.
- **The release asset: `opentide-wasm32-wasip1.wasm`.** Every GitHub Release (a candidate's
  included, public or internal) carries the module under this name, which is fixed and has no
  version in it: the release it is attached to is its version, and the module reports it
  (`opentide --version` prints `opentide 1.0.0-rc.3` for that candidate: the release train builds it
  with `OPENTIDE_BUILD_VERSION`, and its smoke test runs the module under wasmtime and checks it).
  The `release.py` asset list, `SHA256SUMS` and the release's attestations cover it like every other
  asset. The first candidate to ship it is the one cut after this asset's change (`1.0.0-rc.3`);
  `1.0.0-rc.2` has `opentide-lsp-wasm32-wasip1.wasm` and the browser zip, not this module.
- **Size:** 28.2 MB, 7.5 MB at `gzip -9` (measured 2026-11-21). The build fails above 15 MiB gzipped, which is also the
  budget of the whole `.vsix` (plan §11): a `.vsix` is a zip, so the module costs about its gzipped
  size there. `OPENTIDE_WASM_OPT=1` runs `wasm-opt` too, which saves about 2% and is off by default; the release does not set it.
- **No threads, no processes, no sockets.** Work that runs in parallel natively runs in sequence;
  `doctor --offline` says git was found but its version not checked; `setup hooks` prints the
  `chmod +x` line to run, since WASI preview 1 has no file permissions; the terminal UI refuses, as
  it does without a terminal.
- **Panics abort.** A trap ends the process, not one request: the extension restarts a process that
  exits, as it would restart a crashed native one.

## Licences

The module's third-party licences are four release assets the extension ships beside it, each with the release's pin (`SHA256SUMS`): `THIRD-PARTY-LICENSES.html` (every Rust crate compiled into the module, by licence: `about.toml` names `wasm32-wasip1`, so `wasi`, which only this build links, is listed), `WASI-LIBC-LICENSES.txt` (wasi-libc, the C library the module links), `LICENSE` and `NOTICE` (the embedded data). The module is EUPL-1.2 and its package data is opentide's own ([publishing](./publishing.md#the-wasi-command-line-module) has the evidence that the file covers the module's 311 crates).

## Pinning the module

The extension pins one release's module by URL and SHA-256, as it pins `highlights-vX.Y.Z.zip` and
`opentide-wasm-web-vX.Y.Z.zip` in its `pins.json`: one version number, and the digest, say which
module it runs.

```json illustrative
{
  "wasi": {
    "version": "1.0.0-rc.3",
    "url": "https://github.com/opentidehq/opentide/releases/download/v1.0.0-rc.3/opentide-wasm32-wasip1.wasm",
    "sha256": "<the line of this file in the release's SHA256SUMS>"
  }
}
```

- **The digest** is the module's line in the release's `SHA256SUMS` (`sha256sum --check` of the
  downloaded assets also checks it). The extension checks the downloaded bytes against it before
  it compiles them, and refuses a module that differs. The release's attestation (`gh attestation
  verify opentide-wasm32-wasip1.wasm --repo opentidehq/opentide`, signed by `publish.yml`) says
  which run built it.
- **The key's name and shape are the extension's** (`pins.json` is its file). What
  [`scripts/engine/check-vscode-extension.mjs`](../../scripts/engine/check-vscode-extension.mjs)
  prints under `wasi` is the section above for a release's assets: it checks that
  `opentide-wasm32-wasip1.wasm` is in `SHA256SUMS`, with the right digest, and a WebAssembly module,
  and leaves `pins.json` as the extension has it.
- **A new release is a new pin**: the URL's tag and the digest change together, and nothing else
  about the module's name does.

## The launch contract

Load the module once and start each process from it (`@vscode/wasm-wasi` 1.0.1):

```ts illustrative
import { Wasm } from "@vscode/wasm-wasi/v1";

const wasm = await Wasm.load();
const module = await WebAssembly.compile(await vscode.workspace.fs.readFile(moduleUri));
const process = await wasm.createProcess("opentide", module, {
  args: ["serve"],                       // or ["lsp", "start"], ["mcp", "start"]
  env: { PWD: "/workspace" },
  mountPoints: [{ kind: "workspaceFolder" }],
  stdio: { in: { kind: "pipeIn" }, out: { kind: "pipeOut" }, err: { kind: "pipeOut" } },
});
await process.run();
```

- **Mounts.** `{ kind: "workspaceFolder" }` mounts the window's folders: one folder at `/workspace`,
  several at `/workspaces/<name>`. Every path the module reads or prints is a guest path, so the
  extension maps document URIs to guest paths and back (for the language server,
  `@vscode/wasm-wasi-lsp`'s URI converters do it). Nothing else has to be mounted.
- **The working directory.** WASI has no working directory the host can set: the module adopts
  `PWD` when it starts. Set it to the folder the process serves; `serve` also takes a `cwd` per run.
- **Home and state.** No `HOME` is needed: the read-only commands run without one. To keep crash
  logs and state between sessions, mount the extension's global storage
  (`{ kind: "vscodeFileSystem", uri: context.globalStorageUri, mountPoint: "/home/opentide" }`) and
  set `HOME` and `XDG_STATE_HOME` under it.
- **Environment.** The module sees only the `env` given: pass the `OPENTIDE_*` settings the
  extension exposes as it passes them to the native CLI today. `OPENTIDE_TERMINAL_WIDTH` sets the
  width of human output, which WASI cannot ask a terminal for; the protocols do not need it.

## The processes

Three long-lived processes, one per protocol, each started from the same compiled module:

| Process | Protocol | Notes |
|---------|----------|-------|
| `opentide serve` | JSON-RPC, one message per line ([serve](../cli/serve.md)) | One server for every folder of the window (`cwd` per run). Ask for `opentide/fetch` at `initialize` and answer it with `@opentide/wasi-host`'s `FetchHost`, below |
| `opentide lsp start` | LSP over stdio, `Content-Length` framing | Start it with `@vscode/wasm-wasi-lsp`; the custom `opentide/*` requests are as native |
| `opentide mcp start` | MCP over stdio | Only if the extension serves MCP to an agent |

- **Tenant requests.** WASI gives the module no sockets, so `serve` asks the client to make each
  tenant request (`opentide/fetch`). `FetchHost` makes it with Node's HTTP stack in the extension
  host, where VS Code's proxy settings and certificate store apply:

  ```ts illustrative
  import { FETCH_CAPABILITY, FetchHost } from "@opentide/wasi-host";

  const host = new FetchHost((message) => serveIn.write(`${JSON.stringify(message)}\n`));
  // each message serve writes: host.handle(message) || the extension's own handling
  serveIn.write(`${JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: FETCH_CAPABILITY })}\n`);
  ```

  Outside `serve` (the language server, MCP, a command run another way) a tenant operation fails
  with `network_unavailable`, naming the native CLI.
- **Cancel.** With no threads, `serve` reads its input between runs and while a run waits for an
  `opentide/fetch` answer. A `$/cancelRequest` therefore stops a run that is waiting on a tenant,
  and reaches a run that only computes when it ends; a queued run is answered `130` unrun, as native.
- **One run at a time.** Requests are handled in order, as native; a long run delays the next.

## Held to the goldens

CI's `wasm` job builds the module, checks its size and runs its smoke tests, and
`packages/wasi-host`'s tests run it under Node's WASI (`scripts/engine/wasi-run.mjs`). The release
train builds the module again at the release's version, runs it under wasmtime (`--version` names
the release, and a command runs) before it is an asset, and ships it as
`opentide-wasm32-wasip1.wasm` ([publishing](./publishing.md#the-wasi-command-line-module)). Through the
port, `cargo xtask golden check --runner wasi` held it to the oracle's recordings on every case that
needs no network; the recordings and that check were retired in #1142.

## Before UC-6.1 starts

- The licence review of an EUPL-1.2 module run in-process by the MIT extension (ADR 0007).
- Run the language server and `serve` under `@vscode/wasm-wasi` itself, desktop and vscode.dev:
  the goldens run under wasmtime and Node, not under VS Code's host.
- Measure the first-run cost: compiling the module once per window, and the first `validate` of a
  large workspace without threads.
