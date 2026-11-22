---
title: VS Code on WASI
description: The handoff for UC-6.1 — how the VS Code extension runs opentide.wasm under @vscode/wasm-wasi with @opentide/wasi-host — the module, the launch contract, mounts, environment, the three processes and the size budget.
---

# VS Code on WASI: the handoff

The extension's move to the WASI build is paused until the release candidates
([UC-6.1](./unified-core.md), filed as
[opentidehq/vscode-extension#75](https://github.com/opentidehq/vscode-extension/issues/75)). This page is
what the extension needs to start it: what the module is, how to launch it, and what it does and
does not do. The decision is [ADR 0007's amendment](./adr/0007-vscode-extension-stays-separate.md#amendment-2026-11-13-the-extension-is-wasi-native).

## What is done

| Unit | What | Where |
|------|------|-------|
| W1 ([#1097](https://github.com/opentidehq/opentide/pull/1097)) | The `opentide` CLI on `wasm32-wasip1`, held to the goldens under wasmtime; git read with gix (no `git` program) | `scripts/engine/build-wasm.sh cli`, ci.yml `wasm` |
| W2 ([#1103](https://github.com/opentidehq/opentide/pull/1103)) | Tenant requests made by the client: `opentide/fetch`, and its extension-host half | `docs/cli/serve.md`, `packages/wasi-host` |
| W3 | The same for `opentide mcp start`: with `OPENTIDE_FETCH=stdio` its tenant requests are `opentide/fetch` lines on its stdio, and `McpFetchBridge` is the extension-host half | `docs/cli/mcp.md`, `packages/wasi-host` |

## The module

- **Build:** `scripts/engine/build-wasm.sh cli` builds `opentide-cli` without default features (no
  terminal UI) in the `wasi` profile, at `target/wasm32-wasip1/wasi/opentide.wasm`. A release ships
  one module for every platform; the extension pins one release's module, so its coupling to
  opentide is one version number.
- **Size:** 22.1 MB, 9.3 MB at `gzip -9` (opt-level `s`, [`[profile.wasi]`](../../Cargo.toml); `z` was 18.9 MB,
  8.35 MB, and 1,000-object workspaces start and validate faster at `s`: see
  [the WASI cold-start note](./perf-wasi-cold-start-2026-11-22.md#the-command-lines-wasi-module-is-built-at-opt-level-s-1774)).
  The build fails above 15 MiB gzipped, which is also the budget of the whole `.vsix` (plan §11): a `.vsix` is a
  zip, so the module costs about its gzipped size there. `OPENTIDE_WASM_OPT=1` runs `wasm-opt` too, which saves
  about 2% of the gzip size, makes `validate` 36% slower on the `s` module, and is off by default.
- **No threads, no processes, no sockets.** Work that runs in parallel natively runs in sequence;
  `doctor --offline` says git was found but its version not checked; `setup hooks` prints the
  `chmod +x` line to run, since WASI preview 1 has no file permissions; the terminal UI refuses, as
  it does without a terminal.
- **Panics abort.** A trap ends the process, not one request: the extension restarts a process that
  exits, as it would restart a crashed native one.

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
| `opentide mcp start` | MCP over stdio | Only if the extension serves MCP to an agent. Start it with `OPENTIDE_FETCH=stdio` and bridge its stdio with `@opentide/wasi-host`'s `McpFetchBridge`, below: every tool then works, tenant tools included |

- **Tenant requests.** WASI gives the module no sockets, so `serve` asks the client to make each
  tenant request (`opentide/fetch`). `FetchHost` makes it with Node's HTTP stack in the extension
  host, where VS Code's proxy settings and certificate store apply:

  ```ts illustrative
  import { FETCH_CAPABILITY, FetchHost } from "@opentide/wasi-host";

  const host = new FetchHost((message) => serveIn.write(`${JSON.stringify(message)}\n`));
  // each message serve writes: host.handle(message) || the extension's own handling
  serveIn.write(`${JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: FETCH_CAPABILITY })}\n`);
  ```

  Outside `serve` and a bridged `mcp start` (the language server, MCP without `OPENTIDE_FETCH`, a
  command run another way) a tenant operation fails with `network_unavailable`, naming the native
  CLI.
- **Tenant requests from `mcp start`.** With `OPENTIDE_FETCH=stdio` in its environment (the WASI
  build only; the native build ignores it), `mcp start` writes each tenant request as an
  `opentide/fetch` JSON-RPC request line on stdout, among its MCP messages, with the same params as
  `serve`'s and ids `opentide-fetch-<token>-1`, `-2`, …, and reads the answer, a response line with the same
  id, on stdin, among the client's messages ([`opentide mcp`](../cli/mcp.md#tenant-requests-over-stdio-opentide_fetch)).
  `McpFetchBridge` sits between the module and the MCP client, splits the two kinds of line and
  answers the requests with `FetchHost`:

  ```ts illustrative
  import { MCP_FETCH_ENVIRONMENT, McpFetchBridge } from "@opentide/wasi-host";

  // env: { ...settings, ...MCP_FETCH_ENVIRONMENT } when the process is created
  const bridge = new McpFetchBridge({
    toServer: (line) => mcpIn.write(line),    // the client's messages and the host's answers, whole lines
    toClient: (line) => agentOut.write(line), // the module's MCP messages, its tenant requests taken out
  });
  mcpOut.onData((chunk) => bridge.fromServer(chunk));   // the module's stdout
  agentIn.onData((chunk) => bridge.fromClient(chunk));  // the agent's messages
  // on exit: bridge.endServer(); bridge.dispose();
  ```

  - **The client's messages wait for a running call.** WASI has no thread to read stdin with, so a
    tool call that waits for a tenant answer reads stdin itself and keeps the client's other
    messages, in order, until the call returns: a `ping` sent meanwhile is answered after the call,
    not during it. Cancelling the call (`notifications/cancelled` for its request id) stops it at
    once and withdraws its request; the server then answers, or not, and the client ignores it as MCP
    says.
  - **Not an MCP stream.** MCP's 2026-07-28 revision forbids a server writing requests to stdout,
    and `opentide/fetch` lines are requests: with `OPENTIDE_FETCH=stdio` the module's stdout is a
    private transport between the module and `McpFetchBridge`, which strips those lines before the
    editor or agent sees anything. Never hand that stdout to an MCP client directly. Without the
    variable the stdout is MCP alone.
  - **The lines carry tenant credentials** (`Authorization`, API-key headers, the body, CA bundles).
    `McpFetchBridge` never forwards a line that mentions `opentide/fetch` and cannot be read as the
    host's own, and drops a client line that is a response to an `opentide-fetch-` id, so an agent
    behind it cannot answer a request itself. The ids are `opentide-fetch-<token>-N` with a random
    per-process token, so a client that writes to the module's stdin directly cannot guess one
    either. The bridge also drops the module's response to a request the client cancelled.
  - **Withdrawals** are MCP's `notifications/cancelled {requestId: "opentide-fetch-N"}` from the
    module; `FetchHost` aborts the request, and `McpFetchBridge` does not pass it on. Without the
    bridge, a client that gets these lines must handle `notifications/cancelled` itself.
  - **End of input.** Closing the module's stdin with a request unanswered fails the call with `the
    client closed its input before answering an opentide/fetch request`. The module never times a
    wait out (no clock, one thread): the host's own limits (`connect_timeout_ms`,
    `read_timeout_ms`) end a request that gets no answer.
  - **Write whole lines.** Both directions are one message per line: `fromClient` forwards only
    whole lines, so the host's answers never land inside a client message.
- **Cancel.** With no threads, `serve` reads its input between runs and while a run waits for an
  `opentide/fetch` answer. A `$/cancelRequest` therefore stops a run that is waiting on a tenant,
  and reaches a run that only computes when it ends; a queued run is answered `130` unrun, as native.
- **One run at a time.** Requests are handled in order, as native; a long run delays the next.

## Held to the goldens

CI's `wasm` job builds the module, checks its size and runs its smoke tests, and
`packages/wasi-host`'s tests run it under Node's WASI (`scripts/engine/wasi-run.mjs`). Through the
port, `cargo xtask golden check --runner wasi` held it to the oracle's recordings on every case that
needs no network; the recordings and that check were retired in #1142.

## Before UC-6.1 starts

- The licence review of an EUPL-1.2 module run in-process by the MIT extension (ADR 0007).
- Run the language server and `serve` under `@vscode/wasm-wasi` itself, desktop and vscode.dev:
  the goldens run under wasmtime and Node, not under VS Code's host.
- Measure the first-run cost: compiling the module once per window, and the first `validate` of a
  large workspace without threads.
