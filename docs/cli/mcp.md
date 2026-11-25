---
title: opentide mcp
description: Start the opentide MCP server on stdio, for editors and agents.
---

# opentide mcp

`opentide mcp start` serves the [Model Context Protocol](https://modelcontextprotocol.io/) on stdin and stdout, so an agent in an editor can search the catalogue, validate objects and queries, and preview deployments through tools. The editor or agent host starts the process and owns it; you do not run it yourself. The tools, resources and host configuration are in the [MCP reference](../mcp/index.md).

```bash
opentide mcp start
```

`opentide setup mcp` writes the configuration that runs it for VS Code, Cursor, Claude Code or any other host ([MCP configuration](../mcp/configuration.md)), and `opentide doctor` checks that one does (`mcp_config`).

## mcp start

Serves MCP over stdio until the host closes stdin. It takes no options of its own; the root options (`--repo`, `--data`, `--proxy`, `--debug`) apply, and `OPENTIDE_REPO_ROOT` in the host's configuration names the workspace when the host does not start it there ([Repository root resolution](./global-options.md#repository-root-resolution)).

- **Stop and reload.** Stop is the host closing stdin; reload is the host spawning the command again. There is no `stop` or `reload` subcommand.
- **Output.** Like [`opentide lsp start`](./lsp.md) and [`opentide serve`](./serve.md), it runs in the `mcp` [output mode](./json-output.md#output-modes): stdout carries JSON-RPC and nothing else, and logs go to stderr.
- **The Rust server.** The server is the Rust one, on rmcp, the official Rust MCP SDK, with the Python server's name, instructions, tools, schemas, resources and answers. Every tool and every resource runs in Rust: no Python handler answers any of them, and the standalone `opentide` binary (`cargo install opentide --features cli`, the npm package) serves the same tools. The tools that reach a tenant (`validate_query` and `run_query` with `live: true`, `deploy_rule` with `dry_run: false`) run the command line's own `validate query --live`, `query` and `deploy` in the same process.

### Tenant requests over stdio: OPENTIDE_FETCH

The WASI build of opentide (the module the VS Code extension runs) has no sockets, so there the tools that reach a tenant fail with `network_unavailable`, naming the native CLI. Started with `OPENTIDE_FETCH=stdio`, the WASI build's `mcp start` instead asks its client to make each tenant request, as [`opentide serve`](./serve.md#tenant-requests-the-client-makes-opentidefetch) does: the full set of tools then works with no native opentide installed.

| `OPENTIDE_FETCH` | Build | Effect |
|------------------|-------|--------|
| `stdio` | WASI (`wasm32-wasip1`) | Each tenant request is written to stdout as an `opentide/fetch` request, and its answer is read from stdin |
| anything else, or unset | WASI | Unchanged: a tenant tool fails with `network_unavailable` |
| any value | native | Ignored: opentide makes the requests with its own HTTP client, and writes no `opentide/fetch` |

- **Framing.** MCP's stdio is one JSON-RPC message a line, and the requests are messages of that stream: each is a JSON-RPC 2.0 request line on stdout, method `opentide/fetch`, with the [params `opentide serve` sends](./serve.md#tenant-requests-the-client-makes-opentidefetch) (`run` is the `tools/call`'s request id as text, `"2"`), among the server's MCP messages. The client answers with a JSON-RPC response line on stdin, with the same id, among its own MCP messages. The answer is read as `opentide serve` reads it: a result with `status`, `headers`, `body` (base64) and optionally `url` and `elapsed_ms`, or an error whose `data.kind` is `connect`, `timeout`, `aborted`, `unreachable` or `answer`.
  ```json illustrative
  {"jsonrpc":"2.0","id":"opentide-fetch-0123456789abcdef0123456789abcdef-1","method":"opentide/fetch","params":{"run":"2","platform":"elastic","tenant":"soc","method":"POST","url":"https://es.example.com/_query","headers":[["content-type","application/json"]],"body":"eyJxdWVyeSI6Ii4uLiJ9","connect_timeout_ms":120000,"read_timeout_ms":120000,"tls":{"verify":true,"ca_bundles":[]},"proxy":null}}
  {"jsonrpc":"2.0","id":"opentide-fetch-0123456789abcdef0123456789abcdef-1","result":{"status":200,"headers":[["content-type","application/json"]],"body":"eyJ2YWx1ZXMiOltdfQ==","elapsed_ms":120}}
  ```
- **Not MCP-conformant, and secret.** MCP's 2026-07-28 revision says a server must not write JSON-RPC requests to stdout, and `opentide/fetch` lines are requests. While `OPENTIDE_FETCH=stdio` is set the module's stdout is therefore a private stream between the module and the bridge that started it, not an MCP transport. Only a bridge such as `McpFetchBridge` may consume it, and it must take the `opentide/fetch` lines (and the `notifications/cancelled` that withdraws one) out before anything reaches an MCP client, which would reject them. The lines also carry **the tenant's credentials**: the `Authorization` and API-key headers, the request body and the CA bundles. They must never reach an agent, a log or a client. A bridge must drop a line that mentions `opentide/fetch` and that it cannot read, never forward it. Without the variable the stream is MCP and nothing else.
- **Ids.** The server's ids are strings, `opentide-fetch-<token>-1`, `opentide-fetch-<token>-2`, …. The prefix keeps them apart from an MCP client's ids, which are numbers or other strings, but a client can still send a string id that starts with it. The *token* is 128 random bits chosen when the process starts, and appears only on stdout, so a client that can write to the module's stdin cannot guess an id: the module drops an answer to an id it did not ask. A bridge must also drop any client line that is a response to an id with the prefix, so an agent behind it cannot answer a tenant request itself (and fake the result of a deploy or a query); `McpFetchBridge` does. It decides on the parsed line, never on its text: JSON lets any character of an id or a key be written as a `\uXXXX` escape, which the module's parser decodes, so a substring test would let `"\u006fpentide-fetch-…"` through. Only a string `method` makes a message a request: a message with a fetch id and a `method` that is `null`, a number or anything else is an answer in disguise, and is dropped. A batch (an array) is checked element by element, nested ones too, and dropped whole when it holds one forged answer; the server has no batches (MCP dropped them in 2025-06-18) and answers any other batch `-32600`, as it answers any JSON that is not a message.
- **While a call waits.** The WASI build has no thread to read stdin with, so a tool call that waits for an answer reads stdin itself. The answer reaches the call; the client's other messages (`ping`, a list, a later request, a notification) are kept in order and read once the call returns, so they are answered after it, not during it. This differs from the native server, which answers a `ping` or a list while a call runs.
- **Cancellation follows MCP's.** `notifications/cancelled` for the running `tools/call` stops it at once: its pending request is withdrawn, and the call ends without waiting. The server withdraws a request with MCP's own `notifications/cancelled` with `requestId` set to the request's id; a late answer to a withdrawn request is dropped. A call cancelled after its last request was made, or while it computes, runs to its end: the module only reads the client's messages while a request waits. A cancelled call's request that was not yet written is not written (its credentials never reach the line).
- **The module may still answer a cancelled call.** On WASI the cancellation is read by the call itself, not by the MCP server, so the call ends and the server then answers it (an error result) before it reads the cancellation. MCP says the receiver should send no response, and the sender should ignore one that arrives. `McpFetchBridge` drops the response to a request its client cancelled, so the client sees none; a client without the bridge must ignore it.
- **No answer.** If the client closes stdin while a request is unanswered, the call fails with a message that says so (`the client closed its input before answering an opentide/fetch request`), as a tenant that cannot be reached, and the server then exits. A client that stays connected and never answers leaves the call waiting: the WASI build has no clock to time the wait out, so the client enforces the limits (`connect_timeout_ms`, `read_timeout_ms`).
- **The client** is typically the VS Code extension, which bridges the module's stdio with [`@opentide/wasi-host`](https://github.com/opentidehq/opentide/tree/development/packages/wasi-host)'s `McpFetchBridge`.

## mcp

`opentide mcp` on its own does not start the server. Like every group that only holds subcommands, it is a usage error: it names `start` and exits `2` with `failure.code` `usage_error`.

```bash
opentide mcp
```

At a terminal it prints the group's help on stdout (exit `2`); a coding agent (the `agent` mode) gets one line on stderr:

```text illustrative
error: missing command: choose from start
```

This is not captured by the docs harness, which does not run `mcp`; `opentide mcp --help` prints the help and exits `0`.

## Protocol versions

`initialize` negotiates `2024-11-05`, `2025-03-26`, `2025-06-18` and `2025-11-25`: the server answers the version the client asks for when it knows it, else `2025-11-25`, the newest that has `initialize` (a client that asks for `2026-07-28` in `initialize` is answered `2025-11-25`). The 2026-07-28 revision, which has no `initialize`, is served too: `server/discover` answers `supportedVersions` (the four above and `2026-07-28`), and a request that carries `io.modelcontextprotocol/protocolVersion` and `io.modelcontextprotocol/clientCapabilities` in its `_meta` is answered without a handshake. Every result a request of that revision gets carries `resultType: "complete"`, which the revision requires (`tools/list`, `tools/call`, `resources/list`, `resources/templates/list`, `resources/read`, `prompts/list`, `completion/complete` and `server/discover`), together with `ttlMs` and `cacheScope` on the lists and reads. A session that began with `initialize` keeps the shapes it always had: no `resultType` on any result. (`ping`, which that revision removed, is still answered with an empty result.) `server/discover` is held to the same rule as every request of that revision: without those two `_meta` keys it is answered `-32602` (Invalid params), naming the keys it lacks. The 2026-07-28 specification does not exempt it: its general rules say fields marked as required must be included on every request, and that a server must reject a request missing one with `-32602` ([basic](https://modelcontextprotocol.io/specification/2026-07-28/basic.md), [server/discover](https://modelcontextprotocol.io/specification/2026-07-28/server/discover.md), whose example carries both keys). A client that does not yet know a server's versions sends its preferred version in `_meta` and reads the answer's `supportedVersions`, or sends `initialize` as before.

## Protocol errors

The server reads one JSON-RPC message a line. What it answers to a message it cannot serve:

| Message | Answer |
|---------|--------|
| A line that is not JSON | Nothing: the line is skipped, as the official MCP SDKs skip one, since a parse error has no `id` to answer and answering garbage can start an error loop |
| JSON that is not a JSON-RPC message | `-32600` Invalid request, with no `id` |
| `tools/call` or `resources/read` without `params`, or with params that do not read | `-32602` Invalid params, with the method as `data` |
| A method the server does not have | `-32601` Method not found, with the method as `data` |
| A request before `initialize` | `-32602`, naming the `_meta` keys it lacks: the 2026-07-28 revision of MCP lets a request skip `initialize` when it carries its protocol version in `_meta`. Send `initialize` first |

## Exit codes

| Code | When |
|------|------|
| `0` | The host closed stdin |
| `2` | `opentide mcp` without `start`, or an unknown subcommand or option |

## Source

The server, `crates/opentide-cli/src/mcp/`; its manifest, `crates/opentide-cli/data/mcp/manifest.json`.
