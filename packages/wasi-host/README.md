# @opentide/wasi-host

The extension host's half of opentide's `opentide/fetch`. The WASI build of opentide runs under VS Code's WASI host, which gives it no sockets. So its `opentide serve` asks the client to make each tenant request, and `FetchHost` makes them with Node's HTTP stack. That includes the tenant's TLS verification and CA bundles, its proxy, and its connect and read timeouts.

```ts
import { FETCH_CAPABILITY, FetchHost } from "@opentide/wasi-host";

const host = new FetchHost((message) => serve.write(`${JSON.stringify(message)}\n`));
// For each JSON-RPC message the server sends:
if (!host.handle(message)) {
  // not opentide/fetch: the client's own handling
}
// The first request:
serve.write(`${JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: FETCH_CAPABILITY })}\n`);
```

`opentide mcp start` asks the same way when it is started with `OPENTIDE_FETCH=stdio`: its requests are lines on its stdout, among its MCP messages, with ids `opentide-fetch-<token>-1`, `-2`, …, and the answers go in on its stdin. `McpFetchBridge` splits the two on the module's stdio pair, answers the requests with a `FetchHost`, and passes every MCP message through in order, one whole line at a time:

```ts
import { MCP_FETCH_ENVIRONMENT, McpFetchBridge } from "@opentide/wasi-host";

// Start the module with { ...env, ...MCP_FETCH_ENVIRONMENT }.
const bridge = new McpFetchBridge({
  toServer: (line) => module.stdin.write(line), // the client's messages and the host's answers
  toClient: (line) => agent.write(line), // the module's MCP messages
});
module.stdout.on("data", (chunk) => bridge.fromServer(chunk));
agent.on("data", (chunk) => bridge.fromClient(chunk));
module.on("close", () => {
  bridge.endServer();
  bridge.dispose();
});
```

The requests carry the tenant's credentials (`Authorization` and API-key headers, the body, CA bundles), and the module's stdout is not an MCP stream while `OPENTIDE_FETCH=stdio` is set (MCP's 2026-07-28 revision forbids server requests on stdout), so it must never reach an agent directly. The bridge enforces that:

- a line that mentions `opentide/fetch` and cannot be read as a request of the host's is dropped, never forwarded;
- a client line that is a response to an `opentide-fetch-` id, or that mentions the prefix and cannot be read, is dropped, so an agent cannot answer a tenant request itself;
- the module's response to a request the client cancelled is dropped (MCP has no response go out for a cancelled request);
- after `dispose()` no new tenant request is started.

The protocol is in [opentide serve](https://github.com/opentidehq/opentide/blob/development/docs/cli/serve.md#tenant-requests-the-client-makes-opentidefetch).

For `mcp start`, see [opentide mcp](https://github.com/opentidehq/opentide/blob/development/docs/cli/mcp.md#tenant-requests-over-stdio-opentide_fetch).
