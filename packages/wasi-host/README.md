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

The protocol is in [opentide serve](https://github.com/opentidehq/opentide/blob/development/docs/cli/serve.md#tenant-requests-the-client-makes-opentidefetch).
