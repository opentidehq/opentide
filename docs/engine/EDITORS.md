# Editor hosts

The opentide LSP owns Tide diagnostics. Disable yamlls / Red Hat YAML on `objects/**`.

Languages: `opentide-yaml`, `kql`, `spl`, `esql`, `eql`, `kuery` (Kibana KQL), `lucene` (never `sql`).

Semantic tokens come from the server. TextMate grammars must be **copied from the language-server highlight zip**, never hand-authored.

## Helix

See `editors/helix/languages.toml`.

## Neovim

See `editors/nvim/opentide.lua`.

## Zed

See `editors/zed/opentide.json`.

## VS Code

Lives in **opentidehq/vscode-extension** (other repository, #17). MIT client, EUPL engine notices.

Language ids are the server's: `opentide-yaml`, `kql`, `spl`, `esql`, `eql`, `kuery`, `lucene`. Use `DOCUMENT_SELECTOR` from `@opentide/lsp-client`, which matches each language by id and by file pattern.

`esql` is also the id of Elastic's own ES|QL extension. The ids are the shared vocabulary, so the opentide extension registers `esql` too, never a second id for the same language. Its TextMate grammar uses the scope `source.opentide.esql`, not Elastic's `source.esql`, so the two grammars never collide. The server's semantic tokens are authoritative for colour either way. The other three Elastic ids (`eql`, `kuery`, `lucene`) have no prior VS Code owner.

## TypeScript client

`@opentide/lsp-client` reaches the engine three ways. Each answers `highlight()`, `legend()` and, where the transport has an analyzer, `analyze()`. A transport that cannot answer rejects; it never returns an empty result in place of one.

| Transport | Runs | `analyze` |
| --- | --- | --- |
| `stdio` | `opentide-lsp --stdio` (`command`, default `opentide-lsp` on `PATH`), started once, over JSON-RPC | yes |
| `worker` | the `opentide-wasm` module you pass as `module` | no: the browser module only highlights |
| `wasi` | the `wasm32-wasip1` CLI you pass as `wasi`, under `node:wasi`, once per call | yes |

```ts
import { createOpentideClient } from "@opentide/lsp-client";

const client = createOpentideClient({ transport: "stdio" });
const { diagnostics } = await client.analyze("kql", "SecurityEvent | take 1");
await client.dispose();
```

For Monaco, load the module inside your Web Worker with `@opentide/lsp-worker`, then hand it to the client:

```ts
import { loadHighlightModule } from "@opentide/lsp-worker";

const module = await loadHighlightModule("/opentide/opentide_wasm.js"); // wasm-bindgen --target web
const client = createOpentideClient({ transport: "worker", module });
```
