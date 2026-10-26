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

## Web

`packages/lsp-worker` exposes `highlight()` + `legend()` for Monaco without a full language client.

```ts
import { createOpentideClient } from "@opentide/lsp-client";

const client = createOpentideClient({ transport: "stdio" });
```
