# Editor hosts

The OpenTide LSP owns Tide diagnostics. Disable yamlls / Red Hat YAML on `objects/**`.

Languages: `opentide-yaml`, `kql`, `spl` (never `sql`).

Semantic tokens come from the server. TextMate grammars must be **copied from the language-server highlight zip**, never hand-authored.

## Helix

See `editors/helix/languages.toml`.

## Neovim

See `editors/nvim/opentide.lua`.

## Zed

See `editors/zed/opentide.json`.

## VS Code

Lives in **OpenTideHQ/vscode-extension** (other repository). MIT client, EUPL engine notices.

## Web

`packages/lsp-worker` exposes `highlight()` + `legend()` for Monaco without a full language client.

```ts
import { createOpentideClient } from "@opentide/lsp-client";

const client = createOpentideClient({ transport: "stdio" });
```
