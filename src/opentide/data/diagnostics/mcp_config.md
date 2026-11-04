# mcp_config

An MCP configuration from `opentide setup mcp` runs `opentide mcp start`.

Reported by `opentide doctor`. Warns when no configuration has such a server, or its command is not on `PATH`; skipped when there is no configuration. Passes without one when `.vscode/extensions.json` recommends the opentide VS Code extension (`opentidehq.opentide`), which provides the opentide MCP server to VS Code; with both, the message says so, since `.vscode/mcp.json` then serves teammates without the extension.

## Example

```text
○ No MCP configuration: agents in editors cannot call opentide tools · mcp_config
  → opentide setup mcp --vscode (or --cursor, --claude-code, --generic)
```

## How to fix

Run `opentide setup mcp` with your editor's flag.
