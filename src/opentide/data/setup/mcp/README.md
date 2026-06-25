# OpenTide MCP — generic install notes

Install OpenTide (includes the MCP server):

```bash
pip install opentide
```

Copy `generic.json` (or the host-specific file) into your editor's MCP configuration location.

| Host | Typical path |
|------|--------------|
| VS Code | `.vscode/mcp.json` |
| Cursor | `.cursor/mcp.json` |
| Claude Code | `.mcp.json` (project root) |

Run `opentide setup mcp` to write the correct file for your host automatically.
