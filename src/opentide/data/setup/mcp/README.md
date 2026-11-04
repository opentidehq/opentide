# opentide MCP — generic install notes

Install opentide (includes the MCP server):

```bash
pip install opentide
```

Copy `generic.json` (or the host-specific file) into your editor's MCP configuration location.

| Host | Typical path | `OPENTIDE_REPO_ROOT` |
|------|--------------|----------------------|
| VS Code | `.vscode/mcp.json` | `${workspaceFolder}` |
| Cursor | `.cursor/mcp.json` | `${workspaceFolder}` |
| Claude Code | `.mcp.json` (project root) | `${CLAUDE_PROJECT_DIR}` |
| Generic | `opentide.mcp.json` (an Agent Plugins 1.0.0 `mcp.json`) | omitted — server discovers the workspace from cwd |

The generic template does not set `OPENTIDE_REPO_ROOT`. MCP hosts that do not expand editor placeholders should leave it unset (cwd discovery) or set an absolute path. Do not copy `${workspaceFolder}` or `${CLAUDE_PROJECT_DIR}` into a host that will not expand them.

Run `opentide setup mcp` to write the correct file for your host automatically.
