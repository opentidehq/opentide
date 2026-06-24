---
title: MCP configuration
description: Editor MCP config files, environment variables, and multi-host setup with opentide setup mcp.
---

# MCP configuration

## Automated setup

```bash
opentide setup mcp --cursor --yes
opentide setup mcp --vscode --generic --yes
```

| Flag | Config file |
|------|-------------|
| `--vscode` | `.vscode/mcp.json` |
| `--cursor` | `.cursor/mcp.json` |
| `--claude-code` | `.mcp.json` |
| `--generic` | `opentide.mcp.json` |

## Minimal config

All hosts use the same server entry:

```json
{
  "mcpServers": {
    "opentide": {
      "command": "opentide-mcp"
    }
  }
}
```

Bundled templates: `src/opentide/data/setup/mcp/`.

## Environment variables

Set in the MCP host's server environment block when the catalogue is not in the editor workspace root:

| Variable | Required | Purpose |
|----------|----------|---------|
| `OPENTIDE_REPO_ROOT` | Yes | Detection content repository root |
| `OPENTIDE_DATA_ROOT` | No | Override bundled package data |
| `DEBUG` | No | Verbose logging |

### Cursor example

```json
{
  "mcpServers": {
    "opentide": {
      "command": "opentide-mcp",
      "env": {
        "OPENTIDE_REPO_ROOT": "/absolute/path/to/detection-repo"
      }
    }
  }
}
```

## Multi-repo workspaces

When the editor workspace is the **opentide package repo** but content lives elsewhere, always set `OPENTIDE_REPO_ROOT` explicitly.

## Query validation policy

Agents must treat `validate_query` responses with `supported: false` as **not validated** for CrowdStrike and HarfangLab. Never infer a pass.

## Deploy safety

`deploy_rule` defaults to `dry_run=true`. Agents should only set `dry_run=false` with explicit human approval.

## Related

- [Tools](./tools.md)
- [Usage: Agentic setup](../usage/workflows/agentic-setup.md)
