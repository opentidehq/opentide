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

| Flag | Config file | `OPENTIDE_REPO_ROOT` |
|------|-------------|----------------------|
| `--vscode` | `.vscode/mcp.json` | `${workspaceFolder}` |
| `--cursor` | `.cursor/mcp.json` | `${workspaceFolder}` |
| `--claude-code` | `.mcp.json` | `${CLAUDE_PROJECT_DIR}` |
| `--generic` | `opentide.mcp.json` | omitted (cwd discovery) |

## Minimal config

VS Code workspace MCP (`.vscode/mcp.json`) uses a top-level `servers` object. Cursor, Claude Code, and the generic template use `mcpServers`.

Repo-root placeholders are **host-specific**. VS Code and Cursor expand `${workspaceFolder}`. Claude Code expands `${CLAUDE_PROJECT_DIR}`. The generic file is copied into arbitrary hosts, so it does not set `OPENTIDE_REPO_ROOT` — the server walks from cwd to the git root (`get_repo_root`). Set an absolute path when cwd is not the detection repository.

### VS Code

```json
{
  "servers": {
    "opentide": {
      "command": "opentide-mcp",
      "env": {
        "OPENTIDE_REPO_ROOT": "${workspaceFolder}"
      }
    }
  }
}
```

### Cursor

```json
{
  "mcpServers": {
    "opentide": {
      "command": "opentide-mcp",
      "env": {
        "OPENTIDE_REPO_ROOT": "${workspaceFolder}"
      }
    }
  }
}
```

### Claude Code

```json
{
  "mcpServers": {
    "opentide": {
      "command": "opentide-mcp",
      "env": {
        "OPENTIDE_REPO_ROOT": "${CLAUDE_PROJECT_DIR}"
      }
    }
  }
}
```

### Generic

```json
{
  "mcpServers": {
    "opentide": {
      "command": "opentide-mcp"
    }
  }
}
```

When the generic file is imported into a host that does expand placeholders, add that host's variable (or a real path) yourself.

Bundled templates: `src/opentide/data/setup/mcp/`.

## Environment variables

Set in the MCP host's server environment block when the catalogue is not discoverable from the process cwd:

| Variable | Required | Purpose |
|----------|----------|---------|
| `OPENTIDE_REPO_ROOT` | When cwd is not the detection repo | Detection content repository root |
| `OPENTIDE_DATA_ROOT` | No | Override bundled package data |
| `DEBUG` | No | Verbose logging |

If `OPENTIDE_REPO_ROOT` is unset, `get_repo_root()` walks from cwd to the nearest `.git` directory. A literal unexpanded token such as `${workspaceFolder}` is treated as a path, not interpolated by the server.

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

When the editor workspace is the **opentide package repo** but content lives elsewhere, always set `OPENTIDE_REPO_ROOT` to the detection content root (an absolute path, not an editor placeholder the host will not expand).

## Query validation policy

Agents must treat `validate_query` responses with `supported: false` as **not validated** for CrowdStrike and HarfangLab. Never infer a pass.

## Deploy safety

`deploy_rule` defaults to `dry_run=true`. Agents should only set `dry_run=false` with explicit human approval.

## Related

- [Tools](./tools.md)
- [Usage: Agentic setup](../usage/workflows/agentic-setup.md)
