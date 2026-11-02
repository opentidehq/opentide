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

Repo-root placeholders are **host-specific**. VS Code and Cursor expand `${workspaceFolder}`. Claude Code expands `${CLAUDE_PROJECT_DIR}`. The generic file is copied into arbitrary hosts, so it does not set `OPENTIDE_REPO_ROOT` — the server walks up from cwd to the nearest detection workspace (`get_repo_root`). Set an absolute path when cwd is not inside the detection workspace.

### VS Code

```json
{
  "servers": {
    "opentide": {
      "command": "opentide",
      "args": ["mcp", "start"],
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
      "command": "opentide",
      "args": ["mcp", "start"],
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
      "command": "opentide",
      "args": ["mcp", "start"],
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
      "command": "opentide",
      "args": ["mcp", "start"]
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

If `OPENTIDE_REPO_ROOT` is unset, `get_repo_root()` walks up from cwd to the nearest directory holding `.opentide/` or `objects/`, without leaving the enclosing git checkout, and falls back to the git top level. See [Repository root resolution](../cli/global-options.md#repository-root-resolution). A literal unexpanded token such as `${workspaceFolder}` is treated as a path, not interpolated by the server.

### Cursor example

```json
{
  "mcpServers": {
    "opentide": {
      "command": "opentide",
      "args": ["mcp", "start"],
      "env": {
        "OPENTIDE_REPO_ROOT": "/absolute/path/to/detection-repo"
      }
    }
  }
}
```

## Agent Plugins

The [opentidehq/skills](https://github.com/opentidehq/skills) repository is an [Agent Plugins 1.0](https://agent-plugins.org/specification) package: its root `plugin.json` names it, `skills/` holds the detection skills, and its `mcp.json` starts this server, so one install gives an agent both:

```json
{
  "$schema": "https://agent-plugins.org/schemas/1.0.0/mcp.schema.json",
  "mcpServers": {
    "opentide": { "type": "stdio", "command": "opentide", "args": ["mcp", "start"] }
  }
}
```

Install it from the host, with `opentide` on the host's `PATH` (`pip install opentide`):

| Host | Install |
|------|---------|
| VS Code (GitHub Copilot) | **Chat: Install Plugin from Source**, then `https://github.com/opentidehq/skills` |
| Cursor | **Customize** → Plugins, install from the Git repository |
| GitHub Copilot CLI | Install from the Git repository URL |

An Agent Plugins client starts the server in the plugin's own directory, which is the skills package, not your detection repository. The server never serves the plugin as a catalogue. It serves, in order:

1. `OPENTIDE_REPO_ROOT` or `OPENTIDE_TIDE_WORKSPACE`, when it names a detection workspace;
2. the plugin directory, when it is itself a detection workspace;
3. the host's project directory: `CLAUDE_PROJECT_DIR`, else `PWD` (the directory the host was started in), when it lies in a detection workspace.

Otherwise the catalogue tools and resources (`search`, `validation_report`, `opentide://rules`, ...) fail with `workspace_not_found`, naming the plugin directory; `explain` and offline `validate_query` still work. Set `OPENTIDE_REPO_ROOT` in the host's settings for the server, or add the server to the detection repository itself with [`opentide setup mcp`](#automated-setup), whose files name the project directory.

## Multi-repo workspaces

When the editor workspace is the **opentide package repo** but content lives elsewhere, always set `OPENTIDE_REPO_ROOT` to the detection content root (an absolute path, not an editor placeholder the host will not expand).

## Query validation policy

Agents must treat `validate_query` responses with `supported: false` as **not validated** for CrowdStrike and HarfangLab. Never infer a pass.

## Deploy safety

`deploy_rule` defaults to `dry_run=true`. Agents should only set `dry_run=false` with explicit human approval.

## Related

- [Tools](./tools.md)
- [Usage: Agentic setup](../usage/workflows/agentic-setup.md)
