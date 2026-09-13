---
title: MCP installation
description: Install opentide-mcp — included with pip install opentide — and verify stdio transport.
---

# MCP installation

## PyPI

The MCP server ships with the base package:

```bash
pip install 'opentide==0.1.3'
```

Console script: **`opentide-mcp`** → `opentide.mcp_server.server:main`

Dependencies (`mcp`, `fastmcp`) are installed automatically. All seven platform adapters ship in the same wheel — enable them in the repo with `opentide setup platforms`.

## Verify

```bash
which opentide-mcp
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide-mcp   # blocks on stdio — expected for MCP hosts
```

MCP hosts spawn the process automatically; you rarely run it manually.

## Scaffold editor config

```bash
opentide setup mcp --cursor --yes
opentide setup mcp --vscode --claude-code --generic --yes
```

See [Configuration](./configuration.md).

## Development

From this repository:

```bash
uv sync --group dev
uv run opentide-mcp
```

Logging initialises as JSON/plain structlog on the MCP process (no Rich banner).
