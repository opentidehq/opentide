---
title: MCP installation
description: Install the opentide-mcp server with the mcp PyPI extra and verify stdio transport.
---

# MCP installation

## PyPI

```bash
pip install "opentide[mcp]>=0.1"
```

The `mcp` extra installs:

- `mcp>=1.0`
- `fastmcp>=2.0`

Console script: **`opentide-mcp`** → `opentide.mcp_server.server:main`

## Combined with CLI

```bash
pip install "opentide[mcp,cli,sentinel]>=0.1"
```

Platform extras are optional unless tools need live query execution or deployment against a platform API.

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
