---
title: MCP installation
description: Install opentide-mcp with the mcp extra and verify stdio transport.
---

# MCP installation

## PyPI

The server needs the **`mcp` extra**:

```bash
pip install 'opentide[mcp]==0.6.0'
```

Console script: **`opentide-mcp`** → `opentide.mcp_server.launcher:main`

<Callout>
The `opentide-mcp` script is installed by the base package, but `mcp` is not:
it pulls a web-server stack (`starlette`, `httpx`, `sse-starlette`, `uvicorn`)
that a CI pipeline running `opentide validate` has no use for. Run
`opentide-mcp` without the extra and it tells you exactly that, then exits 1 —
it never raises `ModuleNotFoundError`.

The extra pins `mcp>=1.28.1,<2`. `mcp` 2.x replaced `mcp.server.fastmcp` with
`MCPServer`; OpenTide has not migrated yet.
</Callout>

All seven platform adapters ship in the same wheel — enable them in the repo with `opentide setup platforms`.

## Verify

```bash
which opentide-mcp
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide-mcp   # blocks on stdio — expected for MCP hosts
```

If the extra is missing you get this instead of a traceback:

```text
opentide-mcp needs the MCP extra, which is not installed (missing: mcp.server.fastmcp).
Install it with:  pip install 'opentide[mcp]'
Everything else in the opentide CLI works without it.
```

MCP hosts spawn the process automatically; you rarely run it manually.
`opentide setup mcp` warns when it writes a config for a server you cannot yet start.

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
