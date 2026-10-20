---
title: MCP installation
description: Install opentide and start the stdio server with opentide mcp start.
---

# MCP installation

## PyPI

The server ships in the base package:

```bash
pip install 'opentide==0.17.0'
```

Command: **`opentide mcp start`**. It calls `opentide.mcp_server.launcher:main`, which probes for `mcp.server.fastmcp` before importing the server.

<Callout>
`mcp` was an optional `[mcp]` extra until 0.14.0, on the grounds that it pulls a
web-server stack (`starlette`, `httpx`, `sse-starlette`, `uvicorn`) that a CI
pipeline running `opentide validate` has no use for. That traded a few
megabytes for a first-class CLI command that did not work on a plain install,
so `mcp` is now a base dependency. Since 0.16.0 opentide declares no extras at
all; an existing `pip install opentide[mcp]` or an editor config naming it still
installs opentide, with a warning from pip or uv about the unknown extra.

The base dependency pins `mcp>=1.28.1,<2`. `mcp` 2.x replaced
`mcp.server.fastmcp` with `MCPServer`; opentide has not migrated yet, so the
launcher tells those two failures apart rather than reporting both as missing.
</Callout>

All eight platform adapters ship in the same wheel — enable them in the repo with `opentide setup platforms`.

## Verify

`opentide mcp` with no subcommand prints help and exits. It does not start the server. `opentide mcp start` blocks until the host closes stdin. That is what an editor expects. Stop is the host closing stdin. Reload is the host spawning the command again. There is no `reload` or `stop` subcommand.

```bash
which opentide
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide mcp --help
opentide mcp start
```

If `mcp` cannot be imported — an incomplete environment, or an incompatible major — you get this on stderr instead of a traceback:

```text
opentide mcp start cannot import mcp.server.fastmcp, but mcp ships as a base dependency of opentide — this environment is incomplete.
Repair it with:  pip install 'mcp>=1.28.1,<2'
Everything else in the opentide CLI works without it.
```

MCP hosts spawn the process automatically; you rarely run it manually.
`opentide setup mcp` warns when it writes a config for a server you cannot yet start.

Logging on `opentide mcp start` is JSON/plain structlog on stderr. stdout is JSON-RPC only.

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
uv run opentide mcp start
```

Logging initialises as JSON/plain structlog on the MCP process (no Rich banner).
