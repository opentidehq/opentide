---
title: MCP installation
description: Install the mcp extra and start the stdio server with opentide mcp start.
---

# MCP installation

## PyPI

The server needs the **`mcp` extra**:

```bash
pip install 'opentide[mcp]==0.12.0'
```

Command: **`opentide mcp start`**. It calls `opentide.mcp_server.launcher:main`, which probes for `mcp.server.fastmcp` before importing the server.

<Callout>
`mcp` is not a dependency of the base package: it pulls a web-server stack
(`starlette`, `httpx`, `sse-starlette`, `uvicorn`) that a CI pipeline running
`opentide validate` has no use for. Run `opentide mcp start` without the extra
and it tells you exactly that on stderr, then exits 1 — it never raises
`ModuleNotFoundError`, and it writes no JSON-RPC.

The extra pins `mcp>=1.28.1,<2`. `mcp` 2.x replaced `mcp.server.fastmcp` with
`MCPServer`; OpenTide has not migrated yet.
</Callout>

All seven platform adapters ship in the same wheel — enable them in the repo with `opentide setup platforms`.

## Verify

`opentide mcp` with no subcommand prints help and exits. It does not start the server. `opentide mcp start` blocks until the host closes stdin. That is what an editor expects. Stop is the host closing stdin. Reload is the host spawning the command again. There is no `reload` or `stop` subcommand.

```bash
which opentide
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide mcp --help
opentide mcp start
```

If the extra is missing you get this on stderr instead of a traceback:

```text
opentide mcp start needs the MCP extra, which is not installed (missing: mcp.server.fastmcp).
Install it with:  pip install 'opentide[mcp]'
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
