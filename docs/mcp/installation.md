---
title: MCP installation
description: Install opentide and start the stdio server with opentide mcp start.
---

# MCP installation

## PyPI

The server ships in the base package:

```bash
pip install 'opentide==0.28.1'
```

Command: **`opentide mcp start`**. The server is the command line's own, in Rust (rmcp, the official Rust MCP SDK): it needs no Python package of its own.

<Callout>
Until 0.23.0 the server was Python, on the `mcp` package, which opentide declared as a base dependency (`mcp>=2.3,<3`). The Rust server replaced it, and opentide no longer depends on `mcp`.
</Callout>

All thirteen platform adapters ship in the same wheel — enable them in the repo with `opentide setup platforms`.

## Verify

`opentide mcp` with no subcommand does not start the server: it names `start` and exits `2` ([`opentide mcp`](../cli/mcp.md#mcp)); `opentide mcp --help` prints the help. `opentide mcp start` blocks until the host closes stdin. That is what an editor expects. Stop is the host closing stdin. Reload is the host spawning the command again. There is no `reload` or `stop` subcommand.

```bash
which opentide
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide mcp --help
opentide mcp start
```

MCP hosts spawn the process automatically; you rarely run it manually.
`opentide setup mcp` warns when it writes a config for a server you cannot yet start.

Logging on `opentide mcp start` goes to stderr. stdout is JSON-RPC only.

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
