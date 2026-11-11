---
title: opentide mcp
description: Start the opentide MCP server on stdio, for editors and agents.
---

# opentide mcp

`opentide mcp start` serves the [Model Context Protocol](https://modelcontextprotocol.io/) on stdin and stdout, so an agent in an editor can search the catalogue, validate objects and queries, and preview deployments through tools. The editor or agent host starts the process and owns it; you do not run it yourself. The tools, resources and host configuration are in the [MCP reference](../mcp/index.md).

```bash
opentide mcp start
```

`opentide setup mcp` writes the configuration that runs it for VS Code, Cursor, Claude Code or any other host ([MCP configuration](../mcp/configuration.md)), and `opentide doctor` checks that one does (`mcp_config`).

## mcp start

Serves MCP over stdio until the host closes stdin. It takes no options of its own; the root options (`--repo`, `--data`, `--proxy`, `--debug`) apply, and `OPENTIDE_REPO_ROOT` in the host's configuration names the workspace when the host does not start it there ([Repository root resolution](./global-options.md#repository-root-resolution)).

- **Stop and reload.** Stop is the host closing stdin; reload is the host spawning the command again. There is no `stop` or `reload` subcommand.
- **Output.** Like [`opentide lsp start`](./lsp.md) and [`opentide serve`](./serve.md), it runs in the `mcp` [output mode](./json-output.md#output-modes): stdout carries JSON-RPC and nothing else, and logs go to stderr.
- **The Rust server.** With `OPENTIDE_ENGINE=rust` in the host's configuration, the server is the Rust one, on rmcp, the official Rust MCP SDK: the same name, instructions, tools, schemas, resources and answers. `explain` and `validation_report` run in Rust; the other tools and every resource are answered, in the same process, by the Python server's handlers until their Rust implementation exists. Python stays the default, and `compare` runs the Python server, whose validation tools record any Rust difference ([Choosing the implementation](../mcp/tools.md#choosing-the-implementation)).
- **A missing `mcp` package.** Before the handshake, the launcher checks that the `mcp` package (a base dependency, `mcp>=2.3,<3`) imports. When it does not, it prints what is wrong and the command that repairs it on stderr, and exits `1` without writing to stdout ([MCP installation](../mcp/installation.md#verify)).

## mcp

`opentide mcp` on its own does not start the server. Like every group that only holds subcommands, it is a usage error: it names `start` and exits `2` with `failure.code` `usage_error`.

```bash
opentide mcp
```

```text illustrative
error: Missing command: choose from start.
  usage: opentide mcp [OPTIONS] COMMAND [ARGS]...
  help: run 'opentide mcp --help'
```

This is not captured by the docs harness, which does not run `mcp`; `opentide mcp --help` prints the help and exits `0`.

## Exit codes

| Code | When |
|------|------|
| `0` | The host closed stdin |
| `1` | The `mcp` package does not import |
| `2` | `opentide mcp` without `start`, or an unknown subcommand or option |

## Source

`src/opentide/cli/mcp_app.py`, `src/opentide/mcp_server/launcher.py`, `src/opentide/mcp_server/server.py`; the Rust server, `crates/opentide-cli/src/mcp/` and `src/opentide/mcp_server/bridge.py`.
