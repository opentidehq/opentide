---
title: MCP server
description: opentide MCP server — search, validate, deploy, and query detection content from AI agents and editors.
icon: Bot
---

# MCP server

The opentide MCP server exposes catalogue search, validation, deployment, and read-only resources to AI agents and editor integrations.

## Quick start

```bash
pip install 'opentide==1.1.0'
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide setup mcp --cursor --yes
```

`pip install opentide` is all it takes: the server is compiled into the package. See [Installation](./installation.md).

Start manually:

```bash
opentide mcp start
```

`opentide mcp` with no subcommand names `start` and exits `2` ([`opentide mcp`](../cli/mcp.md)). The process blocks until the host closes stdin. Stop is that close. Reload is the host spawning `opentide mcp start` again.

Tool calls and resource reads run one at a time, in the order they arrive, but the server keeps reading while one runs: it answers `ping`, `tools/list` and the other lists at once. `notifications/cancelled` for a running call stops it as Ctrl-C stops a command: its tenant requests are dropped, the call sends no answer (as MCP has it), and the next call runs normally. A call that reaches no tenant (`validate_rule`, `validation_report`, `search`, a resource read, …) does not stop: it runs to its end and its answer is dropped, and the next call waits until it has finished. A call still running when the host closes stdin is stopped the same way.

Transport: **stdio** (standard MCP over stdin/stdout).

## What agents can do

| Capability | Tool / resource |
|------------|-----------------|
| Search catalogue | `search` |
| Threat → objective → rule graph | `get_chaining` |
| ATT&CK coverage gaps | `coverage` |
| Validate a rule, with positions and fixes | `validate_rule`, `validation_report` |
| What a diagnostic code means | `explain` |
| Check queries against the tenant | `validate_query` with `live: true` |
| Run a read-only query, get rows | `run_query` with `live: true` |
| Deploy (dry-run default) | `deploy_rule` |
| Deployment state | `deployment_status` |
| Read schemas, templates, vocab | `opentide://*` resources |

## Server instructions

The server sends `instructions` to MCP hosts with its `initialize` response. They open with:

> opentide: Spec-driven development for agentic detection engineering. opentide gives every detection an ontology and a taxonomy, so it stays threat-aligned, maintainable and fast to ship, with or without agents.

Then they give the agent its workflow: search (`search`, `coverage`, `get_chaining`); draft from `opentide://templates/{object_type}` and write the file itself, since the server writes none; call `validation_report` after every edit, applying each issue's `fix` and reading `explain(code)`, until `ok` is `true`; preview with `deploy_rule` and `dry_run: true`. People review and merge, and run real deployments. They also say that `validate_query` and `run_query` with `live: true` contact the tenant, so the agent asks first, and how to read [`next_actions`](./tools.md#next-actions). The text is the server manifest's `instructions` (`crates/opentide-cli/data/mcp/manifest.json`).

<Callout type="warn">
`validate_query` checks the `query` argument offline, with the engine
compiled into opentide, on every platform but SentinelOne. With `live: true` it
checks the catalogue rules for the platform against the tenant instead, and
does not scan the `query` argument. A missing plan or an unreachable tenant is
a failed live check. `run_query` refuses until `live: true`, then runs a
read-only query on the named tenants and returns their rows. Everything else (search, `validate_rule` / `validation_report`,
chaining, coverage, dry-run deploy) is fully functional.
</Callout>

## Documentation map

| Page | Content |
|------|---------|
| [Installation](./installation.md) | PyPI install and host requirements |
| [Configuration](./configuration.md) | Editor config files and environment |
| [Tools](./tools.md) | Tool parameters and response shapes |
| [Resources](./resources.md) | URI catalogue and JSON payloads |

## Usage guide

Human-oriented agent setup: [Agentic setup](../usage/workflows/agentic-setup.md)

## Source

`crates/opentide-cli/src/mcp/server.rs`, `crates/opentide-cli/src/mcp/tools.rs`, `crates/opentide-cli/src/mcp/resources.rs`
