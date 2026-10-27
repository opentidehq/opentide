---
title: MCP server
description: opentide MCP server — search, validate, deploy, and query detection content from AI agents and editors.
icon: Bot
---

# MCP server

The opentide MCP server exposes catalogue search, validation, deployment, and read-only resources to AI agents and editor integrations.

## Quick start

```bash
pip install 'opentide==0.18.0'
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide setup mcp --cursor --yes
```

`pip install opentide` is all it takes — `mcp` is a base dependency since 0.14.0. See [Installation](./installation.md).

Start manually:

```bash
opentide mcp start
```

`opentide mcp` with no subcommand prints help and exits. The process blocks until the host closes stdin. Stop is that close. Reload is the host spawning `opentide mcp start` again.

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

Then they give the agent its workflow: search (`search`, `coverage`, `get_chaining`); draft from `opentide://templates/{object_type}` and write the file itself, since the server writes none; call `validation_report` after every edit, applying each issue's `fix` and reading `explain(code)`, until `ok` is `true`; preview with `deploy_rule` and `dry_run: true`. People review and merge, and run real deployments. They also say that `validate_query` and `run_query` with `live: true` contact the tenant, so the agent asks first, and how to read [`next_actions`](./tools.md#next-actions). The text is `INSTRUCTIONS` in `src/opentide/mcp_server/server.py`.

<Callout type="warn">
`validate_query` refuses unless you pass `live: true`. That call checks the
catalogue rules for the platform against the tenant. It does not scan the
`query` argument. A missing SDK or a missing plan is a failed live check.
`run_query` refuses the same way until `live: true`, then runs a read-only
query on the named tenants and returns their rows. Everything else (search, `validate_rule` / `validation_report`,
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

`src/opentide/mcp_server/server.py`, `src/opentide/mcp_server/tools.py`, `src/opentide/mcp_server/resources.py`
