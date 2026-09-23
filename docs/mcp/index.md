---
title: MCP server
description: OpenTide MCP server — search, validate, deploy, and query detection content from AI agents and editors.
icon: Bot
---

# MCP server

The OpenTide MCP server exposes catalogue search, validation, deployment, and read-only resources to AI agents and editor integrations.

## Quick start

```bash
pip install 'opentide[mcp]==0.6.1'
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide setup mcp --cursor --yes
```

The `mcp` extra is required — see [Installation](./installation.md).

Start manually:

```bash
opentide-mcp
```

Transport: **stdio** (standard MCP over stdin/stdout).

## What agents can do

| Capability | Tool / resource |
|------------|-----------------|
| Search catalogue | `search` |
| Threat → objective → rule graph | `get_chaining` |
| ATT&CK coverage gaps | `coverage` |
| Validate a rule | `validate_rule`, `validation_report` |
| Check query syntax offline | `validate_query` |
| Run read-only query | `run_query` — **not implemented** |
| Deploy (dry-run default) | `deploy_rule` |
| Deployment state | `deployment_status` |
| Read schemas, templates, vocab | `opentide://*` resources |

## Server instructions

The server advertises this purpose to MCP hosts:

> Detection engineering assistant. Search and analyse detection content, validate rules against their schema, check platform query syntax offline, and dry-run rule deployment. Query execution against live platforms is not implemented: run_query never contacts a tenant and never returns rows.

<Callout type="warn">
`validate_query` is a structural check, not a grammar: it catches unbalanced
delimiters, unterminated strings, broken pipelines, and dangling operators, but
it cannot tell you whether a table or field exists. `run_query` returns
`stub: true` and `rows: null` — it never contacted a platform. Everything else
(search, `validate_rule` / `validation_report`, chaining, coverage, dry-run
deploy) is fully functional.
</Callout>

## Documentation map

| Page | Content |
|------|---------|
| [Installation](./installation.md) | PyPI extra and host requirements |
| [Configuration](./configuration.md) | Editor config files and environment |
| [Tools](./tools.md) | Tool parameters and response shapes |
| [Resources](./resources.md) | URI catalogue and JSON payloads |

## Usage guide

Human-oriented agent setup: [Agentic setup](../usage/workflows/agentic-setup.md)

## Source

`src/opentide/mcp_server/server.py`, `src/opentide/mcp_server/tools.py`, `src/opentide/mcp_server/resources.py`
