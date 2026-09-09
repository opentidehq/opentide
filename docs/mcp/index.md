---
title: MCP server
description: OpenTide MCP server — search, validate, deploy, and query detection content from AI agents and editors.
icon: Bot
---

# MCP server

The OpenTide MCP server exposes catalogue search, validation, deployment, and read-only resources to AI agents and editor integrations.

## Quick start

```bash
pip install 'opentide==0.1.0'
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide setup mcp --cursor --yes
```

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
| Validate query syntax | `validate_query` |
| Run read-only query | `run_query` (capped at 100 rows) |
| Deploy (dry-run default) | `deploy_rule` |
| Deployment state | `deployment_status` |
| Read schemas, templates, vocab | `opentide://*` resources |

> **Stub tools:** `validate_query` and `run_query` are placeholders — they do not parse queries or execute live platform queries yet. Use CLI `opentide validate query` for real syntax validation.

## Server instructions

The server advertises this purpose to MCP hosts:

> Detection engineering assistant. Search and analyse detection content, validate rules and queries, test queries against live platforms, and deploy detection rules.

<Callout type="warn">
That description states the server's **intended** scope. Today, query-related capabilities are not fully implemented: `validate_query` and `run_query` are stubs (see below), so "validate queries" and "test queries against live platforms" do not yet work through MCP. For real query-syntax validation, use the CLI `opentide validate query`. Search, object validation (`validate_rule` / `validation_report`), chaining, coverage, and dry-run deploy are fully functional.
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
