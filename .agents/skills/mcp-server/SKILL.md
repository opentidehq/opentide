---
name: mcp-server
description: Change opentide's MCP server (`opentide mcp start`, src/opentide/mcp_server/) — add or modify a tool or resource, keep the stdio JSON-RPC stream clean, return errors as data, keep docs/mcp/ in sync, and test it in-process and over stdio. Use for any work on MCP tools, resources, the launcher or the mcp dependency.
---

# MCP server — opentide

`opentide mcp start` serves the detection catalogue over MCP stdio, built on the `mcp` 1.x
SDK's `FastMCP`. `mcp` is pinned `<2`: 2.x moved FastMCP (`mcp.server.fastmcp` became a stub),
and the migration is tracked in #581. `launcher.py` turns a missing or wrong-major `mcp` into
one install hint before any JSON-RPC is written.

## Layout

| File | Role |
|------|------|
| `mcp_server/server.py` | Thin `@mcp.tool()` / `@mcp.resource()` wrappers. The docstring of each wrapper is what the client's model reads — keep it short and exact. |
| `mcp_server/tools.py` | `tool_*` implementations: plain functions returning JSON-serialisable `dict`/`list`, unit-testable without a server. |
| `mcp_server/resources.py` | `opentide://…` resource bodies. |
| `mcp_server/catalog.py` | Search, chaining, coverage over the registry (`ensure_initialised()`). |
| `mcp_server/constants.py` | Limits and the platforms that support query validation. |

## Rules

- **Never write to stdout.** stdout is the JSON-RPC stream; one stray `print()` or Rich
  console line corrupts the session. Logging goes to stderr (`opentide.core.logging`).
- **Errors are data.** An unknown UUID, an unsupported platform or a failed check returns a
  dict with an `error`/`supported: false` field; raise only for programming errors.
- **No filesystem paths as inputs.** Tools take UUIDs, names and platform identifiers and
  resolve them through the registry, so a client cannot read or write outside the workspace.
- **Capabilities are honest.** CrowdStrike and HarfangLab cannot validate queries
  (`can_validate is False`): return `supported: False`, never a fake pass. `run_query` never
  contacts a tenant. `deploy_rule` defaults to `dry_run=True`.
- **Freshness.** The server is long-lived. Anything answering "is this valid now?" must see
  the files on disk, not the index from start-up; resources may serve the start-up snapshot
  as documented in `docs/mcp/resources.md`.
- Tool signatures use plain types (`str`, `bool`, `int`) with defaults; FastMCP builds the
  JSON schema from them.

## Adding or changing a tool

1. Implement `tool_<name>` in `tools.py` (typed, returns plain data).
2. Add the `@mcp.tool()` wrapper in `server.py` with a one-paragraph docstring.
3. Tests: unit tests in `tests/test_mcp/` against the `tide_corpus` fixture, and extend
   `tests/test_mcp/e2e/test_mcp_stdio_e2e.py` when the wire shape matters.
4. Document it in `docs/mcp/tools.md` (or `resources.md`), keeping the existing section shape,
   and run `scripts/validate-docs.sh`.

## Related

- [`cli-e2e-testing`](../cli-e2e-testing/SKILL.md) — the `tide_corpus` fixture workspace
- [`docs-maintenance`](../docs-maintenance/SKILL.md) — MCP tab of the docs
- [`review-checklist`](../review-checklist/SKILL.md)
