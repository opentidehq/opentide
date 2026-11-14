---
name: mcp-server
description: Change opentide's MCP server (`opentide mcp start`, crates/opentide-cli/src/mcp/) — add or modify a tool or resource, keep the stdio JSON-RPC stream clean, return errors as data, keep docs/mcp/ in sync, and test it against the recorded sessions and over stdio. Use for any work on MCP tools, resources or the server manifest.
---

# MCP server — opentide

`opentide mcp start` serves the detection catalogue over MCP stdio from the Rust command line,
on rmcp, the official Rust MCP SDK (UC-3.7, #829; UC-6.0c). The Python server it replaced was
removed with the Python implementation (UC-6.2, #841); its recorded sessions
(`tests/golden/mcp/*.jsonl`) are the oracle the Rust server is replayed against.

## Layout

| File | Role |
|------|------|
| `crates/opentide-cli/src/mcp/server.rs` | The rmcp server: the tools and resources it lists, from the manifest |
| `crates/opentide-cli/data/mcp/manifest.json` | The server's name, instructions, tools (descriptions and schemas), resources and templates: the MCP shapes, a plan §3 invariant. The description of each tool is what the client's model reads — keep it short and exact |
| `crates/opentide-cli/src/mcp/tools.rs`, `args.rs` | The tools, and how their arguments are checked and refused |
| `crates/opentide-cli/src/mcp/resources.rs`, `catalog.rs` | `opentide://…` resources; search, chaining and coverage over the workspace |
| `crates/opentide-cli/src/mcp/queries.rs`, `deploy.rs`, `plugin.rs` | `validate_query`, `run_query`, `deploy_rule`, and plugin platforms |

## Rules

- **Never write to stdout.** stdout is the JSON-RPC stream; the server reserves descriptor 1
  for it, and logging goes to stderr.
- **Errors are data.** An unknown UUID, an unsupported platform or a failed check returns a
  result with an `error`/`supported: false` field; a refused argument is `isError` in
  opentide's words.
- **No filesystem paths as inputs.** Tools take UUIDs, names and platform identifiers and
  resolve them in the workspace, so a client cannot read or write outside it.
- **Capabilities are honest.** CrowdStrike, HarfangLab, Sysdig and Bitdefender cannot validate
  queries on a tenant, and Sysdig and Bitdefender run no `opentide query`: return
  `supported: False`, never a fake pass. The registry (`opentide_schema::platforms`) says which
  platform can do what ([`AGENTS.md`](../../../AGENTS.md#platforms)); read it, never a list of names. `run_query` and `validate_query` contact
  a tenant only with `live: true`. `deploy_rule` defaults to `dry_run=True`.
- **Freshness.** The server is long-lived. Anything answering "is this valid now?" must see
  the files on disk, not the index from start-up.
- Resource templates are matched as RFC 6570: a simple `{name}` does not admit reserved
  characters such as `&`. Use `{+name}` when a value can hold one (`att&ck` vocabularies).

## Adding or changing a tool

1. Describe it in the manifest and implement it in `tools.rs`, with Rust tests beside it.
2. `cargo xtask mcp replay --engine rust tests/golden/mcp/*.jsonl` must pass: a difference from
   the recorded Python answers needs an `APPROVED_DIFFS.toml` entry (command `mcp start`, case
   `<session>/<step>`), with its reason, issue and changelog entry ([golden](../golden/SKILL.md)).
   A tool the recordings do not cover adds a session to `sessions.toml`; its recording comes from
   `cargo xtask mcp record --python PATH` against a release that has the Python server, or the
   new tool is held by Rust tests and `tests/test_mcp/e2e/` alone.
3. Extend `tests/test_mcp/e2e/test_mcp_stdio_e2e.py` when the wire shape matters.
4. Document it in `docs/mcp/tools.md` (or `resources.md`), keeping the existing section shape,
   and run `scripts/validate-docs.sh`.

## Related

- [`cli-e2e-testing`](../cli-e2e-testing/SKILL.md) — the `tide_corpus` fixture workspace
- [`docs-maintenance`](../docs-maintenance/SKILL.md) — MCP tab of the docs
- [`review-checklist`](../review-checklist/SKILL.md)
