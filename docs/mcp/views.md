---
title: Interactive views
description: The MCP Apps views opentide's MCP server serves (the detection graph, coverage, validation and lineage) and the hosts that render them.
---

# Interactive views

`graph`, `coverage`, `validation_report` and `get_chaining` each name an interactive page that a host
supporting [MCP Apps](https://modelcontextprotocol.io/extensions/apps/overview) renders next
to the tool's result. A host without MCP Apps shows the result as text, as before; the tools
return exactly the same data either way.

| Tool | View (`_meta.ui.resourceUri`) | What it shows |
|------|-------------------------------|---------------|
| `graph` | `ui://opentide/graph.html` | The [detection graph](#detection-graph): the whole catalogue, its attack paths and its portfolio. |
| `coverage` | `ui://opentide/coverage.html` | The ATT&CK matrix of the bundled release, tactic by tactic: techniques coloured by the number of rules that cover them, gaps included. Select a technique for its sub-techniques and rules (own or inherited). With `technique`, that technique's rules. |
| `validation_report` | `ui://opentide/validation-report.html` | Issues grouped by file, filtered by severity, with position, field path, help and the proposed fix. **Explain** shows the code's `explain` page in place; **Re-validate** runs the report again with the same arguments. |
| `get_chaining` | `ui://opentide/lineage.html` | Threats → objectives → rules, with titles and statuses. Select any object to follow its lineage. |

On hosts that accept messages from a view, **Ask Claude to fix** (an issue) and **Ask Claude
to plan a detection** (a gap) put a prompt in the conversation; the host may ask you first.

## Detection graph

The `graph` view loads the full graph itself (`graph` with `detail: "full"`), so the model's
context only holds the summary. It has three tabs.

- **Graph.** Actors → threats → objectives → rules → platforms, as columns joined by their
  links. Threats run in attack-path order, with `threat.chaining` drawn as arrows beside them.
  A rule's colour is its best status: production, staging, other. A threat or objective that
  no rule reaches has a dashed outline. Point at or select any object to light up its lineage
  (what it comes from and what detects it, not its siblings) and its chained threats. The side
  panel shows the object's details. For a rule it can run **Validate** and **Where is it
  deployed?**, through `validation_report` and `deployment_status`. Filter by text, actor,
  ATT&CK tactic, platform or status, or show the gaps only. An objective with four or more
  rules shows them as one node until you open it.
- **Attack paths.** Threats joined by `preceeds` and `succeeds`, earliest first. Each step says
  whether a rule in production would see it, sees it only outside production, or is blind.
  Other relations (`implements`, `enabling`, …) are listed on the step. **Ask Claude to close
  the gaps** sends the blind steps to the conversation.
- **Portfolio.** How many threats have an objective, a rule, and a rule in production. Each
  platform's rules by status. A technique × platform table of rules (defence in depth). The
  lists of threats and objectives that no rule reaches.

In a host that offers it, **Full screen** opens the view in full-screen display mode.

## Hosts

MCP Apps renders in Claude (Desktop, web, Cowork), ChatGPT, VS Code with Copilot, Cursor and
Goose. opentide's server is local (stdio), so of Claude's apps only **Claude Desktop** shows
the views, with the server added to its configuration:

```json
{
  "mcpServers": {
    "opentide": {
      "command": "opentide",
      "args": ["mcp", "start"],
      "env": { "OPENTIDE_REPO_ROOT": "/path/to/detection-repo" }
    }
  }
}
```

Claude Code and other text-only hosts call the same tools and read their JSON.

## How the views work

The three views are one self-contained page, `src/opentide/mcp_server/views/view.html`,
served at a `ui://` URI per view with the `text/html;profile=mcp-app` MIME type
(`src/opentide/mcp_server/ui.py`). The host renders it in a sandboxed iframe and passes it the
tool's arguments and result over `postMessage` (JSON-RPC, MCP Apps `2026-01-26`).

- **Nothing loads from the network.** Styles and script are inline, and the coverage page
  carries the bundled ATT&CK matrix, so the default MCP Apps content security policy, which
  blocks every origin, is all the views need. They declare no `csp` domains.
- **Every call goes through the host.** To show titles, a view calls `search` once; Explain,
  Re-validate and following a lineage call `explain`, `validation_report` and `get_chaining`;
  the detection graph calls `graph`, `validation_report` and `deployment_status`. They are the read-only tools an agent calls, under the same approval rules. A view never
  calls `run_query`, `validate_query` or `deploy_rule`.
- **Catalogue text is never HTML.** Titles, messages and help are set as text, and the ATT&CK
  data embedded in the page is escaped so that no string can end its `<script>` element.
- **Theme.** The page uses the host's theme and style variables when it passes them, and its
  own light and dark palette otherwise.

The server lists the views among its resources (`resources/list`). The server-side
`extensions` capability only exists from MCP protocol 2026-07-28; hosts find the views from
each tool's `_meta`, which every protocol version carries.
