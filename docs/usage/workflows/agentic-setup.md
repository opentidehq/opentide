---
title: Agentic setup
description: Configure MCP servers and agent skills so AI assistants work safely with detection content — with an example session and its limits.
---

# Agentic setup

opentide exposes the engine to AI agents through an [MCP server](../../mcp/index.md) and portable agent skills, so an assistant in your editor can search the catalogue, validate objects, and preview deploys. This page sets it up, shows a realistic session, and is honest about what agents can and cannot do today.

## What agents can and cannot do today

<Callout type="warn">
`validate_query` checks the `query` argument offline with the analysis engine (KQL, SPL, ES|QL, EQL, Kibana KQL, Lucene): it proves the query parses in its platform's language and names slow shapes, not that it returns rows. `live: true` checks the catalogue rules against the tenant, not the argument; SentinelOne queries are checked that way only. A missing SDK is a failed live check. `run_query` refuses until you pass `live: true`; then it runs a read-only query on the tenants you name and returns the rows, as the [query command](../../cli/query.md) does. Both live calls use the configured credentials, so the agent should ask first. Use `validation_report` for structured object validation an agent can act on.
</Callout>

| Capability | Status |
|-----------|--------|
| Search catalogue, read objects, inspect chaining | Supported |
| Validate objects (`validate_rule`, `validation_report`), with positions, fixes and next actions | Supported |
| Explain a diagnostic code (`explain`, or `opentide explain <code>`) | Supported |
| List every CLI command and option (`opentide --json commands`) | Supported |
| Dry-run deploy (`deploy_rule`, `dry_run=true`) | Supported |
| Offline query check via MCP (`validate_query`) | Supported — the `query` string, in its platform's language; not SentinelOne |
| Tenant query check via MCP (`validate_query`, `live: true`) | Supported — catalogue rules, not the `query` string |
| Language server for the editor (`opentide lsp start`) | Supported — diagnostics, hover and completion for objects and queries |
| Read-only query on a tenant via MCP (`run_query`, `live: true`) | Supported — every platform; rows capped by `limit` |

## Install and configure the server

```bash
pip install 'opentide==0.18.0'
opentide setup mcp --cursor --yes
```

This writes `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "opentide": {
      "command": "opentide",
      "args": ["mcp", "start"],
      "env": { "OPENTIDE_REPO_ROOT": "${workspaceFolder}" }
    }
  }
}
```

The server uses **stdio transport**. It must know where your content lives, so set `OPENTIDE_REPO_ROOT` in the host environment (as above). If the server fails to start, see [MCP configuration](../../mcp/configuration.md).

### Supported hosts

| Host | Setup flag | Config path | `OPENTIDE_REPO_ROOT` |
|------|------------|-------------|----------------------|
| VS Code | `--vscode` | `.vscode/mcp.json` (`servers`, not `mcpServers`) | `${workspaceFolder}` |
| Cursor | `--cursor` | `.cursor/mcp.json` | `${workspaceFolder}` |
| Claude Code | `--claude-code` | `.mcp.json` | `${CLAUDE_PROJECT_DIR}` |
| Generic | `--generic` | `opentide.mcp.json` | omitted (cwd discovery) |

## Install agent skills

Skills give the agent durable, project-specific instructions (object layout, commands, the validate-before-deploy rule):

Browse the catalogue with `discover` and `show`. Those commands read the live `manifest.json` from [opentidehq/skills](https://github.com/opentidehq/skills). If that catalogue cannot be fetched, the command fails with an actionable error. `AGENTS.md` is rendered from the package template. The four authoring skills are copied from the package. Every other skill is the full tree under `skills/<slug>/`, including its reference files; an unreadable or truncated tree fails the install instead of writing a partial skill.

```bash
opentide setup skills discover
opentide setup skills discover --query sentinel
opentide setup skills show opentide-detection-rule

opentide setup skills --yes --generic \
  --name "SOC Detections" \
  --org "Example Corp" \
  --description "Enterprise detection content"

opentide setup skills --yes --install opentide-detection-rule --install detection-engineering
```

| Target | Files created |
|--------|---------------|
| `--generic` | `AGENTS.md`, `.agents/skills/<slug>/SKILL.md` |
| `--cursor` | `.cursor/skills/<slug>/` copies |
| `--claude-code` | `CLAUDE.md`, `.claude/skills/` |
| `--github-copilot` | `.github/copilot-instructions.md` (also applies `--generic` unless already selected) |

After setup, point your agent at the generated `AGENTS.md` at the repo root — it is rendered from the package template for this repository, not copied from the skills catalogue.

### What the instruction files tell an agent

`AGENTS.md`, `CLAUDE.md`, `.github/copilot-instructions.md` and the bundled skills teach an agent with a shell the same contract the [CLI reference](../../cli/index.md#coding-agents) describes:

- Run `opentide --json <command>`; stdout is one JSON document. `opentide --json commands` lists every command, option and an example.
- Branch on the exit code first, then read `failure.code` for the detail, for example `issues_found`, `usage_invalid_choice` or `no_tenant_reached`.
- Apply each finding's `fix` (`safe: true` edits only respell the same word; check the others against `help`), and run `opentide explain <code>` for a finding without one.
- Follow `next_actions`.
- Work in a loop: search, draft, validate until clean, preview the deployment with `--dry-run`. People review and merge the change, and run real deployments.

An agent connected through MCP gets the same workflow from the server's `instructions`, and the same fields from `validation_report`.

`opentide-detection-rule`, `opentide-detection-objective`, `opentide-threat-vector`, and `detection-engineering` are installed from the package so they match `rule::1.0`, `objective::1.0`, and `threat::1.0` under `objects/`. Other skills are downloaded as the full tree under `skills/<slug>/` from opentidehq/skills.

## A safe agent workflow

Give agents this loop. It searches, validates until clean, and only ever *previews* deploys. People review and merge the change, and run real deployments. The MCP server's `instructions` and the generated `AGENTS.md` describe the same loop.

```mermaid
flowchart LR
  search["search()<br/>find relevant objects"] --> read["read object + get_chaining()"]
  read --> edit["draft or edit YAML"]
  edit --> validate["validation_report()"]
  validate -->|ok| dryrun["deploy_rule(dry_run=true)"]
  validate -->|"issues: apply fix, explain(code)"| edit
  dryrun --> human["a person reviews and merges"]
```

### Example session

> **You:** Add a rule for T1059 credential access on Sentinel.
>
> **Agent:** `search(query="T1059")` → finds the *Credential Access* objective `…8002…0001`.
> `get_chaining(uuid="…8002…0001")` → confirms it covers the *Simulated Actor* threat and has no rule yet.
> Writes `objects/rules/sentinel-t1059.yaml` from `opentide://templates/rule`, with `detection_model` pointing at the objective.
> `validation_report(file="objects/rules/sentinel-t1059.yaml")` → one `vocab_unknown` issue at line 8, column 8: `tlp: clearr`, with a `fix` replacing it with `clear`. The fix is not `safe` (another spelling, not only another case), so the agent checks it against `help`: `did you mean 'clear'?`.
> Applies the edit. `validation_report(file=…)` → `ok: true`.
> Runs `opentide validate query --platform sentinel --live --file objects/rules/sentinel-t1059.yaml` (CLI), which checks that one rule's query against the tenant.
> `deploy_rule(uuid=…, platform="sentinel", dry_run=true)` → shows the planned change.
>
> **You:** review the diff, merge it, then deploy for real.

## Safe vs unsafe edit patterns

**Safe — let agents do these**

- Search, read, and summarise objects and coverage.
- Draft new objects from templates, filling required fields.
- Run `validation_report` and surface concrete errors.
- Apply the `fix` edits the validator returns, and fix the dangling references and vocabulary violations it flags.
- Preview deploys with `dry_run=true`.

**Unsafe — keep a human in the loop**

- Real (non-dry-run) deploys to production.
- Bulk promotion of rules to `PRODUCTION` without an explicit human status change and review.
- Editing `.opentide/configurations/` credentials or tenant strategies.
- Trusting an MCP `validate_query` "pass" as proof a query runs — offline it only proves the query parses.
- Regenerating or hand-editing UUIDs to resolve a conflict.

## Recommended guardrails in AGENTS.md

The generated `AGENTS.md` already tells the agent to validate until clean and to deploy only with `--dry-run`. Add rules like these for your own policies:

```md
- Always run `validation_report` (or `opentide --json validate --file …`) until it is
  clean before proposing a rule as done.
- Check each query you write with `validate_query` (offline) before proposing the rule;
  `validate_query` with `live: true` checks the catalogue rules against the tenant.
  Never report a rule as platform-ready on its result alone.
- Ask before `run_query` with `live: true`: it queries a tenant with real credentials.
- Never claim query validation for CrowdStrike or HarfangLab — they are deploy-only.
- Deploys are `dry_run=true` unless a human explicitly approves a real deploy.
```

## Reference

- [MCP tools](../../mcp/tools.md) and [resources](../../mcp/resources.md) — the full agent surface.
- [MCP configuration](../../mcp/configuration.md) — multi-repo, deploy safety, host specifics.
- [Detection-as-code](./detection-as-code.md) — the human loop agents assist with.
