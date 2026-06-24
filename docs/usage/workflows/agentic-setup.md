---
title: Agentic setup
description: Configure MCP servers and agent skills so AI assistants work safely with detection content.
---

# Agentic setup

OpenTide ships first-class scaffolding for AI agents: an MCP server for catalogue access and validation, plus portable agent skills.

## MCP server

Install the MCP extra and configure your editor:

```bash
pip install "opentide[mcp,cli]>=0.1"
opentide setup mcp --cursor --yes
```

This writes `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "opentide": {
      "command": "opentide-mcp"
    }
  }
}
```

The server uses **stdio transport**. Set `OPENTIDE_REPO_ROOT` in the MCP host environment so the catalogue resolves correctly.

### Supported hosts

| Host | Setup flag | Config path |
|------|------------|-------------|
| VS Code | `--vscode` | `.vscode/mcp.json` |
| Cursor | `--cursor` | `.cursor/mcp.json` |
| Claude Code | `--claude-code` | `.mcp.json` |
| Generic | `--generic` | `opentide.mcp.json` |

Full tool and resource reference: [MCP documentation](../../mcp/index.md).

## Agent skills

```bash
opentide setup skills --generic --yes \
  --name "SOC Detections" \
  --org "Example Corp" \
  --description "Enterprise MDR content"
```

| Target | Files created |
|--------|---------------|
| `--generic` | `AGENTS.md`, `.agents/skills/opentide-detection-ops/SKILL.md` |
| `--cursor` | `.cursor/skills/opentide-detection-ops/` |
| `--claude-code` | `CLAUDE.md`, `.claude/skills/` |
| `--github-copilot` | `.github/copilot-instructions.md` |

The bundled **detection-ops** skill documents object layout, core commands, platform matrix, and the validate-before-deploy rule.

## Recommended agent workflow

1. **Search** catalogue with MCP `search` (keyword, UUID, ATT&CK technique).
2. **Validate** with `validate_rule` or `validation_report` before suggesting edits.
3. **Dry-run deploy** with `deploy_rule` (`dry_run=true` by default).
4. Never claim query validation passed for CrowdStrike or HarfangLab.

## Repository agent guide

After `setup skills --generic`, point agents at `AGENTS.md` at the repo root. Package contributors use the richer guide at [`AGENTS.md`](https://github.com/OpenTideHQ/opentide/blob/development/AGENTS.md) in the opentide repository.

## Skills in this repo

The opentide package repo maintains domain skills under [`.agents/skills/`](https://github.com/OpenTideHQ/opentide/tree/development/.agents/skills/) for VCS, testing, CI, and documentation maintenance.

When adding CLI or MCP surface area, update:

- Client skill template: `src/opentide/data/setup/skills/detection-ops/SKILL.md`
- [MCP tools](../../mcp/tools.md) and [CLI](../../cli/index.md) reference pages
