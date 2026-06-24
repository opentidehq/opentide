---
title: Repository setup
description: How opentide setup scaffolds detection repositories, CI, MCP, and agent skills.
---

# Repository setup

`opentide setup` is the primary onboarding entry point. It can run interactively or non-interactively with `--yes`.

## Interactive wizard

```bash
cd /path/to/detection-repo
opentide setup
```

The wizard walks through repository metadata, platforms, CI, MCP hosts, and agent skill targets.

## Scripted onboarding

```bash
opentide setup --yes \
  --path ./detection-repo \
  --name "SOC Detections" \
  --org "Example Corp" \
  --description "Enterprise detection content" \
  --platform sentinel \
  --platform defender_for_endpoint \
  --ci github \
  --mcp cursor \
  --skills generic
```

## What gets created

| Subcommand | Output |
|------------|--------|
| `setup repo` | `objects/{threats,objectives,rules}/`, README, `.gitignore` |
| `setup ci` | GitHub / GitLab / Azure workflow files |
| `setup mcp` | Editor MCP config pointing at `opentide-mcp` |
| `setup skills` | Agent instruction files and detection-ops skill |

### Expected layout after setup + generate

```
detection-repo/
├── objects/
│   ├── threats/
│   ├── objectives/
│   └── rules/
├── docs/                         # opentide document output
├── .opentide/
│   ├── configurations/
│   │   └── platforms/
│   ├── schemas/                  # opentide generate schemas
│   ├── templates/
│   └── exports/
├── .github/workflows/            # when --ci github
├── README.md
└── AGENTS.md                     # when --skills generic
```

Client configuration overrides live under `.opentide/configurations/`. Package defaults ship in the PyPI wheel.

## Scoped subcommands

Run individual setup steps when you only need one surface:

```bash
opentide setup repo --yes --name SOC --platform sentinel
opentide setup ci --ci github --platform sentinel
opentide setup mcp --cursor --yes
opentide setup skills --generic --yes --name SOC --org "Example Corp"
```

## MCP and skills

| MCP host flag | Config file |
|---------------|-------------|
| `--vscode` | `.vscode/mcp.json` |
| `--cursor` | `.cursor/mcp.json` |
| `--claude-code` | `.mcp.json` |
| `--generic` | `opentide.mcp.json` |

| Skills target | Output |
|---------------|--------|
| `--cursor` | `.cursor/skills/opentide-detection-ops/` |
| `--claude-code` | `CLAUDE.md`, `.claude/skills/` |
| `--generic` | `AGENTS.md`, `.agents/skills/` |
| `--github-copilot` | `.github/copilot-instructions.md` |

See [Agentic setup](./workflows/agentic-setup.md) for details.

## VS Code settings (deprecated)

`opentide setup vscode` writes yaml.schemas and snippets — interim scaffolding until the OpenTide VS Code extension ships. Prefer `opentide setup mcp --vscode` for MCP configuration.

## CLI reference

Full flag list: [CLI setup](../cli/setup.md).

## Next steps

```bash
opentide generate
opentide validate --strict
opentide setup mcp --cursor --yes   # if not done during setup
```
