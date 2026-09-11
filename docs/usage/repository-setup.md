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

The wizard uses arrow-key menus and checkboxes for repository metadata, platforms, CI workflow features, MCP hosts, and agent skill targets. Only the repository name is inferred from the current directory. Platforms are explicitly selected, CI starts at **Configure later**, and MCP/skills are opt-in.

Before writing, OpenTide displays the target and selected steps and asks for one confirmation. Existing destinations are therefore visible before setup updates them.

## Scripted onboarding

One-shot (parent `--platform` runs `setup platforms` before CI when `--ci` is also set):

```bash
opentide setup --yes \
  --path ./detection-repo \
  --name "SOC Detections" \
  --org "Example Corp" \
  --description "Enterprise detection content" \
  --platform sentinel \
  --platform defender_for_endpoint \
  --ci github
```

Or step-by-step:

```bash
opentide setup platforms --sentinel --defender-for-endpoint --yes
opentide setup ci github --yes
opentide setup mcp --cursor --yes
opentide setup skills --yes --generic
```

In non-interactive environments, `--yes` confirms only the flags shown in the command. It never silently selects Sentinel, VS Code, a CI provider, or a generic agent target.

## What gets created

| Subcommand | Output |
|------------|--------|
| `setup repo` | `objects/{threats,objectives,rules}/`, README, `.gitignore` |
| `setup platforms` | Enabled `.opentide/configurations/platforms/*.toml` |
| `setup ci` | GitHub / GitLab / Azure workflow files (discovers enabled platforms) |
| `setup mcp` | Editor MCP config pointing at `opentide-mcp` |
| `setup skills` | Agent skills from the live OpenTideHQ/skills catalogue (`discover`, `show`, install) |

### Expected layout after setup + generate

```
detection-repo/
├── objects/
│   ├── threats/
│   ├── objectives/
│   └── rules/
├── docs/                         # opentide generate docs output
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
opentide setup platforms --sentinel --yes
opentide setup ci github --yes
opentide setup mcp --cursor --yes
opentide setup skills discover
opentide setup skills --yes --generic --name SOC --org "Example Corp"
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
| `--cursor` | `.cursor/skills/<slug>/` |
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
