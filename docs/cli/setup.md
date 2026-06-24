# Setup CLI

`opentide setup` is the primary onboarding entry point for detection repositories.

## Default callback

```bash
opentide setup                    # interactive wizard
opentide setup --path ./repo --yes --name SOC --platform sentinel --ci github
opentide setup --yes --mcp vscode --mcp cursor
opentide setup --yes --skills generic --skills github-copilot
```

Use `--path` / `-C` for the repository directory on the default callback. Subcommands accept an optional positional `[path]` argument.

### Flags

| Flag | Purpose |
|------|---------|
| `--name`, `--org`, `--description` | README metadata |
| `--platform` | Detection platforms (repeatable) |
| `--ci` | `github`, `gitlab`, `azure`, or `none` |
| `--staging`, `--promotion`, `--promotion-target` | CI behaviour |
| `--python-version` | CI Python version (default `3.12`) |
| `--mcp` | MCP hosts: `vscode`, `cursor`, `claude-code`, `generic` (repeatable) |
| `--skills` | Agent targets: `cursor`, `claude-code`, `generic`, `github-copilot` (repeatable) |
| `--vscode-setup` | Deprecated interim VS Code yaml.schemas + snippets |
| `--yes` / `-y` | Non-interactive mode |

## Scoped subcommands

| Command | Purpose |
|---------|---------|
| `opentide setup repo` | Directory scaffold + README + `.gitignore` |
| `opentide setup ci` | GitHub / GitLab / Azure pipeline files |
| `opentide setup mcp` | MCP config for editors and agents |
| `opentide setup skills` | Agent skills and instruction files |
| `opentide setup vscode` | **Deprecated** — use OpenTide VS Code extension when available |

### MCP hosts

| Flag | Output |
|------|--------|
| `--vscode` | `.vscode/mcp.json` |
| `--cursor` | `.cursor/mcp.json` |
| `--claude-code` | `.mcp.json` |
| `--generic` | `opentide.mcp.json` |

### Skills targets

| Flag | Output |
|------|--------|
| `--cursor` | `.cursor/skills/opentide-detection-ops/` |
| `--claude-code` | `CLAUDE.md`, `.claude/skills/` |
| `--generic` | `AGENTS.md`, `.agents/skills/` |
| `--github-copilot` | `.github/copilot-instructions.md` |

## VS Code deprecation

`opentide setup vscode` (settings, snippets, all) is interim scaffolding until the **OpenTide VS Code extension** ships with a bundled language server and template actions. MCP configuration belongs under `opentide setup mcp --vscode`, not `setup vscode`.

## Workflow

```bash
opentide setup --yes --name "SOC Detections" --platform sentinel --ci github
opentide generate
opentide setup vscode settings   # deprecated; prefer extension when available
```
