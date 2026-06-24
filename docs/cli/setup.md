---
title: opentide setup
description: Repository scaffolding, CI pipelines, MCP configuration, and agent skills installation.
---

# opentide setup

Primary onboarding entry point for detection repositories.

```bash
opentide setup                              # interactive wizard
opentide setup --yes --platform sentinel --ci github
```

## Default callback flags

| Flag | Purpose |
|------|---------|
| `--path` / `-C` | Repository directory (default `.`; honours `--repo` when `.`) |
| `--name`, `--org`, `--description` | README metadata |
| `--platform` | Detection platforms (repeatable): `sentinel`, `splunk`, `crowdstrike`, `defender_for_endpoint`, `sentinel_one`, `carbon_black_cloud`, `harfanglab` |
| `--ci` | `github`, `gitlab`, `azure`, or `none` |
| `--staging` / `--no-staging` | CI staging stage (default: on) |
| `--promotion` / `--no-promotion` | CI promotion stage (default: on) |
| `--promotion-target` | Promotion target status (default `PRODUCTION`) |
| `--python-version` | CI Python version (default `3.12`) |
| `--mcp` | MCP hosts (repeatable): `vscode`, `cursor`, `claude-code`, `generic` |
| `--skills` | Agent targets (repeatable): `cursor`, `claude-code`, `generic`, `github-copilot` |
| `--vscode-setup` | Deprecated VS Code yaml.schemas + snippets |
| `--yes` / `-y` | Non-interactive mode |

## Subcommands

### setup repo

Scaffold directory layout, README, and `.gitignore`.

```bash
opentide setup repo --yes --name SOC --platform sentinel
```

### setup ci

Generate CI/CD pipeline files.

```bash
opentide setup ci --ci github --platform sentinel --yes
```

### setup mcp

Write MCP server configuration for editors.

```bash
opentide setup mcp --cursor --vscode --yes
```

| Flag | Output file |
|------|-------------|
| `--vscode` | `.vscode/mcp.json` |
| `--cursor` | `.cursor/mcp.json` |
| `--claude-code` | `.mcp.json` |
| `--generic` | `opentide.mcp.json` |

### setup skills

Install detection engineering agent skills.

```bash
opentide setup skills --generic --github-copilot --yes \
  --name SOC --org "Example Corp"
```

### setup vscode (deprecated)

Interim yaml.schemas and snippet generation. Prefer the future OpenTide VS Code extension and `setup mcp --vscode` for MCP.

```bash
opentide setup vscode settings
opentide setup vscode snippets
opentide setup vscode all
```

| Flag | Purpose |
|------|---------|
| `--no-merge` | Replace `.vscode/settings.json` instead of merging (`settings` / `all` only) |

## CI skip

Pass `--ci none` on the default callback to skip CI file generation while still running repo, MCP, or skills steps in the same invocation.

## Source

`src/opentide/cli/setup_app.py`

## Usage guide

Human-oriented walkthrough: [Repository setup](../usage/repository-setup.md)
