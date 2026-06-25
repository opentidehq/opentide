---
title: opentide setup
description: Repository scaffolding, platform configs, CI pipelines, MCP, agent skills, and VS Code helpers.
---

# opentide setup

Primary onboarding entry point for detection repositories.

```bash
opentide setup                              # interactive wizard
opentide setup --yes --platform sentinel --ci github
opentide setup platforms --sentinel --splunk --yes
opentide setup ci github --yes
```

## Default callback flags

| Flag | Purpose |
|------|---------|
| `--path` / `-C` | Repository directory (default `.`; honours `--repo` when `.`) |
| `--name`, `--org`, `--description` | README metadata |
| `--platform` | Detection platforms — runs the `setup platforms` step when set (repeatable) |
| `--ci` | `github`, `gitlab`, `azure`, or `none` |
| `--staging` / `--no-staging` | CI staging stage (default: on) |
| `--promotion` / `--no-promotion` | CI promotion stage (default: on; promotion runs in deploy) |
| `--promotion-target` | Promotion target status (default `PRODUCTION`) |
| `--python-version` | CI Python version (default `3.12`) |
| `--vscode-setup` | Deprecated VS Code yaml.schemas + snippets |
| `--yes` / `-y` | Non-interactive mode |

Use subcommands for MCP and skills — parent `--mcp` / `--skills` enums were removed.

## Subcommands

### setup repo

Scaffold directory layout, README, and `.gitignore`.

```bash
opentide setup repo --yes --name SOC --platform sentinel
```

### setup platforms

Create and enable platform configuration templates under `.opentide/configurations/platforms/`.

```bash
opentide setup platforms --sentinel --defender-for-endpoint --yes
```

| Flag | Platform |
|------|----------|
| `--sentinel` | Microsoft Sentinel |
| `--splunk` | Splunk |
| `--crowdstrike` | CrowdStrike |
| `--defender-for-endpoint` | Microsoft Defender for Endpoint |
| `--sentinel-one` | SentinelOne |
| `--carbon-black-cloud` | Carbon Black Cloud |
| `--harfanglab` | HarfangLab |

### setup ci

Generate CI/CD pipeline files. **CI provider** is the positional argument (`github`, `gitlab`, or `azure`). Detection platforms are **not** passed here — they are discovered from enabled `.opentide/configurations/platforms/*.toml` files written by `setup platforms`.

Run `setup platforms` before `setup ci` so `validate query` jobs are included. If none are enabled, `setup ci` still writes the pipeline and returns a `warnings` entry in JSON mode.

```bash
opentide setup platforms --sentinel --splunk --yes
opentide setup ci github --path . --yes
opentide setup ci gitlab --no-staging
```

Positional argument: `github`, `gitlab`, or `azure` (CI **provider**, not Sentinel/Splunk/etc.).

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

Install detection engineering agent skills from [OpenTideHQ/skills](https://github.com/OpenTideHQ/skills).

<Steps>

<Step>

### Discover the catalogue

```bash
opentide setup skills discover
opentide setup skills discover --query kql
opentide setup skills show opentide-detection-rule
```

</Step>

<Step>

### Install starter or selected skills

```bash
opentide setup skills --yes --generic
opentide setup skills --yes --install opentide-detection-rule --install detection-engineering
opentide setup skills --yes --all --cursor
```

Place flags **before** the optional `[PATH]` argument: `opentide setup skills --yes .`

</Step>

</Steps>

| Flag | Purpose |
|------|---------|
| `--cursor` / `--claude-code` / `--generic` / `--github-copilot` | Target harness layouts |
| `--install` | Skill slug (repeatable) |
| `--all` | Install full bundled catalogue |
| `--name`, `--org`, `--description` | Entrypoint metadata |

Offline browse uses the bundled manifest; `--refresh` on `discover` / `show` fetches the latest catalogue from GitHub.

### setup vscode (deprecated)

Interim yaml.schemas and snippet generation. Default with no flags: both settings and snippets.

```bash
opentide setup vscode --settings --no-merge
opentide setup vscode --snippets
```

| Flag | Purpose |
|------|---------|
| `--settings` | Write `.vscode/settings.json` yaml.schemas |
| `--snippets` | Write model template snippets |
| `--no-merge` | Replace settings instead of merging |

## CI skip

Pass `--ci none` on the default callback to skip CI file generation while still running repo or VS Code steps in the same invocation.

## Source

`src/opentide/cli/setup_app.py`

## Usage guide

Human-oriented walkthrough: [Repository setup](../usage/repository-setup.md)
