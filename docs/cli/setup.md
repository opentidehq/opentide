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

The interactive wizard uses arrow-key menus and checkboxes for platforms, CI, MCP hosts, workflow features, and agent targets. It shows a setup plan before writing. No platform, CI provider, editor, or agent environment is selected implicitly.

## Default callback flags

| Flag | Purpose |
|------|---------|
| `--path` / `-C` | Repository directory (default `.`; honours `--repo` when `.`) |
| `--name`, `--org`, `--description` | README metadata |
| `--platform` | Detection platforms — runs the `setup platforms` step when set (repeatable) |
| `--ci` | `github`, `gitlab`, `azure`, or `none` |
| `--staging` / `--no-staging` | CI staging stage (default: on) |
| `--inflight` / `--no-inflight` | Update pull-request preview shards (default: on) |
| `--promotion` / `--no-promotion` | CI promotion stage (default: on; promotion runs in deploy) |
| `--explorer-pages` / `--no-explorer-pages` | Include GitHub Pages explorer jobs |
| `--promotion-target` | Promotion target status (default `PRODUCTION`) |
| `--python-version` | CI Python version (default `3.12`) |
| `--vscode-setup` | Deprecated VS Code yaml.schemas + snippets |
| `--yes` / `-y` | Confirm explicit options without prompting |

Use subcommands for MCP and skills — parent `--mcp` / `--skills` enums were removed.

`--yes` never chooses a platform, MCP host, or skill target. Commands that require one fail with an actionable error when its flag is omitted.

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
opentide setup skills discover --path /path/to/repo
opentide setup skills show opentide-detection-rule
opentide setup skills show opentide-detection-rule --path /path/to/repo
```

JSON output includes `manifest_source` (`remote` or `bundled`) and `manifest_refreshed` when using `--refresh`.

</Step>

<Step>

### Install starter or selected skills

```bash
opentide setup skills --yes --generic
opentide setup skills --yes --install opentide-detection-rule --install detection-engineering
opentide setup skills --yes --all --cursor
opentide setup skills --yes --generic --path /path/to/repo
```

Use `--path` / `-C` for the repository root on install, `discover`, and `show`. Do not pass a positional path to `opentide setup skills` itself — Click would treat `discover` / `show` as that path and skip the subcommands.

Installing `--github-copilot` without `--generic` also applies the generic layout; JSON output includes `"also_applied": ["generic"]`.

</Step>

</Steps>

| Flag | Purpose |
|------|---------|
| `--path` / `-C` | Repository path (install, discover, show) |
| `--cursor` / `--claude-code` / `--generic` / `--github-copilot` | Target harness layouts |
| `--install` | Skill slug (repeatable) |
| `--all` | Install full catalogue |
| `--name`, `--org`, `--description` | Entrypoint metadata |
| `--refresh` | Re-fetch `manifest.json` from GitHub (`discover` / `show`) |

Catalogue discovery fetches `manifest.json` from [OpenTideHQ/skills](https://github.com/OpenTideHQ/skills) first; the packaged manifest is an offline fallback. Starter skills (`opentide-detection-rule`, `detection-engineering`) are also packaged so install works when GitHub is unreachable. Other catalogue slugs still require network access.

The full wizard checks skill availability before writing repository files. Starter skills stay available from the package; remote-only slugs are omitted with a warning. The standalone skills command fails without leaving a partial skill tree when a requested slug cannot be fetched and is not packaged.

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

## Non-interactive use

Interactive setup requires a TTY. In CI or an agent subprocess, provide explicit targets and `--yes`; OpenTide fails immediately rather than waiting for hidden input.

## Source

`src/opentide/cli/setup_app.py`

## Usage guide

Human-oriented walkthrough: [Repository setup](../usage/repository-setup.md)
