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

Before writing, opentide displays the target and selected steps and asks for one confirmation. Existing destinations are therefore visible before setup updates them.

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
opentide setup env --yes
opentide setup hooks --yes
opentide setup mcp --cursor --yes
opentide setup skills --yes --generic
```

In non-interactive environments, `--yes` confirms only the flags shown in the command. It never silently selects Sentinel, VS Code, a CI provider, or a generic agent target.

## What gets created

| Subcommand | Output |
|------------|--------|
| `setup repo` | `objects/{threats,objectives,rules}/`, README, `.gitignore`; `--platform` also writes enabled platform TOML |
| `setup platforms` | Enabled `.opentide/configurations/platforms/*.toml` |
| `setup ci` | GitHub / GitLab / Azure workflow files (discovers enabled platforms; sets `OPENTIDE_REPO_ROOT`). A share stage is written only with `--sharing` |
| `setup env` | `.env.example` with `OPENTIDE_REPO_ROOT`; ignores `.env` |
| `setup hooks` | `.pre-commit-config.yaml` plus validate-on-commit Git hook |
| `setup mcp` | Editor MCP config that runs `opentide mcp start` |
| `setup skills` | Agent skills: by default `opentide-detection-rule`, from the package, and `detection-engineering`, from the catalogue (the package's copy when it cannot be downloaded); `--install <slug>` or `--all` for others, each the full opentidehq/skills tree (`discover`, `show`, install) |

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
│   ├── templates/                # opentide generate templates
│   ├── exports/                  # opentide generate exports
│   ├── inflight/                 # opentide generate inflight
│   ├── lsp/                      # the language server's catalogs
│   └── hooks/                    # when setup hooks
├── .vscode/                      # the editor snippets (generate)
├── .github/workflows/            # when --ci github
├── .pre-commit-config.yaml       # when setup hooks
├── .env.example                  # when setup env
├── README.md
└── AGENTS.md                     # when --skills generic
```

`.opentide/states/` is not created by setup or generate: `opentide deploy` writes `states/deployment/` (vendor rule ids, committed) the first time a platform returns one, and `opentide share` writes `states/sharing.jsonl` (gitignored).

Client configuration overrides live under `.opentide/configurations/`. The defaults are compiled into opentide.

## Scoped subcommands

Run individual setup steps when you only need one surface:

```bash
opentide setup repo --yes --name SOC --platform sentinel
opentide setup platforms --sentinel --yes
opentide setup ci github --yes
opentide setup env --yes
opentide setup hooks --yes
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
| `--cursor` | `.cursor/skills/<slug>/` (and `.agents/skills/detection-engineering/`) |
| `--claude-code` | `CLAUDE.md`, `.claude/skills/` |
| `--generic` | `AGENTS.md`, `.agents/skills/` |
| `--github-copilot` | `.github/copilot-instructions.md`, and `AGENTS.md` and `.agents/skills/` as `--generic` |

See [Agentic setup](./workflows/agentic-setup.md) for details.

## VS Code settings (deprecated)

`opentide setup vscode` generates templates and JSON schemas, recommends the opentide VS Code extension (`opentidehq.opentide`) in `.vscode/extensions.json`, and writes snippets. It writes no `yaml.schemas`, and removes the router mapping earlier releases wrote to `.vscode/settings.json`: the extension's language server checks object files. Pass `--mcp` to also write `.vscode/mcp.json` via the same helper as `opentide setup mcp --vscode`. Both paths are valid; parent `--vscode-setup` does not imply MCP. A missing target directory is created before generate. Pass `--no-generate` to skip generation when artifacts already exist. The command fails if snippets were requested but could not be written.

## CLI reference

Full flag list: [CLI setup](../cli/setup.md).

## Next steps

```bash
opentide generate
opentide validate --strict
opentide setup mcp --cursor --yes   # if not done during setup
```

`generate` writes `.opentide/templates/*.template.yaml` from the Tide models compiled into opentide (required keys live, optional fields commented with `#` hugging each key, no YAML `null`). The `metadata` keys that [`opentide lint`](../cli/lint.md#configuration) requires, `author` and `organisation` by default, are live too. Copy a template into `objects/` or use the `tide-threat` / `tide-objective` / `tide-rule` VS Code snippets.
