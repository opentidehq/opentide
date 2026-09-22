---
title: opentide setup
description: Repository scaffolding, platform configs, CI pipelines, env files, Git hooks, MCP, agent skills, and VS Code helpers.
---

# opentide setup

Primary onboarding entry point for detection repositories.

```bash
opentide setup                              # interactive wizard
opentide setup --yes --platform sentinel --ci github
opentide setup platforms --sentinel --splunk --yes
opentide setup ci github --yes
opentide setup env --yes
opentide setup hooks --yes
```

The interactive wizard uses arrow-key menus and checkboxes for platforms, CI, MCP hosts, workflow features, and agent targets. It shows a setup plan before writing. No platform, CI provider, editor, or agent environment is selected implicitly.

The wizard needs a terminal and a stdout it can draw on, so it is incompatible with `--json`. Combining the two exits non-zero with a JSON error listing the flags to script instead; see [global options](global-options.md).

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
| `--vscode-setup` | Deprecated VS Code yaml.schemas + snippets (generate-first) |
| `--yes` / `-y` | Confirm explicit options without prompting |

Use subcommands for MCP and skills — parent `--mcp` / `--skills` enums were removed.

`--yes` never chooses a platform, MCP host, or skill target. Commands that require one fail with an actionable error when its flag is omitted.

## Subcommands

### setup repo

Scaffold directory layout, README, and `.gitignore`. `--platform` writes and enables the matching `.opentide/configurations/platforms/*.toml` files (same as `setup platforms`).

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

Generated pipelines set `OPENTIDE_REPO_ROOT` at workflow (GitHub), `variables` (GitLab), or pipeline (Azure) scope so `opentide` commands resolve the detection repository in CI. Re-run `setup ci` to refresh existing pipeline files.

```bash
opentide setup platforms --sentinel --splunk --yes
opentide setup ci github --path . --yes
opentide setup ci gitlab --no-staging
opentide setup ci azure --default-branch development --yes
```

Positional argument: `github`, `gitlab`, or `azure` (CI **provider**, not Sentinel/Splunk/etc.).

`setup ci` accepts the CI flags from the [default callback](#default-callback-flags) (`--staging`, `--inflight`, `--promotion`, `--promotion-target`, `--python-version`, `--explorer-pages`, `--path`, `--yes`) plus:

| Flag | Purpose |
|------|---------|
| `--default-branch` | Branch that triggers deploys and receives inflight shards. GitHub and Azure only; GitLab pipelines always use `$CI_DEFAULT_BRANCH` and warn that the flag is ignored |

Without `--default-branch`, GitHub and Azure pipelines target the remote's default branch (`origin/HEAD`), then the `init.defaultBranch` Git setting, then `main`. The JSON result reports the branch used as `default_branch`. A name the pipelines cannot hold unquoted (spaces, shell characters, or a value YAML reads as a number or boolean such as `2024` or `on`) is rejected with exit code 2.

### setup env

Write `.env.example` with `OPENTIDE_REPO_ROOT` (same variable as `--repo`) and add `.env` to `.gitignore` so copied secrets stay uncommitted. Existing files are left in place when they already set the variable; a missing line is appended.

```bash
opentide setup env --yes
opentide setup env ./detection-repo --yes
```

Copy `.env.example` to `.env` and adjust the path if the working directory is not the detection repository. OpenTide does not load `.env` automatically — export the variables or pass `--repo`.

### setup hooks

Configure validate-on-commit hooks. Writes `.pre-commit-config.yaml` (a local `opentide-validate` hook) and a versioned script at `.opentide/hooks/pre-commit`. When the path is inside a Git repository, copies that script into the repository's hooks directory (`.git/hooks/pre-commit`, the shared directory for a linked worktree, or a `core.hooksPath` inside the repository) unless a third-party hook is already there. A `core.hooksPath` outside the repository, such as a user-wide one, serves every repository on the machine, so setup leaves it alone and warns; call `.opentide/hooks/pre-commit` from that shared hook yourself.

```bash
opentide setup hooks --yes
opentide setup hooks ./detection-repo --yes --no-install
```

The hook runs `opentide --repo "$(git rev-parse --show-toplevel)" validate --strict`, so it always validates the worktree being committed. Pinning `--repo` matters because `OPENTIDE_REPO_ROOT` takes precedence over directory discovery: with that variable exported to another detection repository — which `.env.example` and the MCP/CI guides encourage — an unpinned hook validated the other tree and let broken YAML through.

`validate --strict` passes on a directory with no `.opentide/`, so both the hook and the pre-commit entry first check that the pinned workspace still has one. After a workspace is moved or renamed they fail and ask you to re-run `opentide setup hooks` (or bypass with `OPENTIDE_SKIP_HOOKS=1`, or `SKIP=opentide-validate` under pre-commit) instead of passing every commit.

A workspace in a subdirectory of a larger repository (for example `security/detections/` in a monorepo) is pinned by its path below the Git root: `--repo "$(git rev-parse --show-toplevel)"/security/detections`. pre-commit only reads `.pre-commit-config.yaml` at the repository root. When that file already has an `opentide-validate` hook pinned to the root (which holds no objects) or written by an older release, setup repoints it at the workspace and lists it under `files`; when it pins another workspace that still exists, setup leaves it alone and warns that pre-commit does not validate this one. When the root file has no such hook, setup warns and leaves copying it there to you.

A repository has a single Git `pre-commit` hook, so running `setup hooks` for a second workspace in the same repository adds it to the installed hook rather than replacing the first. The hook lists its workspaces on `# opentide-workspace:` lines, validates every one of them even after a failure, and blocks the commit if any fails. Re-running setup drops, with a warning, a listed workspace that no longer has `.opentide/`. The versioned copy under each workspace's `.opentide/hooks/` validates that workspace only.

Set `OPENTIDE_SKIP_HOOKS=1` to bypass the hook for a single commit. Existing `.pre-commit-config.yaml` files keep other repos; the OpenTide hook is appended when missing, and an `entry:` written by an older release is refreshed in place.

### setup mcp

Write MCP server configuration for editors.

```bash
opentide setup mcp --cursor --vscode --yes
```

| Flag | Output file | `OPENTIDE_REPO_ROOT` |
|------|-------------|----------------------|
| `--vscode` | `.vscode/mcp.json` | `${workspaceFolder}` |
| `--cursor` | `.cursor/mcp.json` | `${workspaceFolder}` |
| `--claude-code` | `.mcp.json` | `${CLAUDE_PROJECT_DIR}` |
| `--generic` | `opentide.mcp.json` | omitted (cwd discovery) |

VS Code and Cursor expand `${workspaceFolder}`. Claude Code expands `${CLAUDE_PROJECT_DIR}`. Generic hosts that do not interpolate editor placeholders should omit the variable so the server discovers the git root from cwd, or set an absolute path. See [MCP configuration](../mcp/configuration.md).

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

JSON output includes `manifest_source` (`remote`) and `manifest_refreshed` when using `--refresh`. Discovery always fetches the live `manifest.json`; there is no packaged catalogue snapshot.

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

Catalogue discovery fetches `manifest.json` from [OpenTideHQ/skills](https://github.com/OpenTideHQ/skills) on `main`. Default install pulls the starter slugs (`opentide-detection-rule`, `detection-engineering`) from that catalogue; `--install` / `--all` select other live entries. GitHub must be reachable — the wheel does not ship skill trees that can go stale.

The full wizard checks skill availability before writing repository files. If the catalogue or a requested slug cannot be fetched, the standalone skills command fails without installing a partial tree. The full `opentide setup` wizard omits the skills step with a warning so the rest of the scaffold can still apply.

### setup vscode (deprecated)

Interim yaml.schemas and snippet generation. By default the command generates templates and JSON schemas into `.opentide/`, then writes settings and snippets. A missing target path is created first so generate-first setup does not `chdir` into a nonexistent directory. Deprecation is logged once per invocation.

`yaml.schemas` maps each object folder to its concrete schema (`threat.1.0.schema.json` → `objects/threats/**/*.yaml`, and the same for objectives and rules). Nested files under those folders stay associated; it does not map the `opentide.schema.json` router against `objects/**/*.yaml` — the Red Hat YAML extension reports "Matches multiple schemas" for that glob.

```bash
opentide setup vscode                 # generate templates + schemas, then settings + snippets
opentide setup vscode --mcp          # same, plus .vscode/mcp.json via write_mcp_config
opentide setup vscode --settings    # generate schemas, then settings
opentide setup vscode --snippets     # generate templates, then snippets
opentide setup vscode --no-generate  # skip generate (power users)
opentide setup mcp --vscode          # MCP only (unchanged multi-host path)
```

If snippets were requested and templates are still missing after generate, the command exits non-zero (`status: failed`) instead of reporting success.

| Flag | Purpose |
|------|---------|
| `--settings` | Write `.vscode/settings.json` yaml.schemas and `.vscode/extensions.json` (generates schemas first) |
| `--snippets` | Write model template snippets (generates templates first) |
| `--no-merge` | Replace settings instead of merging |
| `--no-generate` | Do not run `opentide generate` phases first |
| `--mcp` | Write `.vscode/mcp.json` by calling `write_mcp_config` (opt-in; parent `--vscode-setup` does not imply this) |

## CI skip

Pass `--ci none` on the default callback to skip CI file generation while still running repo or VS Code steps in the same invocation.

## Non-interactive use

Interactive setup requires a TTY. In CI or an agent subprocess, provide explicit targets and `--yes`; OpenTide fails immediately rather than waiting for hidden input.

## Source

`src/opentide/cli/setup_app.py`

## Usage guide

Human-oriented walkthrough: [Repository setup](../usage/repository-setup.md)
