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

The interactive wizard opens with the opentide logo and the tagline (the one-line pill in a terminal narrower than 82 columns, and no mark with `--no-color` or `NO_COLOR`), then uses arrow-key menus and checkboxes for platforms, CI, MCP hosts, workflow features, and agent targets. An empty repository name is refused on screen. It shows a setup plan before writing. No platform, CI provider, editor, or agent environment is selected implicitly.

Every `setup` command, scripted or interactive, ends the same way: the files it wrote, its warnings (each once), one outcome line, and numbered next steps when it created a repository:

```text illustrative
  objects/{threats,objectives,rules}/                your detection catalogue
  README.md                                          quick start
  .gitignore                                         files git leaves out
  .opentide/configurations/platforms/sentinel.toml   platform configuration
  .github/workflows/opentide.yml                     GitHub Actions pipeline

warning: This folder is not a git repository yet, so the pipeline targets 'main'; create it on that branch with 'git init -b main', or write the pipeline for another one with 'opentide setup ci <provider> --default-branch <branch>'.
✓ Created Tutorial Detections in ./tutorial-detections

Next steps
  1  cd tutorial-detections
  2  opentide generate · schemas, templates and editor snippets
  3  opentide validate · check every object before you commit
```

This is `opentide setup --yes --name "Tutorial Detections" --platform sentinel --ci github --path tutorial-detections` outside a git repository; it is not captured by the docs harness, which runs no `setup`. `--json` returns the same facts: the outcome under `message`, each step's `files`, and the next steps under `next_actions`.

The wizard needs a terminal and a stdout it can draw on, so it is incompatible with `--json`. Combining the two exits non-zero with a JSON error listing the flags to script instead; see [global options](global-options.md).

## Default callback flags

| Flag | Purpose |
|------|---------|
| `--path` / `-C` | Repository directory. The default `.` is the working directory; an explicit `--repo` replaces `.` |
| `--name`, `--org`, `--description` | README metadata |
| `--platform` | Detection platforms — runs the `setup platforms` step when set (repeatable) |
| `--ci` | `github`, `gitlab`, `azure`, or `none` |
| `--staging` / `--no-staging` | CI staging stage (default: on) |
| `--inflight` / `--no-inflight` | Update pull-request preview shards (default: on) |
| `--sharing` / `--no-sharing` | Share changed objects on the default branch (default: off) |
| `--promotion` / `--no-promotion` | Status promotion in `opentide deploy`. Omit the flag to keep the repository's setting; `--no-promotion` writes `[promotion] enabled = false` (see [setup ci](#setup-ci)) |
| `--explorer-pages` / `--no-explorer-pages` | Include GitHub Pages explorer jobs |
| `--promotion-target` | Status `deploy` promotes rules to. Omit the flag to keep the repository's setting; another status is written as `[promotion] promotion_target` |
| `--python-version` | CI Python version (default `3.12`) |
| `--default-branch` | Branch that deploys and receives inflight shards (see [setup ci](#setup-ci)) |
| `--vscode-setup` | Deprecated VS Code yaml.schemas + snippets (generate-first) |
| `--yes` / `-y` | Confirm explicit options without prompting |

Use subcommands for MCP and skills — parent `--mcp` / `--skills` enums were removed.

`--path` / `-C` and `--yes` / `-y` work on **every** `setup` subcommand (`repo`, `platforms`, `ci`, `env`, `hooks`, `mcp`, `skills`, `vscode`). A positional `PATH` is still accepted as a hidden alias on the subcommands that historically required it; passing both forms in one invocation is a usage error. `setup vscode` accepts `--yes` for symmetry — it writes editor-local files and never prompts.

Given before the subcommand, `--path` and `--yes` still apply to it: `opentide setup --path ./detection-repo --yes hooks` is the same as `opentide setup hooks --path ./detection-repo --yes`. Naming two different paths (`setup --path a env --path b`) is a usage error. Any other `setup` option placed before a subcommand (`opentide setup --ci github env`) is also a usage error, because the subcommand would ignore it.

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
| `--elastic` | Elastic Security |

### setup ci

Generate CI/CD pipeline files. **CI provider** is the positional argument (`github`, `gitlab`, or `azure`). Detection platforms are **not** passed here — they are discovered from enabled `.opentide/configurations/platforms/*.toml` files written by `setup platforms`.

Run `setup platforms` before `setup ci` so `validate query` jobs are included. If none are enabled, `setup ci` still writes the pipeline and prints a `WARNING` line (a `warnings` entry in JSON mode).

Generated pipelines set `OPENTIDE_REPO_ROOT` at workflow (GitHub), `variables` (GitLab), or pipeline (Azure) scope so `opentide` commands resolve the detection repository in CI. Re-run `setup ci` to refresh existing pipeline files.

The validate job runs `opentide validate --strict` and `opentide lint --strict`, each writing its findings as a report under `opentide-reports/`: SARIF on GitHub (kept as an artifact, and sent to code scanning on a public repository by a `code_scanning` job that holds only `security-events: write`) and Azure (the `CodeAnalysisLogs` artifact), Code Quality on GitLab (`artifacts:reports:codequality`). Annotations and job summaries need no step; see [CI/CD](../usage/workflows/ci-cd.md#annotations-summaries-and-reports). Each enabled platform that supports query validation also runs `opentide validate query --live --changed`, which checks only the rule files the run's pull request, merge request or push changed (see [validate](./validate.md#which-rules-are-checked)), and skips that step when any required credential for the platform is unset. GitHub runs those checks in the validate job. GitLab and Azure run one job per platform in that stage, and generate does not start until they succeed. CrowdStrike and HarfangLab have no query job. Live query validation and the staging deploy first replace the repository root's `.opentide/configurations` with the default branch's copy, so a pull request cannot send a credential to a tenant it added or changed there. A platform with no tenant there yet skips its live query step with exit 0; see [CI/CD](../usage/workflows/ci-cd.md#tenant-configuration-on-pull-requests). The staging job runs a dry-run and then `opentide deploy --strategy PREVIEW --skip-unconfigured`; the production job does the same with `--strategy RELEASE` ([Statuses, strategies and tenants](../usage/concepts/statuses-and-strategies.md#the-two-generated-jobs)). `--skip-unconfigured` exits 0 when every platform with rules to deploy still has the commented-out `[[tenants]]` block `setup` writes. A `RELEASE` run also disables or deletes changed rules whose status maps to `DISABLEMENT` or `DELETION`. The production job then commits what the deploy wrote back (promoted rule statuses and `.opentide/states/deployment/`) to the default branch with a `[skip ci]` message, also after a deploy that failed part way; see [CI/CD](../usage/workflows/ci-cd.md#production-write-back). The file header lists the credential variables from the bundled platform files. GitHub deploy jobs map each of those names to `secrets.<NAME>`. The GitLab file sets `workflow:rules` so pipelines run for merge requests and the default branch, which every job needs to run in a merge request pipeline. Proxies and private certificate authorities are runner settings, not part of the generated file; see [CI/CD](../usage/workflows/ci-cd.md#behind-a-proxy-or-a-private-ca).

The Azure pipeline sets `pool.vmImage` to `ubuntu-latest` and triggers on every branch so a topic-branch push still validates. `pr:` is kept for Azure Pipelines hosted on GitHub or Bitbucket. Azure Repos Git ignores `pr:`; add a build validation policy on the default branch so a pull request sets `Build.Reason` to `PullRequest`. Staging deploy stays gated on that reason.

```bash
opentide setup platforms --sentinel --splunk --yes
opentide setup ci github --path . --yes
opentide setup ci gitlab --no-staging
opentide setup ci azure --default-branch development --yes
opentide setup --ci azure --default-branch development --yes
```

Positional argument: `github`, `gitlab`, or `azure` (CI **provider**, not Sentinel/Splunk/etc.).

`setup ci` accepts the same CI flags as the [default callback](#default-callback-flags) (`--staging`, `--inflight`, `--sharing`, `--promotion`, `--promotion-target`, `--python-version`, `--explorer-pages`, `--default-branch`, `--path`, `--yes`), so `opentide setup --ci github --default-branch trunk --yes` and `opentide setup ci github --default-branch trunk --yes` write the same pipeline and print the same `WARNING` lines. The one-shot JSON result lists each step's warnings under `steps[].warnings` and again in the top-level `warnings`.

`--sharing` adds one job, `share`, that runs `opentide share push --changed` on a push to the default branch, after the production deploy job and on a checkout of the default branch's tip, so the rules that deploy promoted are shared in the same run ([sharing in CI](../usage/workflows/ci-cd.md)). It runs after a failed deploy too, and a share failure does not affect deploy. The flag does not write `sharing.toml` and does not ask for a URL, API key, or block name. The wizard checkbox is "Sharing on the default branch", and it stays unchecked. `--sharing` with `--ci none`, or with no `--ci`, warns and writes no pipeline. A later `setup ci` that leaves the flag off removes the job when it rewrites the pipeline.

`--default-branch` names the branch that triggers deploys and receives inflight shards. It applies to GitHub and Azure; GitLab pipelines always use `$CI_DEFAULT_BRANCH` and warn that the flag is ignored.

Without `--default-branch`, GitHub and Azure pipelines target the first of:

1. the remote's default branch (`origin/HEAD`, set by `git clone`);
2. the checked-out branch, so a repository created with `git init -b trunk` targets `trunk`;
3. the `init.defaultBranch` Git setting, for a target outside any Git repository or on a detached `HEAD`;
4. `main`.

The JSON result reports the branch used as `default_branch`. It adds a `warnings` entry, and logs a warning, when the pipeline falls back to a `main` branch the repository does not have, or targets the checked-out branch while other local branches exist. Pass `--default-branch` in either case. A name the pipelines cannot hold unquoted (spaces, shell characters, or a value YAML reads as a number or boolean such as `2024` or `on`) is rejected with exit code 2.

The pipeline has no promotion job: `opentide deploy --strategy RELEASE` promotes rules as the merged `deployment.toml` [configures](../usage/configuration.md#promotion). Omitting the flags keeps that setting. An explicit flag writes the `[promotion]` table of `.opentide/configurations/deployment.toml` when the value differs from the bundled default and the file has no `[promotion]` table yet, and the result lists that file under `files`. The same flags on `opentide setup` without `--ci` write that table too:

```bash
opentide setup --yes --no-promotion                           # same table, no CI pipeline
opentide setup ci github --no-promotion --yes                 # [promotion] enabled = false
opentide setup ci github --promotion-target ACCEPTANCE --yes  # [promotion] promotion_target = "ACCEPTANCE"
```

- Omitting `--promotion` and `--promotion-target` changes nothing, including a table a previous run wrote.
- An explicit value that matches the bundled default writes nothing on a repository that has no `[promotion]` table.
- `--promotion-target` must name a status of the repository's merged `deployment.toml`; any other value exits with code 2 before a file is written.
- An existing `deployment.toml` without a `[promotion]` table keeps its content; the table is appended. If it already has a `[promotion]` table and an explicit flag disagrees with it, setup exits with code 2 and leaves the file for you to edit, because rewriting it would drop its comments.

### setup env

Write `.env.example` with `OPENTIDE_REPO_ROOT` (same variable as `--repo`) and add `.env` to `.gitignore` so copied secrets stay uncommitted. Existing files are left in place when they already set the variable; a missing line is appended.

```bash
opentide setup env --yes
opentide setup env --path ./detection-repo --yes
```

Copy `.env.example` to `.env` and adjust the path if the working directory is not the detection repository. opentide does not load `.env` automatically — export the variables or pass `--repo`.

### setup hooks

Configure validate-on-commit hooks. Writes `.pre-commit-config.yaml` (a local `opentide-validate` hook) and a versioned script at `.opentide/hooks/pre-commit`. When the path is inside a Git repository, copies that script into the repository's hooks directory (`.git/hooks/pre-commit`, the shared directory for a linked worktree, or a `core.hooksPath` inside the repository) unless a third-party hook is already there. A `core.hooksPath` outside the repository, such as a user-wide one, serves every repository on the machine, so setup leaves it alone and warns; call `.opentide/hooks/pre-commit` from that shared hook yourself.

```bash
opentide setup hooks --yes
opentide setup hooks --path ./detection-repo --yes --no-install
```

The hook runs `opentide --repo "$(git rev-parse --show-toplevel)" validate --strict`, so it always validates the worktree being committed. Pinning `--repo` matters because `OPENTIDE_REPO_ROOT` takes precedence over directory discovery: with that variable exported to another detection repository — which `.env.example` and the MCP/CI guides encourage — an unpinned hook validated the other tree and let broken YAML through.

`validate --strict` passes on a directory with no `.opentide/`, so both the hook and the pre-commit entry first check that the pinned workspace still has one. After a workspace is moved or renamed they fail and ask you to re-run `opentide setup hooks` (or bypass with `OPENTIDE_SKIP_HOOKS=1`, or `SKIP=opentide-validate` under pre-commit) instead of passing every commit.

A workspace in a subdirectory of a larger repository (for example `security/detections/` in a monorepo) is pinned by its path below the Git root: `--repo "$(git rev-parse --show-toplevel)"/security/detections`. pre-commit only reads `.pre-commit-config.yaml` at the repository root. When that file already has an `opentide-validate` hook pinned to the root (which holds no objects) or written by an older release, setup repoints it at the workspace and lists it under `files`; when it pins another workspace that still exists, setup leaves it alone and warns that pre-commit does not validate this one. When the root file has no such hook, setup warns and leaves copying it there to you.

A repository has a single Git `pre-commit` hook, so running `setup hooks` for a second workspace in the same repository adds it to the installed hook rather than replacing the first. The hook lists its workspaces on `# opentide-workspace:` lines, validates every one of them even after a failure, and blocks the commit if any fails. Re-running setup drops, with a warning, a listed workspace that no longer has `.opentide/`. The versioned copy under each workspace's `.opentide/hooks/` validates that workspace only.

Set `OPENTIDE_SKIP_HOOKS=1` to bypass the hook for a single commit. Existing `.pre-commit-config.yaml` files keep other repos; the opentide hook is appended when missing, and an `entry:` written by an older release is refreshed in place.

### setup mcp

Write MCP server configuration for editors. Each file runs `opentide mcp start`. The editor owns that process: closing stdin stops it, and spawning the command again reloads it.

```bash
opentide setup mcp --cursor --vscode --yes
```

| Flag | Output file | `OPENTIDE_REPO_ROOT` |
|------|-------------|----------------------|
| `--vscode` | `.vscode/mcp.json` | `${workspaceFolder}` |
| `--cursor` | `.cursor/mcp.json` | `${workspaceFolder}` |
| `--claude-code` | `.mcp.json` | `${CLAUDE_PROJECT_DIR}` |
| `--generic` | `opentide.mcp.json` | omitted (cwd discovery) |

VS Code and Cursor expand `${workspaceFolder}`. Claude Code expands `${CLAUDE_PROJECT_DIR}`. Generic hosts that do not interpolate editor placeholders should omit the variable so the server discovers the detection workspace from cwd, or set an absolute path. See [MCP configuration](../mcp/configuration.md).

### setup skills

Install detection engineering agent skills from [opentidehq/skills](https://github.com/opentidehq/skills).

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

`discover` prints a table of the skills, each description cut at a word boundary to about 80 characters (`setup skills show <slug>` prints all of it), then one outcome line. The sample is illustrative because the counts come from the live catalogue:

```text illustrative
✓ 31 skills available · 2 installed · opentidehq/skills@main
```

With `--query`, the line counts the matches (`3 skills match 'kql'`); `--installed` keeps the skills under `.agents/skills/`. JSON output has `skills`, `count`, `source`, `manifest_source` (`remote`) and `manifest_refreshed`, and `summary` gives `skills` and `installed`. Discovery always fetches the live `manifest.json`; there is no packaged catalogue snapshot.

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
| `--cursor` | Copy the skills to `.cursor/skills/` |
| `--claude-code` | Write `CLAUDE.md` and copy the skills to `.claude/skills/` |
| `--generic` | Write `AGENTS.md` for any agent that reads `.agents/skills/` |
| `--github-copilot` | Write `.github/copilot-instructions.md`, and `AGENTS.md` as `--generic` does |
| `--install` | Skill slug to install (repeatable); default: `opentide-detection-rule` and `detection-engineering` |
| `--all` | Install every skill in the catalogue |
| `--name`, `--org`, `--description` | Heading (default: the folder name), organisation and opening paragraph of the agent files |
| `--yes` / `-y` | Install without asking |
| `--query` / `-q` | `discover`: keep skills whose name, slug or description holds the text |
| `--installed` | `discover`: keep only the skills installed in `.agents/skills/` |
| `--refresh` | `discover` / `show`: fetch `manifest.json` again rather than reuse the in-process copy from the last 30 seconds; each CLI run fetches it once anyway |

Catalogue discovery fetches `manifest.json` from [opentidehq/skills](https://github.com/opentidehq/skills) on `main`. `AGENTS.md` is rendered from the package template and is not copied from that repository. `opentide-detection-rule`, `opentide-detection-objective`, `opentide-threat-vector`, and `detection-engineering` are installed from the package. Other slugs, including those selected with `--install` or `--all`, are the full GitHub tree under `skills/<slug>/`. A truncated or unreadable tree fails that skill instead of installing a partial copy.

The full wizard checks skill availability before writing repository files. If the catalogue or a requested slug cannot be fetched, the standalone skills command fails without installing a partial tree. The full `opentide setup` wizard omits the skills step with a warning so the rest of the scaffold can still apply.

### setup vscode (deprecated)

Interim yaml.schemas and snippet generation. By default the command generates templates and JSON schemas into `.opentide/`, then writes settings and snippets. A missing target path is created first so generate-first setup does not `chdir` into a nonexistent directory. Deprecation is logged once per invocation.

`yaml.schemas` maps `objects/**/*.yaml` to the `.opentide/schemas/opentide.schema.json` router. The glob is the common parent of the configured object folders; when they share none, each folder gets its own recursive glob. The router validates each object against the revision schema named in its `metadata.schema`, so `rule::1.0` and `rule::1.1` rules can sit in the same folder. See [Schema revision](../usage/concepts/schema-revision.md).

When merging into an existing `settings.json`, the command removes the per-folder revision mappings earlier releases wrote (for example `.opentide/schemas/rule.1.0.schema.json` → `objects/rules/**/*.yaml`). Other settings and other `yaml.schemas` entries are kept.

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
| `--no-merge` | Replace `settings.json` and `extensions.json` instead of merging |
| `--no-generate` | Do not run `opentide generate` phases first |
| `--mcp` | Write `.vscode/mcp.json` by calling `write_mcp_config` (opt-in; parent `--vscode-setup` does not imply this) |

## CI skip

Pass `--ci none` on the default callback to skip CI file generation while still running repo or VS Code steps in the same invocation.

## Non-interactive use

Interactive setup requires a TTY. In CI or an agent subprocess, provide explicit targets and `--yes`; opentide fails immediately rather than waiting for hidden input.

## Source

`src/opentide/cli/setup_app.py`

## Usage guide

Human-oriented walkthrough: [Repository setup](../usage/repository-setup.md)
