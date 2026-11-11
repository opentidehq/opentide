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
opentide setup --plan --platform sentinel --ci github --mcp vscode --hooks --env
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
| `--lint-changed` / `--lint-all` | Gate `opentide lint` on the object files each run changed, or on every file (default) |
| `--promotion` / `--no-promotion` | Status promotion in `opentide deploy`. Omit the flag to keep the repository's setting; `--no-promotion` writes `[promotion] enabled = false` (see [setup ci](#setup-ci)) |
| `--explorer-pages` / `--no-explorer-pages` | Include GitHub Pages explorer jobs |
| `--promotion-target` | Status `deploy` promotes rules to. Omit the flag to keep the repository's setting; another status is written as `[promotion] promotion_target` |
| `--python-version` | CI Python version (default `3.12`) |
| `--default-branch` | Branch that deploys and receives inflight shards (see [setup ci](#setup-ci)) |
| `--vscode-setup` | Deprecated `setup vscode`: recommend the opentide extension, write snippets (generate-first) |
| `--mcp` | MCP configuration for `vscode`, `cursor`, `claude-code` or `generic` (repeatable): the [setup mcp](#setup-mcp) step |
| `--skills` | Agent skills for `claude-code`, `cursor`, `github-copilot` or `generic` (repeatable): the [setup skills](#setup-skills) step, with its default skills |
| `--plugin` | Register the opentidehq/skills Agent Plugin for Claude Code, as `setup skills --plugin` |
| `--hooks` | Validate-on-commit hooks: the [setup hooks](#setup-hooks) step |
| `--env` | `.env.example` and the `.env` ignore rule: the [setup env](#setup-env) step |
| `--plan` | List the files each step would write, and write nothing (see [Plan before you write](#plan-before-you-write)) |
| `--yes` / `-y` | Confirm explicit options without prompting |

With `--mcp`, `--skills`, `--plugin`, `--hooks` and `--env`, every question the wizard asks has a flag, so the whole wizard is one non-interactive command:

```bash
opentide setup --yes --name "Detections" --platform sentinel --ci github \
  --mcp vscode --skills generic --hooks --env
```

The steps run in this order: `repo`, `platforms`, `ci`, `env`, `hooks`, `mcp`, `skills`, `vscode`. Like `--ci`, the new flags do not scaffold the repository on their own: `opentide setup --yes --hooks` configures the hooks only, and adding `--name`, `--org`, `--description` or `--platform` scaffolds it too.

## Plan before you write

`--plan` lists the files each step would write and writes nothing. It works on `setup` and on every subcommand (`setup repo --plan`, `setup mcp --cursor --plan`, …), and given before a subcommand it applies to it, as `--path` and `--yes` do. A plan never prompts, so it needs no `--yes`, but it needs the same choices a scripted run needs: `setup mcp --plan` without a host exits `2`, as `setup mcp --yes` does.

```bash
opentide --json setup --plan --name "Tutorial Detections" --org "Example Corp" \
  --platform sentinel --path ./tutorial-detections
```

```json illustrative
{
  "plan": true,
  "path": "/home/me/tutorial-detections",
  "steps": [
    {
      "step": "repo",
      "files": [
        { "path": "README.md", "action": "create" },
        { "path": ".gitignore", "action": "create" },
        { "path": ".opentide/configurations/platforms/sentinel.toml", "action": "create" }
      ],
      "warnings": []
    },
    {
      "step": "platforms",
      "files": [{ "path": ".opentide/configurations/platforms/sentinel.toml", "action": "skip" }],
      "warnings": []
    }
  ],
  "message": "Plan: 15 files to write (15 new, 0 changed) · nothing written",
  "summary": { "create": 15, "merge": 0, "skip": 1, "delete": 0, "steps": 2 }
}
```

| `action` | Meaning |
|----------|---------|
| `create` | The step would write a file that does not exist yet |
| `merge` | The step would write over a file that exists (setup merges into the ones it shares with you, such as `.gitignore`, `.vscode/mcp.json` or `.pre-commit-config.yaml`), or over one an earlier step wrote |
| `skip` | The step would leave the file as it is, because it already says what setup would write |
| `delete` | The step would remove the file: an older version's file in `.agents/skills/<slug>/`, which setup replaces whole |

Each step's `warnings` are the warnings that step would print. Paths are relative to the repository being set up; a file outside it, such as the Git hook of a workspace in a subdirectory, is relative too (`../.git/hooks/pre-commit`).

The plan is not a guess: setup runs the same steps in a copy of the repository in a temporary directory, and compares the copy's files before and after each one. The copy holds the Git work tree around the target (the target alone outside Git), less dependency, cache and build folders (`node_modules`, `.venv`, `__pycache__`, `.cache`, `target`, `dist`, `build`, `.terraform`, …) other than the target and the folders above it and anything that is not a file, folder or link, and a `.git` that reads the repository's own branches, configuration and hooks. A link, in the work tree or in `.git`'s hooks, that points outside the tree is copied as what it points at, and one that points into the repository points into the copy, so nothing is written through it. The plan refuses (exit `2`) to copy a home folder or a file system root, and a tree of more than 50,000 files or 512 MB: point `--path` at the repository. The copy is deleted when the plan ends, also when it is stopped with SIGTERM or SIGHUP; a signal the process ignores (SIGHUP under `nohup`) stays ignored. So `setup --plan` then `setup --yes` with the same flags writes exactly the files the plan listed under `create` and `merge`. The skills step still downloads the catalogue to know which files it would write. A plan that removes files says how many in its message (`…, 1 to remove · nothing written`).

`--path` / `-C` and `--yes` / `-y` work on **every** `setup` subcommand (`repo`, `platforms`, `ci`, `env`, `hooks`, `mcp`, `skills`, `vscode`). A positional `PATH` is still accepted as a hidden alias on the subcommands that historically required it; passing both forms in one invocation is a usage error. `setup vscode` accepts `--yes` for symmetry — it writes editor-local files and never prompts.

Given before the subcommand, `--path` and `--yes` still apply to it: `opentide setup --path ./detection-repo --yes hooks` is the same as `opentide setup hooks --path ./detection-repo --yes`. Naming two different paths (`setup --path a env --path b`) is a usage error. Any other `setup` option placed before a subcommand (`opentide setup --ci github env`) is also a usage error, because the subcommand would ignore it.

`--yes` never chooses a platform, MCP host, or skill target. Commands that require one fail with an actionable error when its flag is omitted.

## Subcommands

### setup repo

Scaffold directory layout, README, and `.gitignore`. `--platform` writes and enables the matching `.opentide/configurations/platforms/*.toml` files (same as `setup platforms`).

On an existing repository the command keeps what is there. A `README.md` is left as it is (`skipped`). An existing `.gitignore` keeps its content, byte-order mark and line endings and gains only the lines opentide needs that it lacks: `.opentide/exports/*.export.json`, `.opentide/states/sharing.jsonl` (the sharing cache; `.opentide/states/deployment/` must be committed) and `opentide-reports/`. A line counts as present with or without a leading or trailing `/` (`/opentide-reports` does). The Python lines a new `.gitignore` starts with (`build/`, `dist/`, ...) are not added to an existing one. `--json` lists the lines added under `gitignore_added`, and `.gitignore` under `files` when it changed, under `skipped` when it did not; a rerun adds nothing. A `.gitignore` that is not UTF-8 is left alone with a warning naming the lines to add.

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
| `--sysdig` | Sysdig Secure (Falco) |
| `--bitdefender` | Bitdefender GravityZone |
| `--graylog` | Graylog |

### setup ci

Generate CI/CD pipeline files. **CI provider** is the positional argument (`github`, `gitlab`, or `azure`). Detection platforms are **not** passed here — they are discovered from enabled `.opentide/configurations/platforms/*.toml` files written by `setup platforms`.

Run `setup platforms` before `setup ci` so `validate query` jobs are included. If none are enabled, `setup ci` still writes the pipeline and prints a `WARNING` line (a `warnings` entry in JSON mode).

Generated pipelines set `OPENTIDE_REPO_ROOT` at workflow (GitHub), `variables` (GitLab), or pipeline (Azure) scope so `opentide` commands resolve the detection repository in CI. Re-run `setup ci` to refresh existing pipeline files.

The validate job runs `opentide validate --strict` and `opentide lint --strict`, each writing its findings as a report under `opentide-reports/`: SARIF on GitHub (kept as an artifact, and sent to code scanning on a public repository by a `code_scanning` job that holds only `security-events: write`) and Azure (the `CodeAnalysisLogs` artifact), Code Quality on GitLab (merged by `after_script` into `opentide-reports/codequality.json`, the one file `artifacts:reports:codequality` declares). Annotations and job summaries need no step; see [CI/CD](../usage/workflows/ci-cd.md#annotations-summaries-and-reports). Each enabled platform that supports query validation also runs `opentide validate query --live --changed`, which checks only the rule files the run's pull request, merge request or push changed (see [validate](./validate.md#which-rules-are-checked)), and skips that step when any required credential for the platform is unset. GitHub runs those checks in the validate job. GitLab and Azure run one job per platform in that stage, and generate does not start until they succeed. CrowdStrike and HarfangLab have no query job. Live query validation and the staging deploy first replace the repository root's `.opentide/configurations` with the default branch's copy, so a pull request cannot send a credential to a tenant it added or changed there. A platform with no tenant there yet skips its live query step with exit 0; see [CI/CD](../usage/workflows/ci-cd.md#tenant-configuration-on-pull-requests). The staging job runs a dry-run and then `opentide deploy --strategy PREVIEW --skip-unconfigured`; the production job does the same with `--strategy RELEASE` ([Statuses, strategies and tenants](../usage/concepts/statuses-and-strategies.md#the-two-generated-jobs)). `--skip-unconfigured` exits 0 when every platform with rules to deploy still has the commented-out `[[tenants]]` block `setup` writes. A `RELEASE` run also disables or deletes changed rules whose status maps to `DISABLEMENT` or `DELETION`. The production job then commits what the deploy wrote back (promoted rule statuses and `.opentide/states/deployment/`) to the default branch with a `[skip ci]` message, also after a deploy that failed part way; see [CI/CD](../usage/workflows/ci-cd.md#production-write-back). The file header lists the credential variables from the bundled platform files. GitHub deploy jobs map each of those names to `secrets.<NAME>`. The GitLab file sets `workflow:rules` so pipelines run for merge requests and the default branch, which every job needs to run in a merge request pipeline. Proxies and private certificate authorities are runner settings, not part of the generated file; see [CI/CD](../usage/workflows/ci-cd.md#behind-a-proxy-or-a-private-ca). A change marked `[skip deploy]` (commit message or request title) or labelled `skip-deploy` runs no live query check, deploy or share, for a migration or reformat that touches every rule; see [CI/CD](../usage/workflows/ci-cd.md#skipping-deploys-for-a-catalogue-wide-change). Every job installs `opentide==$OPENTIDE_VERSION`, set once at the top of the file. GitLab write-backs push to `OPENTIDE_PUSH_URL` when that CI/CD variable is set, and can push and sign with an SSH key; see [GitLab write-back credentials](../usage/workflows/ci-cd.md#gitlab-write-back-credentials).

The Azure pipeline sets `pool.vmImage` to `ubuntu-latest` and triggers on every branch so a topic-branch push still validates. `pr:` is kept for Azure Pipelines hosted on GitHub or Bitbucket. Azure Repos Git ignores `pr:`; add a build validation policy on the default branch so a pull request sets `Build.Reason` to `PullRequest`. Staging deploy stays gated on that reason.

```bash
opentide setup platforms --sentinel --splunk --yes
opentide setup ci github --path . --yes
opentide setup ci gitlab --no-staging
opentide setup ci azure --default-branch development --yes
opentide setup --ci azure --default-branch development --yes
```

Positional argument: `github`, `gitlab`, or `azure` (CI **provider**, not Sentinel/Splunk/etc.).

`setup ci` accepts the same CI flags as the [default callback](#default-callback-flags) (`--staging`, `--inflight`, `--sharing`, `--lint-changed`, `--promotion`, `--promotion-target`, `--python-version`, `--explorer-pages`, `--default-branch`, `--path`, `--yes`), so `opentide setup --ci github --default-branch trunk --yes` and `opentide setup ci github --default-branch trunk --yes` write the same pipeline and print the same `WARNING` lines. The one-shot JSON result lists each step's warnings under `steps[].warnings` and again in the top-level `warnings`.

`--lint-changed` gates `opentide lint` on the object files each run changed, `opentide lint --strict --changed`, the diff the deploy job of the same run reads ([linting what changed](./lint.md)), so a catalogue with inherited lint findings (objects without `author`, old query style) can adopt the gate the day it moves to opentide and fix the rest file by file. `opentide validate --strict` still checks every file. The validate job then checks out full history, and on GitLab installs `git`. `--lint-all`, the default, keeps the whole-catalogue lint gate.

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

The opentide VS Code extension (`opentidehq.opentide`) provides the opentide MCP server to VS Code itself. When `.vscode/extensions.json` recommends it, `setup mcp --vscode` still writes `.vscode/mcp.json`, for teammates without the extension, and says so: JSON output has `"extension_mcp": true` and a `detail` sentence, printed as a note.

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
| `--cursor` | Copy the skills to `.cursor/skills/`, keeping files you added there |
| `--claude-code` | Write `CLAUDE.md` and copy the skills to `.claude/skills/`, keeping files you added there |
| `--generic` | Write `AGENTS.md` for any agent that reads `.agents/skills/` |
| `--github-copilot` | Write `.github/copilot-instructions.md`, and `AGENTS.md` as `--generic` does |
| `--install` | Skill slug to install (repeatable); default: `opentide-detection-rule` and `detection-engineering` |
| `--all` | Install every skill in the catalogue |
| `--plugin` | Register the [opentidehq/skills](https://github.com/opentidehq/skills) Agent Plugin for Claude Code in `.claude/settings.json` (see [The Agent Plugin](#the-agent-plugin)) |
| `--name`, `--org`, `--description` | Heading (default: the folder name), organisation and opening paragraph of the agent files |
| `--yes` / `-y` | Install without asking |
| `--query` / `-q` | `discover`: keep skills whose name, slug or description holds the text |
| `--installed` | `discover`: keep only the skills installed in `.agents/skills/` |
| `--refresh` | `discover` / `show`: fetch `manifest.json` again rather than reuse the in-process copy from the last 30 seconds; each CLI run fetches it once anyway |

`--cursor` and `--claude-code` never write through a link: a link in a skill's folder at a path the skill ships is replaced by the skill's file, and a skill folder that links out of the repository is left as it is. Each is reported in `warnings`.

Catalogue discovery fetches `manifest.json` from [opentidehq/skills](https://github.com/opentidehq/skills) on `main`. `AGENTS.md` is rendered from the package template and is not copied from that repository. `opentide-detection-rule`, `opentide-detection-objective`, `opentide-threat-vector`, and `detection-engineering` are installed from the package. Other slugs, including those selected with `--install` or `--all`, are the full GitHub tree under `skills/<slug>/`. A truncated or unreadable tree fails that skill instead of installing a partial copy.

#### The Agent Plugin

[opentidehq/skills](https://github.com/opentidehq/skills) is also an [Agent Plugin](https://agent-plugins.org/specification): one install gives an agent the skills and the opentide MCP server, which the plugin starts as `opentide mcp start`.

```bash
opentide setup skills --plugin --yes
opentide setup skills --plugin --claude-code --yes
```

`--plugin` adds the `opentide` marketplace (`extraKnownMarketplaces`, from GitHub `opentidehq/skills`) and enables `opentide@opentide` (`enabledPlugins`) in `.claude/settings.json`, keeping every other setting there. Claude Code offers the marketplace and the plugin to whoever opens the project. With `--claude-code`, `CLAUDE.md` is written as usual but the skills are not copied to `.claude/skills/`: the plugin carries them, and a copy would load each skill twice. On its own, `--plugin` downloads nothing. JSON output has `"plugin": "opentide@opentide"`, and `advice` names the install command of each other agent (Cursor, VS Code, Copilot CLI), which install plugins from their own command or menu rather than a project file. A `.claude/settings.json` that is not a JSON object is left unchanged, with a warning.

The plugin starts the MCP server in its own folder; [Agent Plugins](../mcp/configuration.md#agent-plugins) says how the server finds the detection workspace from there (in Claude Code, `CLAUDE_PROJECT_DIR`). Do not also run `opentide setup mcp --claude-code`, or Claude Code starts two opentide servers.

The full wizard checks skill availability before writing repository files. If the catalogue or a requested slug cannot be fetched, the standalone skills command fails without installing a partial tree. The full `opentide setup` wizard omits the skills step with a warning so the rest of the scaffold can still apply.

### setup vscode (deprecated)

Recommends the opentide VS Code extension and writes the object snippets. By default the command generates templates and JSON schemas into `.opentide/`, then writes `.vscode/extensions.json` and the snippets. A missing target path is created first so generate-first setup does not `chdir` into a nonexistent directory. Deprecation is logged once per invocation.

`.vscode/extensions.json` recommends `opentidehq.opentide`, the opentide extension: its language server checks object files, and it bundles the templates and the MCP server. Recommendations already there are kept, and the extension is not added when the file lists it under `unwantedRecommendations`.

The command writes no `yaml.schemas`: a YAML language server mapped to opentide's schemas reports what the opentide language server already does. When `.vscode/settings.json` exists, it removes the entries earlier releases wrote, the `.opentide/schemas/opentide.schema.json` router mapping and the per-folder revision mappings (for example `.opentide/schemas/rule.1.0.schema.json` → `objects/rules/**/*.yaml`), and drops `yaml.schemas` when nothing else is left in it. A mapping counts whether its globs are a string or a list. Only the globs setup wrote go, for the object folders in the configuration of the repository it sets up (with `-C`, that repository's, wherever you run it): a folder you mapped to the router yourself (`playbooks/**/*.yaml`) stays mapped. Other settings and other `yaml.schemas` entries are kept. It never creates `settings.json`, and leaves it untouched when it holds no such entry; `files` lists it only when it was rewritten. Both files are edited in place: only the removed entry, or the added recommendation, changes, so comments, layout, line endings and a byte-order mark stay. `extensions.json` is not written when it already recommends `opentidehq.opentide` or lists it under `unwantedRecommendations`. A commented file setup cannot edit that way, or one that does not parse, is left unchanged, with a warning.

The snippets have `scope: "yaml,opentide-yaml"`, so they complete in plain YAML files and in the extension's object files (language `opentide-yaml`).

```bash
opentide setup vscode                 # generate templates + schemas, then extensions.json + snippets
opentide setup vscode --mcp          # same, plus .vscode/mcp.json via write_mcp_config
opentide setup vscode --settings    # generate schemas, then extensions.json and the settings.json cleanup
opentide setup vscode --snippets     # generate templates, then snippets
opentide setup vscode --no-generate  # skip generate (power users)
opentide setup mcp --vscode          # MCP only (unchanged multi-host path)
```

If snippets were requested and templates are still missing after generate, the command exits non-zero (`status: failed`) instead of reporting success.

With `--mcp`, when `.vscode/extensions.json` recommends the extension, JSON output has `"extension_mcp": true` and `detail` says that the extension provides the opentide MCP server to VS Code, so `.vscode/mcp.json` is for teammates without it, as with [`setup mcp --vscode`](#setup-mcp).

| Flag | Purpose |
|------|---------|
| `--settings` | Recommend the extension in `.vscode/extensions.json` and remove opentide's `yaml.schemas` entries from `.vscode/settings.json` (generates schemas first) |
| `--snippets` | Write model template snippets (generates templates first) |
| `--no-merge` | Replace `extensions.json` instead of merging. `settings.json` is only ever cleaned up |
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
