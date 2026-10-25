---
title: CLI reference
description: Complete opentide command-line interface — commands, flags, exit codes, and JSON output.
icon: Terminal
---

# CLI reference

The `opentide` command is a [Typer](https://typer.tiangolo.com/) application included in the core package:

```bash
pip install 'opentide==0.17.2'
```

Run `opentide --help` for the live command tree.

## Command overview

| Command | Purpose |
|---------|---------|
| [`setup`](./setup.md) | Onboard detection repositories (repo, platforms, CI, MCP, skills) |
| [`migrate`](./migrate.md) | Move legacy `Configurations/` and `Objects/` into the greenfield layout |
| [`generate`](./generate.md) | Documentation, exports, framework artifacts, optional platform import |
| [`validate`](./validate.md) | Object and query validation |
| [`lint`](./lint.md) | Catalogue hygiene (filename slugs, recommended metadata) |
| [`rules`](./rules.md) | Review staleness for detection rules |
| [`deploy`](./deploy.md) | Platform rule deployment |
| [`share`](./share.md) | Publish objects to a MISP destination |
| [`info`](./info.md) | Repository and platform statistics |
| [`explain`](./diagnostics.md) | What a diagnostic code means, an example, and how to fix it |
| [`commands`](#command-tree-for-agents) | Every command with its options, defaults and an example; `--json` for the tree |
| [`mcp`](../mcp/index.md) | Stdio MCP server (`mcp start`); the editor owns the process |

<Callout type="info">

Top-level `document`, `export`, and `extract` remain as **hidden deprecation shims** for one release. They log a warning and delegate to `opentide generate docs`, `generate exports`, and `generate extract`. `mutate` was removed — use `opentide deploy` for promotion. Layout-only `opentide migrate objects` moves `Configurations/` and `Objects/` into the greenfield tree; CoreTide submodule replacement still uses the [migration prompt](../usage/migration/prompt.md).

</Callout>

## Global options

All commands inherit [global options](./global-options.md):

| Flag | Env var | Purpose |
|------|---------|---------|
| `--repo` | `OPENTIDE_REPO_ROOT` | Detection repository root |
| `--data` | `OPENTIDE_DATA_ROOT` | Bundled data root override |
| `--debug` | `OPENTIDE_DEBUG` | Debug logging |
| `--quiet` | — | Only the outcome line and errors |
| `--no-color` | `NO_COLOR` | Disable Rich colour |
| `--json` | `OPENTIDE_OUTPUT=json` | One [JSON document](./json-output.md) on stdout |
| `--version`, `-V` | — | Print the installed version and exit |

## Typical CI sequence

```bash
opentide generate
opentide --json validate --strict
opentide validate query --platform sentinel --live
opentide lint --strict
opentide deploy --platform sentinel --dry-run --strategy PREVIEW --all
```

Generated pipelines use `opentide generate docs --output docs` for documentation jobs. Status promotion runs inside `opentide deploy` — there is no separate `mutate promote` step.

## JSON output

With `--json`, every command writes exactly one JSON document to stdout. Successes include `"ok": true`; failures include `"ok": false`, a status, message, and non-zero exit code. Diagnostics use stderr and never prefix the stdout document. (`opentide info` emits the info object through the same contract.)

## Exit codes

Commands set a process exit code so CI can gate without parsing output: `0` success, `1` error, `2` usage error. Full reference: [Exit codes](./exit-codes.md).

## Coding agents

An agent in a shell drives the same commands as a person. Four rules cover it, and `opentide setup skills` writes them into `AGENTS.md`, `CLAUDE.md` and `.github/copilot-instructions.md`:

1. Run `opentide --json <command>`. stdout is one [JSON document](./json-output.md) and nothing else.
2. Branch on the exit code first, then read `failure.code` for the detail, for example `issues_found`, `usage_invalid_choice` or `no_tenant_reached`. A usage error carries the closest valid value in `failure.suggestion`.
3. Apply each finding's `fix`: every edit replaces the text from (`line`, `column`) up to (`end_line`, `end_column`), 1-based, with `replacement`. `safe: true` edits only respell the same word and can be applied as they are; check the others against `help`. For a finding with no fix, `opentide explain <code>` says what it means and how to fix it.
4. Follow `next_actions`, each a `{command, reason}`.

The loop: search what exists (`opentide --json info coverage --technique T1059`), draft from `.opentide/templates/`, run `opentide --json validate --file <file>` until `ok` is `true`, then preview with `opentide --json deploy --dry-run --strategy PREVIEW --all`. People review and merge the change and run real deployments. An agent never gets a prompt: a command that needs input exits `2` with `usage_needs_input` and names the flags to pass.

### Command tree for agents

`opentide --json commands` prints every visible command, read from the CLI itself, so it never drifts from what the CLI accepts:

```bash
opentide --json commands
```

```json illustrative
{
  "program": "opentide",
  "version": "0.17.2",
  "global_options": [
    {
      "name": "repo",
      "flags": ["--repo"],
      "secondary_flags": [],
      "type": "string",
      "choices": null,
      "default": null,
      "required": false,
      "multiple": false,
      "is_flag": false,
      "envvars": ["OPENTIDE_REPO_ROOT"],
      "help": "Repository root"
    }
  ],
  "commands": [
    {
      "path": "validate query",
      "name": "query",
      "summary": "Query validation checks the tenant. Pass --live.",
      "help": "Query validation checks the tenant. Pass --live. …",
      "group": false,
      "runs_alone": true,
      "subcommands": [],
      "deprecated": false,
      "arguments": [],
      "options": [
        {
          "name": "platform",
          "flags": ["--platform"],
          "type": "choice",
          "choices": ["sentinel", "splunk", "crowdstrike", "…"],
          "required": true,
          "…": "…"
        }
      ],
      "example": "opentide validate query --platform sentinel"
    }
  ],
  "ok": true,
  "status": "completed",
  "message": "49 commands",
  "summary": { "commands": 49, "groups": 13 },
  "…": "envelope keys"
}
```

| Key | Meaning |
|-----|---------|
| `version` | The installed opentide version: key a cached copy of the tree on it. |
| `global_options` | The root options (`--repo`, `--json`, …). `--json`, `--no-color`, `--debug` and `--quiet` may also follow the command. |
| `environment` | `[{name, meaning}]`: variables that change every command but are not options: `OPENTIDE_OUTPUT`, `OPENTIDE_DEBUG`, `NO_COLOR` and the agent-detection variables (`AI_AGENT`, `CLAUDECODE`, …). |
| `commands` | Flat and depth-first, in `--help` order. `path` is the words to type; a group's `subcommands` are the entries whose path extends it. Hidden commands and options are left out. |
| `runs_alone` | `false` for a group that only prints its help (`opentide mcp`): run one of its subcommands. |
| `options[].type` | `string`, `integer`, `number`, `boolean`, `choice` (with `choices`), `path`, … A `string` the command checks itself lists its values in `choices` too: `validate --type`, `deploy --strategy`, `info`'s section. `share --target` takes the configured targets, so it has none. |
| `options[].envvars` | Environment variables that set the option. |
| `example` | The first example in the command's `--help`. A command whose help has none yet gets a placeholder: the command with its required arguments and options filled in. A placeholder names the command but may not run as it is (`opentide deploy` still needs `--strategy`). |

Without `--json`, `opentide commands` prints the tree, one command per line with its summary, and ends with `✓ 49 commands`. Listing the tree imports every command's module once; it never loads the detection registry.

## Choosing between CLI, SDK, and MCP

The CLI is one of three interfaces to the same engine. For humans and pipelines, use the CLI; to embed in Python, use the [SDK](../sdk/index.md); for AI agents, use [MCP](../mcp/index.md). See [Choosing an interface](../usage/choosing-an-interface.md).

## Shell completion

```bash
opentide --install-completion
opentide --show-completion
```

## Source

Command definitions: `src/opentide/cli/commands/` (the root list is `src/opentide/cli/commands/__init__.py`; global options are in `src/opentide/cli/root.py`), `src/opentide/cli/setup_app.py`, `src/opentide/cli/share_app.py`.
