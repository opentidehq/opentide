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

## Home screen

At a terminal, `opentide` with no command prints a home screen instead of the help: the workspace and its git state, how many rules, threats and objectives it holds, whether the schemas are generated, the enabled platforms, and up to three commands worth running next. It reads files on disk only, so it is as quick as `--help`. In a pipe, in CI, under a coding agent or with `NO_COLOR`, it prints the help.

![The home screen in the tutorial repository: the opentide icon, the workspace facts and the suggested next commands](https://raw.githubusercontent.com/opentidehq/opentide/development/docs/assets/cli/home.png)

Recorded in the [tutorial](../usage/tutorial.md) repository from [`docs/tapes/home.tape`](https://github.com/opentidehq/opentide/blob/development/docs/tapes/home.tape).

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

## Choosing between CLI, SDK, and MCP

The CLI is one of three interfaces to the same engine. For humans and pipelines, use the CLI; to embed in Python, use the [SDK](../sdk/index.md); for AI agents, use [MCP](../mcp/index.md). See [Choosing an interface](../usage/choosing-an-interface.md).

## Shell completion

```bash
opentide --install-completion
opentide --show-completion
```

## Source

Command definitions: `src/opentide/cli/commands/` (the root list is `src/opentide/cli/commands/__init__.py`; global options are in `src/opentide/cli/root.py`), `src/opentide/cli/setup_app.py`, `src/opentide/cli/share_app.py`.
