---
title: CLI reference
description: Complete opentide command-line interface — commands, flags, exit codes, and JSON output.
icon: Terminal
---

# CLI reference

The `opentide` command is a [Typer](https://typer.tiangolo.com/) application included in the core package:

```bash
pip install 'opentide==0.1.0'
```

Run `opentide --help` for the live command tree.

## Command overview

| Command | Purpose |
|---------|---------|
| [`setup`](./setup.md) | Onboard detection repositories (repo, platforms, CI, MCP, skills) |
| [`generate`](./generate.md) | Documentation, exports, framework artifacts, optional platform import |
| [`validate`](./validate.md) | Object and query validation |
| [`deploy`](./deploy.md) | Platform rule deployment |
| [`info`](./info.md) | Repository and platform statistics |

<Callout type="info">

Top-level `document`, `export`, and `extract` remain as **hidden deprecation shims** for one release. They log a warning and delegate to `opentide generate docs`, `generate exports`, and `generate extract`. `mutate` and `migrate` were removed — use `opentide deploy` for promotion and the [CoreTide migration prompt](../usage/migration/prompt.md) for legacy repos.

</Callout>

## Global options

All commands inherit [global options](./global-options.md):

| Flag | Env var | Purpose |
|------|---------|---------|
| `--repo` | `OPENTIDE_REPO_ROOT` | Detection repository root |
| `--data` | `OPENTIDE_DATA_ROOT` | Bundled data root override |
| `--debug` | `DEBUG` | Debug logging |
| `--no-color` | `NO_COLOR` | Disable Rich colour |
| `--json` | — | Machine-readable JSON output |

## Typical CI sequence

```bash
opentide generate
opentide validate --strict --json
opentide validate query --platform sentinel
opentide deploy --platform sentinel --dry-run
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

Command definitions: `src/opentide/cli/__init__.py`, `src/opentide/cli/setup_app.py`.
