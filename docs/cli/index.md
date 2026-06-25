---
title: CLI reference
description: Complete opentide command-line interface — commands, flags, exit codes, and JSON output.
icon: Terminal
---

# CLI reference

The `opentide` command is a [Typer](https://typer.tiangolo.com/) application. Install with the `cli` extra:

```bash
pip install "opentide[cli]>=0.1"
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
| `--no-color` | — | Disable Rich colour |
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

With `--json`, most success payloads include `"ok": true` and write JSON to stdout. Errors emit `"ok": false` and exit non-zero. Human-oriented log lines may still appear on stderr when structlog is configured for JSON — treat stdout as the contract for automation.

## Shell completion

```bash
opentide --install-completion
opentide --show-completion
```

## Source

Command definitions: `src/opentide/cli/__init__.py`, `src/opentide/cli/setup_app.py`.
