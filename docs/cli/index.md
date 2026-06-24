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
| [`setup`](./setup.md) | Onboard detection repositories (interactive or scripted) |
| [`generate`](./generate.md) | Build indexes, schemas, templates, exports |
| [`validate`](./validate.md) | Object and query validation |
| [`deploy`](./deploy.md) | Platform rule deployment |
| [`document`](./document.md) | Wiki and object documentation generation |
| [`mutate`](./mutate.md) | Bulk content mutations |
| [`export`](./export.md) | Navigator layers, object dumps, revisions |
| [`extract`](./extract.md) | Import rules from external platforms |
| [`info`](./info.md) | Repository and platform statistics |
| [`migrate`](./migrate.md) | Legacy import and script migration |

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

## JSON output

With `--json`, success payloads include `"ok": true`. Errors emit `"ok": false` and exit non-zero. Use in pipeline gates and agent tooling.

## Shell completion

```bash
opentide --install-completion
opentide --show-completion
```

## Source

Command definitions: `src/opentide/cli/__init__.py`, `src/opentide/cli/setup_app.py`.
