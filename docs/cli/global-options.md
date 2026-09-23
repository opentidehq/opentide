---
title: Global options
description: Repository root, data root, debug logging, colour, and JSON output flags shared by all CLI commands.
---

# Global options

Set on the root `opentide` callback before any subcommand.

```bash
opentide --repo /path/to/repo --json validate --strict
opentide --debug --no-color generate
```

## Options

| Flag | Environment variable | Default | Description |
|------|---------------------|---------|-------------|
| `--repo` | `OPENTIDE_REPO_ROOT` | Discovered from the current directory | Detection workspace root |
| `--data` | `OPENTIDE_DATA_ROOT` | Package bundled data | Override vocabulary and default configs |
| `--debug` | `DEBUG` | off | Enable structlog debug logging |
| `--no-color` | `NO_COLOR` / `FORCE_COLOR=0` | off | Disable Rich colour output |
| `--json` | — | off | Emit JSON instead of Rich tables / logs |

## Repository root resolution

When `--repo` is omitted, OpenTide walks up from the current directory and stops at the first directory holding `.opentide/` or `objects/`. That is the detection workspace, so every command sees the same catalogue whether you start at its root, in `objects/rules`, or in `.opentide/configurations/platforms`.

The walk never leaves the enclosing git checkout. A workspace kept in a subdirectory of a larger repository (`monorepo/detections/`) is found from anywhere inside `detections/`, while markers above the checkout are ignored. When nothing on the way up is marked, the root is the git top level, or the current directory outside git. Git's own `.git/objects` and a Python package named `objects/` (one with an `__init__.py`) are not markers.

In order, the first of these wins:

1. `--repo`
2. `OPENTIDE_REPO_ROOT`
3. `OPENTIDE_TIDE_WORKSPACE` (selects the objects read; the repository root is still resolved as below)
4. The nearest `.opentide/` or `objects/` walking up from the current directory
5. The git top level, or the current directory outside git

Git commands such as `generate docs --changed` and `generate inflight` still run against the whole checkout when the workspace sits below its top level: changed paths are reported relative to the git top level (`detections/objects/rules/…`).

`opentide validate` prints the directory it checked when it finds no objects there. See [Which workspace was checked](./validate.md#which-workspace-was-checked).

A `--repo` typed on the command line also overrides an exported `OPENTIDE_TIDE_WORKSPACE`. That variable is read before the repository root when locating detection objects, so without this precedence `--repo` resolved the root while the workspace — and therefore the objects actually validated — stayed on the exported path.

Setup commands honour `--repo` when `--path` is `.` (default).

## Environment propagation

The CLI context calls `apply_environment()` before engine work, pushing flags into `os.environ` so library code and platform plugins see consistent paths.

## Terminal output

Interactive terminals receive Rich colours. Redirected or captured streams automatically use clean plain text. Set `NO_COLOR=1`, `FORCE_COLOR=0`, or pass `--no-color` to disable colour explicitly; set `FORCE_COLOR=1` to force it.

Routine commands do not print an ASCII banner. The interactive setup wizard uses a compact branded heading.

With `--json`, stdout is one machine-readable JSON document. Diagnostics and debug logs use stderr.

`--json` therefore cannot drive an interactive wizard. `opentide --json setup` (and `setup repo`, `setup mcp`, `setup skills`) refuses to prompt and exits non-zero with a JSON error naming the flags to pass instead — `--yes` plus the explicit selections. Without `--json` the same commands open the wizard as before.

## Deployment plan

Some subcommands read `DEPLOYMENT_PLAN` from the environment or `--plan`:

- `opentide deploy --plan STAGING`
- `opentide validate query --platform sentinel --live --plan STAGING`

`--plan` is a no-op for the default offline `validate query`, which checks the query text of every rule regardless of what the plan would deploy.

## Related

- [Usage: Installation](../usage/installation.md)
- [CLI validate](./validate.md)
