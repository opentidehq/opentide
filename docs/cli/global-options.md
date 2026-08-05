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
| `--repo` | `OPENTIDE_REPO_ROOT` | Auto-detected repo root | Detection content repository |
| `--data` | `OPENTIDE_DATA_ROOT` | Package bundled data | Override vocabulary and default configs |
| `--debug` | `DEBUG` | off | Enable structlog debug logging |
| `--no-color` | `NO_COLOR` / `FORCE_COLOR=0` | off | Disable Rich colour output |
| `--json` | — | off | Emit JSON instead of Rich tables / logs |

## Repository root resolution

When `--repo` is omitted, OpenTide walks up from the current directory to find the repository root (objects, configurations markers). Explicit `--repo` or `OPENTIDE_REPO_ROOT` always wins.

Setup commands honour `--repo` when `--path` is `.` (default).

## Environment propagation

The CLI context calls `apply_environment()` before engine work, pushing flags into `os.environ` so library code and platform plugins see consistent paths.

## Terminal output

Interactive terminals receive Rich colours. Redirected or captured streams automatically use clean plain text. Set `NO_COLOR=1`, `FORCE_COLOR=0`, or pass `--no-color` to disable colour explicitly; set `FORCE_COLOR=1` to force it.

Routine commands do not print an ASCII banner. The interactive setup wizard uses a compact branded heading.

With `--json`, stdout is one machine-readable JSON document. Diagnostics and debug logs use stderr.

## Deployment plan

Some subcommands read `DEPLOYMENT_PLAN` from the environment or `--plan`:

- `opentide deploy --plan STAGING`
- `opentide validate query --platform sentinel --plan STAGING`

## Related

- [Usage: Installation](../usage/installation.md)
- [CLI validate](./validate.md)
