---
title: Global options
description: Repository root, data root, debug logging, colour, JSON output, and version flags shared by all CLI commands.
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
| `--proxy` | `OPENTIDE_PROXY` | none | HTTP(S) proxy for platform and lookup calls; see [Proxy](#proxy) |
| `--version`, `-V` | — | — | Print `opentide <version>` and exit |

## Version

`opentide --version` (or `-V`) prints the installed package version as `opentide <version>` and exits 0. It runs before the repository root is resolved and before any command, so it works outside a detection workspace and is cheap enough to log at the start of a pipeline job:

```bash
opentide --version
```

The output is plain text even with `--json`. For the version inside a JSON document, read `version` from `opentide --json info`.

## Repository root resolution

When `--repo` is omitted, opentide walks up from the current directory and stops at the first directory holding `.opentide/` or `objects/`. That is the detection workspace, so every command sees the same catalogue whether you start at its root, in `objects/rules`, or in `.opentide/configurations/platforms`.

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

## Proxy

`--proxy http://[user:pass@]host:port`, or `OPENTIDE_PROXY` when the flag is omitted, sets `HTTP_PROXY` and `HTTPS_PROXY` for the `opentide` process only, overriding any value it inherited. Platform clients and the CVE lookup then use the proxy. Without either, opentide uses whatever `HTTP_PROXY` and `HTTPS_PROXY` (or their lowercase spellings) the environment already holds.

Hosts listed in `NO_PROXY` (or `no_proxy`) are reached directly, with or without `--proxy`. That is how one command reaches a cloud tenant through the proxy and an internal tenant without it:

```bash
export NO_PROXY=splunk.internal.example
opentide --proxy http://proxy.internal.example:8080 deploy --plan PRODUCTION
```

A `proxy` key under a tenant's `[tenants.setup]`, in `deployment.toml` `[proxy]` or in `[cve]` is retired: the command fails and names `opentide --proxy`. For pipelines behind a proxy, see [CI/CD → Behind a proxy or a private CA](../usage/workflows/ci-cd.md#behind-a-proxy-or-a-private-ca).

## Environment propagation

The CLI context calls `apply_environment()` before engine work, pushing flags into `os.environ` so library code and platform plugins see consistent paths.

## Terminal output

Interactive terminals receive Rich colours. Redirected or captured streams automatically use clean plain text. Set `NO_COLOR=1`, `FORCE_COLOR=0`, or pass `--no-color` to disable colour explicitly; set `FORCE_COLOR=1` to force it.

Routine commands do not print an ASCII banner. The interactive setup wizard uses a compact branded heading.

With `--json`, stdout is one machine-readable JSON document. Diagnostics and debug logs use stderr.

Without `--json`, a result prints its `message` first, then any `detail` and `advice` from the payload as indented `detail:` / `advice:` lines, then its warnings. The text is printed as-is: brackets such as `[error]` or `[deploy, validate]` are shown, never read as Rich markup.

`--json` therefore cannot drive an interactive wizard. `opentide --json setup` (and `setup repo`, `setup mcp`, `setup skills`) refuses to prompt and exits non-zero with a JSON error naming the flags to pass instead — `--yes` plus the explicit selections. Without `--json` the same commands open the wizard as before.

## Deployment plan

Some subcommands read `DEPLOYMENT_PLAN` from the environment or `--plan`:

- `opentide deploy --plan STAGING`
- `opentide validate query --platform sentinel --live --plan STAGING`

`--plan` is unused by a bare `validate query`, which refuses and names `--live`. The plan applies to `validate query --live` and to `deploy`.

## Related

- [Usage: Installation](../usage/installation.md)
- [CLI validate](./validate.md)
