---
title: Global options
description: Repository root, data root, debug logging, quiet, colour, JSON output, version flags, shell completion and terminal progress shared by all CLI commands.
---

# Global options

Set on the root `opentide` callback. The boolean flags (`--json`, `--no-color`, `--debug`, `--quiet`) are accepted anywhere before `--`, after the command too; options that take a value (`--repo`, `--data`, `--proxy`) go before the command.

```bash
opentide --repo /path/to/repo --json validate --strict
opentide validate --strict --json
opentide --debug --no-color generate
```

A flag that is the value of the option before it stays that option's value: in `opentide setup skills discover --query --json`, `--json` is the search text. There are no short forms (`-q` belongs to `--query`).

## Options

| Flag | Environment variable | Default | Description |
|------|---------------------|---------|-------------|
| `--repo` | `OPENTIDE_REPO_ROOT` | Discovered from the current directory | Detection workspace root |
| `--data` | `OPENTIDE_DATA_ROOT` | Package bundled data | Override vocabulary and default configs |
| `--debug` | `OPENTIDE_DEBUG`, or `DEBUG` when it is a boolean | off | Enable debug logging, with timestamps |
| `--quiet` | — | off | Print only the outcome line and errors |
| `--no-color` | `NO_COLOR` / `FORCE_COLOR=0` | off | Disable colour |
| `--json` | `OPENTIDE_OUTPUT=json` | off | Print one JSON document on stdout; see [JSON output](./json-output.md) |
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

A `--repo` typed on the command line must name an existing directory: anything else exits `2` with `usage_invalid_value` (`--repo ../detections does not exist`, then `→ opentide --help`), so a typo cannot read as an empty catalogue that passes. `setup` is the exception, since it may name the folder it is about to create.

## Proxy

`--proxy http://[user:pass@]host:port`, or `OPENTIDE_PROXY` when the flag is omitted, sets `HTTP_PROXY`, `HTTPS_PROXY` and their lowercase spellings for the `opentide` process only, overriding any value it inherited. Platform clients and the CVE lookup then use the proxy. Without either, opentide uses whatever `HTTP_PROXY` and `HTTPS_PROXY` (or their lowercase spellings) the environment already holds.

Hosts listed in `NO_PROXY` (or `no_proxy`) are reached directly, with or without `--proxy`. That is how one command reaches a cloud tenant through the proxy and an internal tenant without it:

```bash
export NO_PROXY=splunk.internal.example
opentide --proxy http://proxy.internal.example:8080 deploy --strategy RELEASE
```

A `proxy` key under a tenant's `[tenants.setup]`, in `deployment.toml` `[proxy]` or in `[cve]` is retired: the command fails and names `opentide --proxy`. For pipelines behind a proxy, see [CI/CD → Behind a proxy or a private CA](../usage/workflows/ci-cd.md#behind-a-proxy-or-a-private-ca).

## Debug

`--debug` turns on debug logging on stderr, each line with its time. `OPENTIDE_DEBUG=1` does the same for every command. `DEBUG` is read too, but only when its value is a boolean (`1`, `true`, `yes`, `on`, or `0`, `false`, `no`, `off`): `DEBUG='*'`, which Node tooling exports, is ignored instead of failing every command. `OPENTIDE_DEBUG` wins when both are set.

opentide exports `OPENTIDE_DEBUG=1` to the processes it starts when debugging, never `DEBUG`.

When opentide stops on an unexpected error, `--debug` also prints the traceback, above the `error[internal]` line. Without it the traceback is only in the crash log; see [Troubleshooting](../usage/troubleshooting.md#opentide-stops-with-errorinternal).

## Environment variables

`opentide --json commands` lists these under `environment`, and a test fails when the code reads an `OPENTIDE_*` variable the list leaves out.

| Variable | Effect |
|----------|--------|
| `OPENTIDE_OUTPUT` | Output mode: `human`, `plain`, `agent` or `json`; see [Output modes](./json-output.md#output-modes) |
| `OPENTIDE_DEBUG` | `1` for debug logging, like `--debug` |
| `NO_COLOR` | Any value turns colour off, like `--no-color` |
| `OPENTIDE_JSON_INDENT` | `0` prints every `--json` document on one line, `2` indents it; default: indented at a terminal, one line otherwise |
| `OPENTIDE_REPO_ROOT` | Repository root, like `--repo` |
| `OPENTIDE_DATA_ROOT` | Bundled data root, like `--data` |
| `OPENTIDE_PROXY` | HTTP(S) proxy, like `--proxy` |
| `OPENTIDE_TIDE_WORKSPACE` | Folder whose objects are read, when it is not the repository root; see [Repository root resolution](#repository-root-resolution) |
| `OPENTIDE_EXPLORER_PACKAGE` | npm spec [`opentide explorer`](./explorer.md) runs instead of `@opentide/explorer@<version>`: a mirror, a fork or a local tarball |
| `OPENTIDE_LINKS` | Link scheme of code-frame paths: `file`, `vscode`, `cursor` or `none`; default `vscode` inside VS Code, else `file` |
| `OPENTIDE_LOG_JSON` | `1` for one JSON object per log line on stderr |
| `OPENTIDE_VALIDATE_WORKERS` | Most threads `validate` uses: a number, or `auto` |
| `OPENTIDE_VALIDATE_PARALLEL_THRESHOLD` | Fewest objects before `validate` runs in parallel (default 32) |
| `OPENTIDE_PROGRESS` | `0` turns terminal progress (OSC 9;4) off; `1` sends it to any terminal in `human` mode. See [Progress in the tab and taskbar](#progress-in-the-tab-and-taskbar) |
| `OPENTIDE_CACHE_DIR` | Where opentide caches what it generates for the language server (`lsp-catalogs/`); default: the user cache directory |
| `CLAUDECODE`, `AI_AGENT`, … | Set by a coding agent: selects `agent` output mode |

## Environment propagation

The CLI context calls `apply_environment()` before engine work, pushing flags into `os.environ` so library code and platform plugins see consistent paths.

## Terminal output

Interactive terminals receive Rich colours. Redirected or captured streams, CI logs and coding agents get plain text that is never wrapped, so a path stays on one line. Set `NO_COLOR=1`, `FORCE_COLOR=0`, or pass `--no-color` to disable colour explicitly; set `FORCE_COLOR=1` to force it. `OPENTIDE_OUTPUT` (`human`, `plain`, `agent`, `json`) overrides the choice; see [Output modes](./json-output.md#output-modes).

Routine commands do not print an ASCII banner. The interactive setup wizard uses a compact branded heading.

With `--json`, stdout is one machine-readable JSON document, usage errors included: indented at a terminal, one compact line otherwise, and `OPENTIDE_JSON_INDENT=0` or `2` chooses either way. Logs use stderr, at `WARNING` and above unless `--debug`.

Without `--json`, a result prints its warnings first (`warning: …`), then one outcome line (`✓ message`, `! message` when there are issues, `Skipped: message`), then any `detail` and `advice` from the payload as indented `note:` / `help:` lines, then at most three next steps (`→ command`). A failure prints `error: message` on stderr instead of the outcome line; a command that failed on findings it printed (`validate`, `lint --strict`, `info --strict`) prints its outcome line as `✗ …` on stderr instead. The text is printed as-is: brackets such as `[error]` or `[deploy, validate]` are shown, never read as Rich markup. `--quiet` keeps only the outcome line and errors: it drops section headers, progress lines, warnings, notes and next steps, but keeps the result tables a command prints as its output, such as `info` and `setup skills discover`.

`--json` therefore cannot drive an interactive wizard. `opentide --json setup` (and `setup repo`, `setup mcp`, `setup skills`) refuses to prompt and exits `2` with `failure.code` `usage_needs_input`, naming the flags to pass instead — `--yes` plus the explicit selections. A coding agent gets the same refusal without `--json`, even on a terminal. Otherwise the same commands open the wizard as before.

### Progress in the tab and taskbar

While a long command runs (`generate` and its subcommands, `deploy`, `validate query --live`, `share`), opentide also sends the terminal's progress sequence (OSC 9;4), so the tab or the taskbar shows how far the run is: a percentage for a run of several steps, a busy indicator for a single step. The bar is cleared when the command ends, fails, or is stopped with Ctrl-C.

It is sent only in `human` mode, without `--quiet`, when standard error is itself a terminal (so `2> build.log` gets none, even with `FORCE_COLOR` set), and only to a terminal that reads it: Windows Terminal (`WT_SESSION` set), WezTerm (`TERM_PROGRAM`), Ghostty 1.2 or later and iTerm2 3.6.6 or later (`TERM_PROGRAM` and `TERM_PROGRAM_VERSION`), and kitty (`TERM=xterm-kitty`). Older iTerm2 shows each OSC 9 sequence as a desktop notification, so a version that is older or unknown gets nothing. Inside tmux (`TMUX` set) the sequence goes through tmux passthrough, which needs `set -g allow-passthrough on` in `tmux.conf`; there the outer terminal is recognised from `WT_SESSION`, `KITTY_WINDOW_ID`, `WEZTERM_PANE` or `LC_TERMINAL=iTerm2` with `LC_TERMINAL_VERSION` 3.6.6 or later, because tmux replaces `TERM` and `TERM_PROGRAM`.

| `OPENTIDE_PROGRESS` | Effect |
|---------------------|--------|
| unset | Sent to the terminals above |
| `0`, `false`, `no`, `off` | Never sent |
| `1`, `true`, `yes`, `on` | Sent to any terminal in `human` mode, for one that reads OSC 9;4 but is not recognised (Ghostty inside tmux, or a version opentide cannot read) |

## Shell completion

`opentide --install-completion` installs completion for the current shell (bash, zsh, fish or PowerShell) and prints where it went and how to load it:

```console
$ opentide --install-completion
✓ Installed zsh completion in ~/.zfunc/_opentide
→ source ~/.zshrc · or restart your shell
```

`opentide --show-completion` prints the script instead, to install it by hand. Both take the shell as the word after them (`opentide --show-completion fish`); a word that is not `bash`, `zsh`, `fish`, `powershell` or `pwsh` is a usage error (exit `2`). Besides commands and option names, it completes these values from the workspace:

| Value | Completes with | Read from |
|-------|----------------|-----------|
| `--uuid` (`validate`, `validate query`, `share`) | Object UUIDs, with the object's name and kind | The `name` and `metadata.uuid` lines at the top of each object file |
| `--file` (same commands) | Object file paths, relative to the current directory when inside it, otherwise to the workspace; a bare file name when no path matches | The object folders |
| `--type` | `rule`, `threat`, `objective` | — |
| `--technique` (`info`) | ATT&CK ids, with their titles | The bundled ATT&CK vocabulary (`--data` or `OPENTIDE_DATA_ROOT` when set) |
| `--platform` | The platforms enabled in the workspace first, marked `enabled`, then the others | `.opentide/configurations/platforms/*.toml` |
| `--strategy` (`deploy`, `validate query`) | `PREVIEW`, `RELEASE` | — |
| `explain <code>` | Diagnostic codes, with what each one means; applies once `opentide explain` ([#620](https://github.com/opentidehq/opentide/issues/620)) is available | The pages bundled with `opentide explain` |

`validate query` completes rules only, and a `--type` already on the command line narrows `--uuid` and `--file`. The workspace is the one the command would use: `--repo`, then `OPENTIDE_REPO_ROOT`, then the nearest one up from the current directory. Object folders follow `[paths.objects]` in `.opentide/configurations/paths.toml` when it sets them.

Completing a value does not load the command's module or the engine, so it costs about what completing a command name does. Completing an option name (`opentide validate --<Tab>`), or a value after an option completion does not know, loads the command. Completion never loads the catalogue the way a command does: it reads only the first lines of each object file, and `--file` reads only those of the paths that match. That keeps it close to `--help` for a catalogue of hundreds of objects; with many thousands, `--uuid` takes about a second. In bash, spaces and shell characters in a completed path are escaped with a backslash. When nothing matches `--file`, the shell completes file names itself.

## Strategy

`opentide deploy` takes `--strategy PREVIEW` or `--strategy RELEASE` (repeatable): the status strategy the run deploys. `validate query --live` takes the same option to narrow its check. There is no environment variable for it. See [Statuses, strategies and tenants](../usage/concepts/statuses-and-strategies.md).

- `opentide deploy --strategy PREVIEW`
- `opentide validate query --platform sentinel --live --strategy RELEASE`

`--plan` and `DEPLOYMENT_PLAN` were removed in 0.17.0. Passing `--plan`, or running `deploy` or `validate query --live` with `DEPLOYMENT_PLAN` set, fails with exit `2` and names the `--strategy` to use.

## Related

- [JSON output](./json-output.md)
- [Usage: Installation](../usage/installation.md)
- [CLI validate](./validate.md)
