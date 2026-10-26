---
title: JSON output
description: The JSON document every opentide command prints with --json, its envelope keys, failure codes and output modes.
---

# JSON output

With `--json`, every `opentide` command prints exactly one JSON document on stdout, whether it succeeds, fails, or was called with a typo. Logs go to stderr, at `WARNING` and above (everything with `--debug`), so `opentide --json validate 2>/dev/null` is always parseable. This page describes the keys every document shares. Each command's own keys are on its page.

`--json` works before or after the command: `opentide --json validate` and `opentide validate --json` are the same. So do `--no-color`, `--debug` and `--quiet`. Options that take a value (`--repo`, `--data`, `--proxy`) stay before the command.

```bash
opentide validate --json
opentide --json info --platform sentinel
```

## The envelope

Every document carries these keys next to the command's own. Keys that existed before keep their name, type and meaning; new information is only ever added under new keys.

| Key | Type | Meaning |
|-----|------|---------|
| `ok` | bool | `false` when the command failed |
| `status` | str | `completed`, `passed`, `issues`, `skipped` or `failed` |
| `message` | str | The outcome in one sentence |
| `error` | str | On every non-zero exit: the error message, as a string (the `message` unless the command names a more specific error) |
| `warnings` | list[str] | Present when the command has warnings |
| `schema_version` | int | `1`. It changes only if an existing key ever changes meaning |
| `command` | str | The command that ran: `validate`, `validate query`, `generate docs rules`. Empty when no command was recognised |
| `duration_ms` | int | Wall time of the command |
| `exit_code` | int | The process exit code, the same as `$?` |
| `summary` | object | Counts behind the outcome, such as `files` or `errors`. Empty when the command reports none yet |
| `next_actions` | list | Commands worth running next, as a JSON reader runs them: `[{ "command": "opentide --json lint --fix", "reason": "…" }]` |
| `failure` | object or null | Why the command did not exit `0`. `null` exactly when `exit_code` is `0` |

`failure` has five keys:

| Key | Meaning |
|-----|---------|
| `code` | Stable snake_case code to branch on. See below |
| `message` | The error message (the same text as `error` on a failure) |
| `argument` | The input at fault, such as `--type`, `section` or the mistyped command; otherwise `null` |
| `suggestion` | The closest valid value, such as `validate` for `valdate`; otherwise `null` |
| `crash_log` | Reserved for unexpected errors; `null` |

## Failure codes

| Code | Exit | Meaning |
|------|-----:|---------|
| `usage_unknown_command` | 2 | No such command. `suggestion` names the closest one |
| `usage_unknown_option` | 2 | No such option for that command |
| `usage_invalid_choice` | 2 | A value outside the accepted ones: `--platform`, `--type`, `--target`, an `info` section, a `generate` phase, a `--strategy` |
| `usage_invalid_value` | 2 | A value that cannot be used, such as the removed `--plan` or a `rules unreviewed --older-than` that is not a window |
| `usage_missing_option` | 2 | A required option or argument is missing (`--platform`, `--strategy`, `--technique`, `validate query` without `--live`) |
| `usage_needs_input` | 2 | The command would prompt, but nobody can answer: `--json`, no terminal, or a coding agent. The message names the flags that answer the prompt |
| `usage_error` | 2 | Another usage error, such as options that cannot be combined, or a command group named without its subcommand (`opentide --json mcp`) |
| `usage_watch_needs_tty` | 2 | `validate --watch` under `--json`, a coding agent or `OPENTIDE_OUTPUT=agent`: it redraws a terminal until Ctrl-C, and nobody would see it |
| `no_tenant_reached` | 2 | `validate query --live` sent no query because no configured tenant takes the rules |
| `needs_human_decision` | 2 | `migrate vocab-scope` left values only a person can place |
| `not_implemented` | 2 | A reserved command, such as `deploy metadata` |
| `share_unreachable` | 2 | `share`: every failure was authentication or connectivity |
| `share_partial` | 3 | `share`: some objects were shared and some failed |
| `share_failed` | 1 | `share`: objects failed and none succeeded |
| `scope_no_match`, `api_key_unset`, … | 1 | `share` preflight failures; the code is the `preflight` value |
| `issues_found` | 1 | The command failed on what it found: `validate` errors (or warnings under `--strict`), `lint --strict` findings, `info --strict` load errors. The findings are in the document |
| `config_parse` | 1 | A configuration TOML file does not parse. `diagnostics` holds the file, line and column |
| `yaml_parse` | 1 | `deploy` read a rule file whose YAML is not one mapping. `diagnostics` holds the file and line |
| `not_run` | non-zero | The command was skipped and says why in `message` |
| `command_failed` | 1 | Any other failure |

Exit codes are in [Exit codes](./exit-codes.md). `opentide explain <code>` prints the page for each failure code, as it does for findings ([Diagnostic codes](./diagnostics.md)).

## A usage error

A typo in a command, an option or a value exits `2` with the same document. Case and `-`/`_` do not count against a suggestion: `--type RULE` suggests `rule`. Under `--json` nothing goes to stderr. In this tutorial repository, `opentide --json info rulez` exits `2`:

```bash
opentide --json info rulez
opentide info rulez
```

```json output-of="opentide --json info rulez" exit=2
{
  "error": "Unknown info section: rulez. Choose rules, threats, objectives, coverage.",
  "ok": false,
  "status": "failed",
  "message": "Unknown info section: rulez. Choose rules, threats, objectives, coverage.",
  "schema_version": 1,
  "command": "info",
  "duration_ms": "...",
  "exit_code": 2,
  "summary": {},
  "next_actions": [],
  "failure": {
    "code": "usage_invalid_choice",
    "message": "Unknown info section: rulez. Choose rules, threats, objectives, coverage.",
    "argument": "section",
    "suggestion": "rules",
    "crash_log": null
  }
}
```

Without `--json` the same error is one line on stderr, with the suggestion under it:

```text output-of="opentide info rulez" exit=2
error: Unknown info section: rulez. Choose rules, threats, objectives, coverage.
  help: did you mean 'rules'?
```

## Output modes

opentide decides once per command who is reading. The first rule that matches wins:

| Order | Rule | Mode |
|------:|------|------|
| 1 | `opentide mcp start` | `mcp`: stdout carries nothing but JSON-RPC |
| 2 | `--json` | `json`: one document on stdout |
| 3 | `OPENTIDE_OUTPUT` is `json`, `agent`, `plain` or `human` | that mode |
| 4 | A coding agent is detected | `agent` |
| 5 | stdout is not a terminal, `NO_COLOR` or `--no-color`, `TERM=dumb`, or CI | `plain` |
| 6 | Otherwise | `human` |

`OPENTIDE_OUTPUT=json` is the same as passing `--json` to every command.

`plain` is `human` without colour or animation. Lines are never wrapped, so a long path stays on one line.

`agent` is `plain`, plus: a command that would prompt exits `2` at once with `usage_needs_input` and names the flags that answer the prompt, and a failure ends with `tip: add --json for machine-readable output`. Agents are detected from `AI_AGENT` first, then `CLAUDECODE`, `CURSOR_AGENT`, `GEMINI_CLI`, `CODEX_CI`, `COPILOT_AGENT`, `COPILOT_CLI`, `OPENCODE`, `AMP_CURRENT_THREAD_ID`, `AUGMENT_AGENT` and `CLINE_ACTIVE`. Detection changes presentation only: it never relaxes a confirmation, a `--yes` requirement or a strategy check.

## Human output

Without `--json`, a command prints its warnings first (`warning: …` on stderr), then exactly one outcome line, then at most three next steps:

```text illustrative
warning: Query validation reported warnings for sentinel
✓ Query validation passed for sentinel
```

`validate` and `lint` print each finding as a code frame before the outcome line, and their outcome line counts them (`✗ 2 errors in 1 file · 3 objects checked · 0.9s`). See [Diagnostic codes](./diagnostics.md).

| Line | Meaning |
|------|---------|
| `✓ …` | Done |
| `! …` | Done, with issues |
| `Skipped: …` | Nothing was done, and why |
| `error: …` | Failed (stderr), followed by indented `note:` and `help:` lines |
| `→ …` | A next step: the command to run, and why |

A console that cannot encode `✓`, `✗` or `→` (a Windows code page, `PYTHONIOENCODING=ascii`) gets `ok`, `x` and `->`.

## Related

- [Exit codes](./exit-codes.md)
- [Global options](./global-options.md)
