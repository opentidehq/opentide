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

The document is indented when stdout is a terminal, and one compact line otherwise: in a pipe, a file, CI or a coding agent's shell. `OPENTIDE_JSON_INDENT=0` prints one line everywhere and `OPENTIDE_JSON_INDENT=2` indents by two spaces everywhere; any other value is ignored. Either way the document ends in exactly one newline, so `opentide --json validate | jq .summary` and `json.loads` read it the same.

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
| `crash_log` | With `internal`: the path of the redacted crash log, or `null` if it could not be written. Otherwise `null` |

## Failure codes

| Code | Exit | Meaning |
|------|-----:|---------|
| `usage_unknown_command` | 2 | No such command. `suggestion` names the closest one |
| `usage_unknown_option` | 2 | No such option for that command |
| `usage_invalid_choice` | 2 | A value outside the accepted ones: `--platform`, `--type`, `--target`, an `info` section, a `generate` phase, a `--strategy` |
| `usage_invalid_value` | 2 | A value that cannot be used, such as the removed `--plan` or a `rules unreviewed --older-than` that is not a window |
| `usage_missing_option` | 2 | A required option or argument is missing (`--platform`, `--strategy`, `--technique`; `validate query --live` without `--platform`; `validate query --platform sentinel_one` without `--live`) |
| `usage_needs_input` | 2 | The command would prompt, but nobody can answer: `--json`, no terminal, or a coding agent. The message names the flags that answer the prompt |
| `usage_tui_needs_tty` | 2 | `opentide tui` ran outside the `human` mode or without a terminal on stdin and stdout |
| `usage_error` | 2 | Another usage error, such as options that cannot be combined, or a command group named without its subcommand (`opentide --json mcp`) |
| `usage_watch_needs_tty` | 2 | `validate --watch` under `--json`, a coding agent or `OPENTIDE_OUTPUT=agent`: it redraws a terminal until Ctrl-C, and nobody would see it |
| `no_tenant_reached` | 2 | `validate query --live` sent no query because no configured tenant takes the rules |
| `query_check_timeout` | 1 | `validate query --live`: every failed check got no answer within `--check-timeout`. `timed_out` lists them |
| `needs_human_decision` | 2 | `migrate vocab-scope` left values only a person can place |
| `not_implemented` | 2 | A reserved command, such as `deploy metadata` |
| `share_unreachable` | 2 | `share`: every failure was authentication or connectivity |
| `share_partial` | 3 | `share`: some objects were shared and some failed |
| `share_failed` | 1 | `share`: objects failed and none succeeded |
| `scope_no_match`, `api_key_unset`, … | 1 | `share` preflight failures; the code is the `preflight` value |
| `reference_not_found` | 2 | `new`: `--objective` or `--threat` names no object in the catalogue |
| `path_exists` | 1 | `new`: the file it would write already exists; it never overwrites |
| `path_not_writable` | 1 | `new`: the folder or the file it would write cannot be written (read-only checkout, permissions) |
| `template_missing` | 1 | `new`: generation ran but wrote no template or schema for the family |
| `doctor_checks_failed` | 1 | `doctor`: at least one check failed. Read `checks` for which |
| `issues_found` | 1 | The command failed on what it found: `validate` errors (or warnings under `--strict`), `validate query` errors (or warnings under `--strict`), `lint --strict` findings, `info --strict` load errors. The findings are in the document |
| `engine_unavailable` | 1 | The analysis engine compiled into opentide does not load: `validate query` offline, `lint` (its `queries` check), and `OPENTIDE_ENGINE=compare` on a command it compares. In `validate`, an `engine_unavailable` issue instead. `advice` names the reinstall command |
| `engine_not_ported` | 2 | [`OPENTIDE_ENGINE=rust`](#choosing-the-implementation) on a command that has no Rust implementation yet; `argument` is `OPENTIDE_ENGINE` |
| `engine_mismatch` | 70 | [`OPENTIDE_ENGINE=compare`](#choosing-the-implementation): the command's Python and Rust implementations did not do the same. `message` names the diff report |
| `config_parse` | 1 | A configuration TOML file does not parse. `diagnostics` holds the file, line and column |
| `yaml_parse` | 1 | `deploy` read a rule file whose YAML is not one mapping. `diagnostics` holds the file and line |
| `not_run` | non-zero | The command was skipped and says why in `message` |
| `command_failed` | 1 | Any other failure |
| `internal` | 1 | An unexpected error: a bug in opentide. See [An unexpected error](#an-unexpected-error) |
| `interrupted` | 130 | [`opentide serve`](./serve.md#cancel): the client cancelled the run |

Exit codes are in [Exit codes](./exit-codes.md). `opentide explain <code>` prints the page for each failure code, as it does for findings ([Diagnostic codes](./diagnostics.md)).

## A usage error

A typo in a command, an option or a value exits `2` with the same document. Case and `-`/`_` do not count against a suggestion: `--type RULE` suggests `rule`. Under `--json` nothing goes to stderr. In this tutorial repository, `opentide --json info rulez` exits `2`:

```bash
opentide --json info rulez
opentide info rulez
```

```json output-of="opentide --json info rulez" exit=2
{
  "error": "Unknown info section: rulez. Choose rules, threats, objectives, coverage, vocab, catalog.",
  "ok": false,
  "status": "failed",
  "message": "Unknown info section: rulez. Choose rules, threats, objectives, coverage, vocab, catalog.",
  "schema_version": 1,
  "command": "info",
  "duration_ms": "...",
  "exit_code": 2,
  "summary": {},
  "next_actions": [],
  "failure": {
    "code": "usage_invalid_choice",
    "message": "Unknown info section: rulez. Choose rules, threats, objectives, coverage, vocab, catalog.",
    "argument": "section",
    "suggestion": "rules",
    "crash_log": null
  }
}
```

Without `--json` the same error is one line on stderr, with the suggestion under it:

```text output-of="opentide info rulez" exit=2
error: Unknown info section: rulez. Choose rules, threats, objectives, coverage, vocab, catalog.
  help: did you mean 'rules'?
```

## An unexpected error

An exception no command handles is a bug in opentide. The run exits `1` and, under `--json`, still prints one document on stdout, with `failure.code` `internal` and `failure.crash_log` naming the log written for it. The message also goes to stderr, for the person reading the terminal. No command in a healthy repository prints this, so the sample is illustrative:

```json illustrative
{
  "error": "RuntimeError: index exploded",
  "ok": false,
  "status": "failed",
  "message": "RuntimeError: index exploded",
  "command": "info",
  "exit_code": 1,
  "failure": {
    "code": "internal",
    "message": "RuntimeError: index exploded",
    "argument": null,
    "suggestion": null,
    "crash_log": "/home/me/.local/state/opentide/crash-20261023T110335102704Z-648.log"
  }
}
```

Where the log goes, what it holds and how to report the bug: [Troubleshooting](../usage/troubleshooting.md#opentide-stops-with-errorinternal).

## Choosing the implementation

opentide is moving its commands from Python to Rust, one at a time ([#790](https://github.com/opentidehq/opentide/issues/790)). Each command has a default implementation, Python until its default changes. `OPENTIDE_ENGINE` chooses another, read when the command starts:

| Value | Runs |
|-------|------|
| empty or unset | The command's default implementation: Python for every command today |
| `python` | The Python implementation, whatever the command's default |
| `rust` | The Rust implementation. A command that has none exits `2` with `failure.code` `engine_not_ported` and `failure.argument` `OPENTIDE_ENGINE`, and so does a run whose input it does not cover yet (`generate docs` on threats that list CVEs while `[cve] retrieve_details` is on: only the Python implementation fetches their details) |
| `compare` | Both, each on its own copy of the workspace, and compares their exit codes, stdout, stderr and the files each created, changed or deleted. JSON is compared by its data, then by the order of every object's keys, then byte for byte. If they agree, the Python run's output and exit code are the command's. If not, the command exits `70` with `failure.code` `engine_mismatch`, and `failure.message` names the diff report. A command that has no Rust implementation, or a run whose input its Rust implementation refuses with `engine_not_ported`, runs Python alone |

Any other value is a usage error (`usage_invalid_choice`, exit `2`, `argument` `OPENTIDE_ENGINE`). `info` (every section), `rules unreviewed`, `generate exports`, `generate docs`, `commands`, `explain`, `lint`, `validate`, `validate query` (offline), `new threat`, `new objective`, `new rule`, `generate` with its phases named (`generate schemas templates`) and `deploy --dry-run` have a Rust implementation today; `rust` refuses the other commands and `compare` runs them on Python alone. A command's Rust implementation can cover only some of its runs: `deploy` runs in Rust with `--dry-run` only, so `rust` refuses a deploy that sends with `engine_not_ported`, and `compare` runs it in Python alone; likewise a bare `generate` (the full pipeline). A command that reaches tenants is routed by the platforms it names: `query` runs in Rust when every `--platform` it names has a query runner (Carbon Black Cloud, CrowdStrike, Defender for Endpoint, Elastic, HarfangLab, Sentinel, SentinelOne or Splunk; not for `--rule` or `--file`), and `validate query --live` when it names its platform: CrowdStrike, HarfangLab and Sysdig answer `supported: false`, and the other six check each rule's queries on their tenants through the Rust connectors; a run on a platform without a Rust connector, or one that names none, is refused by `rust` with `engine_not_ported` (`error: opentide validate query --live without --platform has no Rust implementation yet`) and run in Python alone by `compare`. `compare` refuses `query` itself, which reaches tenants. The variable chooses the implementation, never what a command does: the documents on this site are the contract both implementations print.

A command's default moves to Rust one at a time, in three releases ([#822](https://github.com/opentidehq/opentide/issues/822)):

1. The Rust implementation ships, Python stays the default, and `compare` (in opentide's CI on every corpus, and in yours if you opt in) shows any difference.
2. After a release with no difference, the default changes to Rust, with a changelog entry. `OPENTIDE_ENGINE=python` still runs Python for that release: the escape hatch if your workspace finds what the corpora did not.
3. The release after, the Python implementation goes.

No command's default has changed yet. `opentide serve` and `opentide mcp start` run under any engine: the engine applies to the commands `serve` runs and to the MCP validation tools (`validate_rule`, `validation_report`); `rust` also serves `mcp start` from the Rust server, and `compare` keeps the Python one ([opentide serve](./serve.md#the-rust-engine), [MCP tools](../mcp/tools.md#choosing-the-implementation)). The SDK's `run_validation` follows `OPENTIDE_ENGINE` the same way ([Validation](../sdk/validation.md#choosing-the-implementation)).

Whatever the engine, a command runs in the process you started: `opentide` and `python -m opentide` read `OPENTIDE_ENGINE` before anything else and run a Rust implementation in that process, with nothing in between, so Ctrl-C (`error: interrupted`, exit `130`) and SIGTERM reach the command itself (`opentide serve` exits `143`, `opentide mcp start` ends). Only `compare` starts processes: one per implementation.

```bash
OPENTIDE_ENGINE=compare opentide --json validate
```

The diff report is a JSON file in opentide's state directory, `$XDG_STATE_HOME/opentide/compare/<time>.json` (`~/.local/state/opentide/compare/` when `XDG_STATE_HOME` is unset; `~/Library/Logs/opentide/compare/` on macOS, `%LOCALAPPDATA%\opentide\logs\compare\` on Windows), readable by you alone. It lists each difference with its `target` (`exit_code`, `stdout`, `stderr` or `file:<path>`), its `kind`, the JSON `pointer` where there is one, and the two sides; argument values named like a secret are redacted. Before comparing, both runs are normalised by the goldens' rules (`crates/opentide-compare/src/normalise.rs` lists them): each run's workspace path reads as `<WS>`, wall time as `0`, the clock's date-times on the run's dates and the week before with their digits as `0`, and, for a command that mints identifiers, its fresh UUIDs as `<UUID-n>`. Unlike a golden case, nothing is normalised per fixture. In `compare` both runs print in the mode this one resolved (`OPENTIDE_OUTPUT`, `OPENTIDE_JSON_INDENT`) but to a pipe, and read nothing from stdin, so compare is for scripts and CI, not for prompts or servers. A command that reaches outside the workspace (a tenant, a sharing destination) is refused with `usage_error`: both runs would reach it, and nothing would compare what they did there. It runs inside the workspace: from a folder outside it, or with a path outside it on the command line (absolute, or climbing out with `..`), it exits `2` with `usage_error`, since no copy would isolate what both runs do there. A symbolic link in the workspace that points outside it stays a link to the same place in both copies, so a command that writes through one writes outside, twice; folders the run only creates or removes, empty, are not carried back. When the two agree, the files the Python run changed in its copy are changed in the workspace, and its output names the workspace, as a plain run would. `--help` is printed as usual whatever `OPENTIDE_ENGINE` says.

## Progress events

A document arrives when the command ends. To show progress while a long command runs, set `OPENTIDE_PROGRESS=json`: the command also writes one JSON object per line on stderr as it goes. Stdout is unchanged, still exactly one document, so the redirect below keeps both apart.

```bash
OPENTIDE_PROGRESS=json opentide --json generate 2> events.ndjson
```

```json illustrative
{"event":"progress","step":"schemas","done":3,"total":6}
{"event":"tenant","platform":"sentinel","tenant":"prod","status":"ok","rows":120,"elapsed_ms":1800}
```

| Event | Keys | Sent by |
|-------|------|---------|
| `progress` | `step`, `done`, `total` (`null` when unknown) | `generate` and its subcommands: one per finished phase (`schemas`, `templates`, …). `validate`: `objects` as objects are checked, in batches (about 20 per run, and always the last one, where `done` equals `total`), then `queries` once the query check ran. `validate query`: `queries` once the engine checked them offline (`done` and `total` are the number of queries); with `--live`, one step named after the platform (`Microsoft Sentinel queries`) once its tenants answered. `deploy --dry-run`: one per platform, `step` being the platform. `deploy` and the other commands with steps: one per finished step |
| `tenant` | `platform`, `tenant`, `status` (`ok` or `failed`), `rows`, `elapsed_ms`; `label` when the rule holds several queries | `query`: one per tenant and query, as each answers |

Each event is one line of compact JSON, written whole, in ASCII: a character outside it is a `\u` escape, so the line is JSON whatever stderr's encoding. Log lines share stderr (`OPENTIDE_LOG_JSON=1` makes them JSON too), so a reader keeps the lines whose `event` is `progress` or `tenant`. Under [`opentide serve`](./serve.md) the same events arrive as `progress` notifications instead of on stderr.

## Output modes

opentide decides once per command who is reading. The first rule that matches wins:

| Order | Rule | Mode |
|------:|------|------|
| 1 | `opentide mcp start`, `opentide lsp start` or `opentide serve` | `mcp`: stdout carries nothing but JSON-RPC |
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

In JSON, every `validate`, `validate query` and `lint` finding carries `path`, `line`, `column`, `end_line` and `end_column`: one-based, columns in Unicode code points, the span from (`line`, `column`) up to (`end_line`, `end_column`), `end_column` exclusive and on `end_line`. `end_line` equals `line` for a span on one line. An editor maps them to a range as they are ([validate](./validate.md#diagnostic-fields), [lint](./lint.md#json-findings)).

| Line | Meaning |
|------|---------|
| `✓ …` | Done |
| `! …` | Done, with issues |
| `Skipped: …` | Nothing was done, and why |
| `error: …` | Failed (stderr), followed by indented `note:` and `help:` lines |
| `→ …` | A next step: the command to run, and why |

A console that cannot encode `✓`, `✗` or `→` (a Windows code page, `PYTHONIOENCODING=ascii`) gets `ok`, `x` and `->`.

## The command tree

`opentide --json commands` describes every command an agent can run, with its options, types, choices, defaults, environment variables and an example. See [`opentide commands`](./commands.md).

## Output schemas

Each command in `opentide --json commands` carries `output_schema`: the [JSON Schema](https://json-schema.org/draft/2020-12) of the document it prints, generated from the typed result models in `src/opentide/cli/ui/results/`. It is a `$ref` into the `$defs` of the same document, `anyOf` the command's own result and `CommandError`, the document of a usage error. To check a document against its command's schema:

```bash
opentide --json commands > commands.json
jq '{"$defs": ."$defs"} + (.commands[] | select(.path == "validate") | .output_schema)' \
  commands.json > validate.schema.json
opentide --json validate > validate.json
check-jsonschema --schemafile validate.schema.json validate.json
```

The schemas allow keys they do not name, because new keys are added without notice. A key a schema names keeps its type.

## Related

- [Exit codes](./exit-codes.md)
- [Global options](./global-options.md)
