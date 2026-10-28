---
title: CLI experience
description: The output contract, presentation rules and surface map every opentide command, MCP tool and generated file follows, for people and for agents.
---

# CLI experience

opentide is **spec-driven development for agentic detection engineering**. People and coding agents drive the same commands, so every interaction is designed twice: once for a person reading a terminal or a CI log, once for an agent reading JSON. This page is the contract both renderers follow. Change it before you change the output.

## Principles

1. **One result, many renderers.** A command returns a `CommandResult`. Human text, plain text, JSON and CI annotations are rendered from it, so they cannot disagree.
2. **Semantic density.** Every line carries a status, a subject, a number and a place. No decorative rules, no repeated facts, no "completed" without a count.
3. **Say what happened, why, and the next command.** The fix is a command that can be pasted, or a machine-applicable edit.
4. **Stable codes.** Every finding and every failure has a snake_case code that never changes meaning and has an `opentide explain` page.
5. **Never claim what did not happen.** A dry run "would create". An empty catalogue "passed, but found nothing".
6. **Quiet where machines read.** No animation, prompt or brand mark unless a person is at an interactive terminal.
7. **Additive JSON.** Existing keys keep their name, type and meaning. New information goes under new keys.

## Output modes

Resolved once per process by `opentide.cli.ui.mode.resolve_mode()`. The first rule that matches wins:

| Order | Rule | Mode |
|------:|------|------|
| 1 | `opentide mcp start` | `mcp` |
| 2 | `--json` anywhere on the line | `json` |
| 3 | `OPENTIDE_OUTPUT` is `json`, `agent`, `plain` or `human` | that mode |
| 4 | An agent is detected | `agent` |
| 5 | stdout is not a TTY, `NO_COLOR` is set, `TERM=dumb`, or CI is detected | `plain` |
| 6 | Otherwise | `human` |

| Mode | Behaviour |
|------|-----------|
| `human` | Colour, live progress, clickable paths, brand marks where allowed, next steps |
| `plain` | No animation, no brand marks, `soft_wrap` so paths never break mid-word, colour only when `FORCE_COLOR`/`PY_COLORS` force it |
| `agent` | `plain`, plus: never prompt (exit 2 at once, naming the flags that answer the prompt), and one `tip: add --json for machine-readable output` line on failure |
| `json` | Exactly one JSON document on stdout. stderr carries logs at WARNING and above only (INFO with `--debug`), never findings. No CI annotations. |
| `mcp` | Nothing but JSON-RPC on stdout. Once MCPServer owns the transport, `sys.stdout` points at stderr for everything else; `OPENTIDE_OUTPUT`, agent detection and the envelope do not apply |

**Agent detection** reads `AI_AGENT` (proposed standard, agentsmd/agents.md#136) first, then `CLAUDECODE`, `CURSOR_AGENT`, `GEMINI_CLI`, `CODEX_CI`, `COPILOT_AGENT`, `COPILOT_CLI`, `OPENCODE`, `AMP_CURRENT_THREAD_ID`, `AUGMENT_AGENT`, `CLINE_ACTIVE`. It is a hint: it never relaxes a confirmation, a `--yes` requirement or a strategy check. An agent running in CI (Copilot coding agent, claude-code-action) gets `agent` mode, and the CI annotation sinks still run.

**CI sinks** (`GITHUB_ACTIONS`, `GITLAB_CI`, `TF_BUILD`) are additive to `plain` and `agent`, and off in `json` and `mcp`. GitHub only reads workflow commands from stdout, which is why they cannot coexist with a JSON document there.

## Global flags

The boolean root flags `--json`, `--no-color`, `--debug` and `--quiet` are accepted anywhere before `--`, so `opentide validate --json` works. Hoisting happens in the root `TyperGroup.parse_args`, which runs under `CliRunner`, completion and host apps as well as the console script. It skips a token that is the value of the preceding option of the leaf command (`--query --json` keeps `--json` as the query). There is no short form: `-q` already belongs to `setup skills discover --query`. Value-taking root options (`--repo`, `--data`, `--proxy`) stay before the subcommand.

`--quiet` prints only the outcome line and errors.

`--debug` reads `OPENTIDE_DEBUG`. `DEBUG` is still honoured, but only when its value is a boolean literal (`1`, `true`, `yes`, `on`, and their negatives); any other value, such as `DEBUG='*'` from Node tooling, is ignored instead of failing every command. opentide no longer exports `DEBUG` to child processes.

## Human output grammar

```
<glyph> <subject> <facts> · <where> · <time>
```

| Glyph | Meaning | Fallback when the stream encoding cannot encode it |
|-------|---------|------------------|
| `✓` | done, passed | `ok` |
| `✗` | failed | `x` |
| `!` | warning | `!` |
| `○` | skipped, not applicable (a checklist item) | `o` |
| `+ ~ - ×` | plan: create, update, disable, delete | `+ ~ - x` |
| `→` | next step | `->` |
| `…` | text cut short | `...` |
| `≋` | opentide mark (headers only) | `opentide` |

Every command ends with **exactly one outcome line**. Warnings print before it. At most three next steps print after it, and only when there is something to do. Engine modules stop printing directly: section headers (`emit_section`) become progress steps owned by the CLI, and Rich panels move out of services into renderers.

| Command | Outcome line (examples) |
|---------|-------------------------|
| `validate` | `✓ 3 objects valid · 0.9s` / `✗ 2 errors in 1 file · 3 objects checked · 0.9s` |
| `lint` | `✓ 42 files clean` / `! 3 findings in 2 files` (+ `→ opentide lint --fix` only when filename findings exist) |
| `info` | the table, then `1 rule · 1 threat · 1 objective · 0 load errors` |
| `setup skills discover` | the table, then `✓ 31 skills available · 2 installed · opentidehq/skills@main` |
| `generate` (all phases and subcommands) | `✓ Generated 28 files in 4.8s · 6 phases` |
| `generate extract <platform>` | `✓ Imported 14 rules from sentinel · 2 skipped` |
| `deploy --dry-run` | `Plan: 1 to create, 0 to update, 0 to disable, 0 to delete` (the plan's header names `1 platform, 0 tenants`), then `dry run, nothing sent` |
| `deploy` | a line per rule as it is sent, then `✓ Deployed 3 rules to 2 tenants · 1 created, 2 updated · 0 failed, 0 not attempted · 12.4s` / `✗ Deployment failed · 2 created or updated, 1 failed, 88 not attempted · 14s` |
| `deploy migrate-state` | `✓ Moved 6 vendor ids to .opentide/states/deployment/` |
| `validate query --live` | `✓ 12 queries valid on 2 tenants` / `error: Queries rejected on sentinel · 12 checked on 2 tenants` / `Skipped: no configured tenant reached` |
| `setup` and its subcommands | `✓ Created Tutorial Detections in ./tutorial-detections` / `✓ Wrote .vscode/settings.json` |
| `share push/preview/status/retract/targets` | `✓ Shared 4 objects to misp-prod · 3 new, 1 updated` |
| `rules unreviewed` | `! 5 rules unreviewed for 90 days` / `✓ Every rule reviewed in the last 90 days` / `Skipped: No rules yet` |
| `migrate objects/vocab-scope` | `Would move 12 files` (dry run) / `✓ Moved 12 files` |

Exempt: `--version` (plain `opentide <version>`, even with `--json`, as documented), `mcp start`, hidden `deploy replay-state`.

Paths are relative to the current directory when inside it, otherwise to the workspace, and carry `:line:col` when known. In `human` mode they are OSC 8 links. The scheme is `file://<abs>` by default; `vscode://file/<abs>:<line>:<col>` when `TERM_PROGRAM=vscode`; and `OPENTIDE_LINKS=file|vscode|cursor|none` overrides it, because Cursor also reports `TERM_PROGRAM=vscode`.

**Severity words** are `error`, `warning`, `note`, `help`. `FATAL` and a traceback are reserved for crashes.

**Each fact once.** A condition is either logged or returned in `warnings`, never both. In human mode a warning the result already reports is logged at DEBUG. Log lines carry one level label and readable text, never a raw event slug.

## Diagnostics

A **diagnostic** is the shape every finding takes: validation issues, lint findings, deploy and query failures, and share errors. Commands keep the lists they already return (`report.issues`, `findings`, …). Each entry gains these fields, **additively**:

| Field | Type | Notes |
|-------|------|-------|
| `code` | str | Stable snake_case (`invalid_ref`, `vocab_unknown`, `yaml_parse`, …). Already present on validation issues. |
| `severity` | `error` · `warning` · `note` | |
| `message` | str | One sentence, in the user's words |
| `path` | str \| null | Workspace-relative. `file_path` stays absolute for compatibility. |
| `line` | int \| null | **1-based.** `yaml_line` stays 0-based for compatibility. |
| `column`, `end_column` | int \| null | 1-based, best effort, from ruamel's `lc` positions; null when unknown |
| `field_path` | list[str] | YAML path |
| `help` | str \| null | Suggestion in prose (`did you mean …`) |
| `fix` | object \| null | `{ "safe": bool, "edits": [{ "line", "column", "end_column", "replacement" }] }`. `opentide validate --fix` applies every safe edit; an agent can apply any of them. |
| `explain` | str | `opentide explain <code>` |

Rendered in `human` and `plain`:

```
error[vocab_unknown]: 'clearr' is not a TLP value
  ╭─▶ objects/rules/sentinel-kql-rule.yaml:8:8
  │
7 │   modified: 2026-01-02
8 │   tlp: clearr
  │        ━━━━━━ not in tlp::1.0
  │
  ╰─ help: did you mean 'clear'?
```

One finding per cause: an `invalid_ref` and a `vocab_unknown` on the same field and value merge into the `invalid_ref`. YAML parse errors name the file and position, never `<unicode string>`.

`opentide explain <code>` prints what the code means, an example and how to fix it. Pages live in `src/opentide/data/diagnostics/<code>.md` and are rendered into `docs/cli/diagnostics.md`.

## JSON output

Every command in `json` mode prints one document. These keys are added; none of the existing keys change.

| Key | Type | Meaning |
|-----|------|---------|
| `schema_version` | int | `1` |
| `command` | str | `validate`, `generate docs rules`, … |
| `duration_ms` | int | Wall time |
| `exit_code` | int | The process exit code |
| `summary` | object | Counts for the outcome line (`objects`, `errors`, `warnings`, `files`, `created`, …) |
| `next_actions` | list | `[{ "command": "opentide --json validate --type rule", "reason": "…" }]` |
| `failure` | object \| null | `{ "code", "message", "argument", "suggestion", "crash_log" }` |

`error` stays a string, as today. `ok`, `status` and `message` keep their meaning.

Usage errors produce this document too, with `failure.code` in `usage_unknown_command`, `usage_unknown_option`, `usage_invalid_choice`, `usage_missing_option`, `usage_needs_input` (a prompt with no TTY).

JSON is indented on a TTY and compact (one line) otherwise; `OPENTIDE_JSON_INDENT=0|2` overrides.

`opentide commands --json` prints the command tree: commands, options, types, choices, defaults, environment variables, an example for each, and the JSON Schema of each command's output, generated from typed result models.

MCP tool payloads keep their shapes. MCP gains the same issue codes and diagnostic fields, an `explain` tool and the tagline in its instructions.

## Exit codes

| Code | Meaning |
|-----:|---------|
| `0` | Success |
| `1` | Failure |
| `2` | Usage error. Also, as documented today: `validate query --live` skipped, `share` authentication or connectivity failure, `migrate vocab-scope` values that need a human decision |
| `3` | `share` partial success, as documented today |

`failure.code` tells the cases apart. **Behaviour change:** app-level usage errors (an unknown `info` section, an unknown `generate` phase, an invalid `--type`, an unknown `share --target`, a `setup` prompt with no TTY) exit `2` instead of `1`, as `docs/cli/exit-codes.md` already promises. The changelog says so.

## Errors people and agents make

| Input | Response |
|-------|----------|
| Typo in a command, option or choice | `did you mean …?` with the valid values, exit 2. A choice that differs only in case or `-`/`_` wins outright (`RULE` → `rule`); otherwise app-level choices use `difflib.get_close_matches` on the lower-cased spellings. |
| `--json` after the subcommand | Accepted |
| A prompt with no TTY or under an agent | Exit 2 at once, naming the flags that answer it |
| `DEBUG='*'` in the environment | Ignored |
| Unexpected exception | `error[internal]: <Type>: <message>`, the crash log path, a pre-filled issue link; the traceback only with `--debug`. Always on stderr. The log goes to `$XDG_STATE_HOME/opentide/` (platform equivalent elsewhere), never into the repository, with proxy credentials, tokens and tenant secrets redacted. |

## Brand in the terminal

Assets: `opentidehq/.github/assets` (Pantone Reflex Blue `#001489`, white, the Material "Tsunami" icon, the pill logo, Inter SemiBold). `opentide.cli.ui.brand` holds the marks as pixel grids rendered with upper half-blocks:

| Mark | Size | Where |
|------|------|-------|
| Pill logo | 80 × 10 | `setup` wizard welcome only |
| Icon | 28 × 14 | bare `opentide` home screen |
| One-line pill `▐ ≋ opentide ▌` | 1 line | section headers; the home screen narrower than 76 columns, the welcome narrower than 82 |

Rules: only in `human` mode, and only when the stream encoding can encode the block characters (otherwise none). Blue is a fill, never a text colour. `NO_COLOR` on its own selects `plain` (row 5 of the precedence table), so it prints no mark; where `human` is chosen explicitly (`OPENTIDE_OUTPUT=human`) on a console without colour, the marks keep their shapes in the terminal's foreground colour (`brand.is_mono()`). No yellow, no gradients. `print_banner()` is public API: it is deprecated with a warning and renders the new mark, and is removed in a later release. `coretide-logo.png` is removed.

**Tagline**, wherever the product describes itself: *Spec-driven development for agentic detection engineering.* Retired: "DetectionOps", "DetectionOps engine", the `detection-ops` skill pack name (installed packs keep working through an alias), "MDR" in user-facing text, "CoreTIDE". Not renamed: the Elastic managed-rule tag `OpenTide` (a deployed identifier) and the deprecated `OpenTide` class alias.

## Surfaces

| Surface | Contract |
|---------|----------|
| Interactive terminal | Human grammar, progress, home screen, brand marks |
| Pipes, `NO_COLOR`, pre-commit hooks | Plain grammar, no animation |
| CI logs | Plain or agent grammar, plus annotations and step summary |
| Pull requests | Inline annotations, deploy plan in the job summary |
| Coding agents (shell) | Agent mode, JSON keys above, `commands --json`, `explain` |
| MCP server | `mcp` mode; same codes and diagnostic fields; instructions carry the tagline |
| Agent instruction files (`setup skills`) | Tell agents to run `opentide --json …`, read `fix` and `next_actions`, and branch on exit codes and `failure.code` |
| Editor (schemas, snippets) | Vocabulary enums carry descriptions; schema titles use the tagline |
| Setup wizard | Branded welcome, visible validation, summary and next steps |
| Help and completion | Grouped panels (Author, Ship, Workspace, Agents and integrations), an example per command |
| Logs (`--debug`, JSON) | One level label, readable text, no duplicates of returned warnings |
| Windows consoles | Glyph and brand fallbacks by stream encoding |
| Docs, website, PyPI | Tagline, `json-output.md`, `diagnostics.md`, updated exit codes |

## CI

| Provider | Inline | Summary |
|----------|--------|---------|
| GitHub Actions | `::error file=,line=,col=,title=<code>::<message>` per diagnostic, on stdout, never wrapped | Markdown to `$GITHUB_STEP_SUMMARY` |
| GitLab CI | `--format codequality` writes Code Climate JSON for `artifacts:reports:codequality` | Markdown artifact |
| Azure Pipelines | `##vso[task.logissue type=…;sourcepath=…;linenumber=…;columnnumber=…;code=…]` | `##vso[task.uploadsummary]` |

`--format sarif` writes SARIF 2.1.0 for code scanning. `opentide setup ci` wires these into new pipelines.

## Libraries

One new runtime dependency, `textual`, for `opentide tui`.

| Package | Use |
|---------|-----|
| Typer 0.27 (kept) | `rich_help_panel`, `epilog`, autocompletion callbacks; a root `TyperGroup` subclass for flag hoisting and lazy command loading. Not migrating to cyclopts or rich-click: Typer already renders Rich help. |
| Rich 15 (kept) | Console, `Live`/`Progress`/`Status`, `Table.grid`, OSC 8 links, `export_text` for snapshot tests |
| structlog (kept) | Logs only. Presentation never goes through logging. |
| questionary (kept) | Wizard prompts, restyled to the brand |
| orjson (kept) | JSON output |
| stdlib | `difflib` (did you mean), `importlib` (lazy loading) |
| syrupy, pexpect (dev, kept) | Snapshot tests of every renderer at fixed width; the wizard on a real PTY |
| textual (new) | `opentide tui` only, imported lazily so it never affects start-up |
| Not added | `agent-detector` (a dozen env checks), `sarif-om` (SARIF is a small dict), `trogon` (early-stage; the TUI is built on Textual directly), `watchfiles` (`--watch` polls modification times) |

`src/opentide/cli/ui/` is inside ty's checked scope even while the rest of `src/opentide/cli` is excluded.

## Performance

| Command | Budget (warm cache) | How |
|---------|---------------------|-----|
| `opentide --version` | < 120 ms | Answered in `main()` before Typer is imported |
| `opentide --help`, completion | Import no engine module | Commands load lazily from modules; help text comes from a static registry; `opentide/__init__` resolves `Opentide` lazily |

Tests assert the import graph (which modules a command imports), not wall-clock time, so they hold on every Python version in the CI matrix.

## Authoring loop

| Command | Contract |
|---------|----------|
| `opentide validate --fix` | Applies every `fix` with `safe: true`, re-validates, prints `✓ Fixed 3 values in 2 files` and the remaining diagnostics. `--fix --dry-run` prints the edits as a diff. Never touches unsafe fixes. |
| `opentide validate --watch` | Re-validates changed objects on save (mtime polling, 0.5 s) in a Rich Live view in `human` mode; one outcome line per run in `plain`; refused in `json`, `agent` and `mcp` modes with exit 2. Ctrl-C exits 0. |
| `opentide new rule\|threat\|objective` | Scaffolds from the generated template with a fresh UUID v4, today's date, the git author and organisation; `--platform`, `--name`, `--objective` pre-fill; prompts only in `human` mode; prints the path and the next command (`opentide validate --file …`). |
| `opentide doctor` | One checklist: Python and package version, workspace found, git and default branch, schemas and templates fresh, enabled platforms, SDKs importable, credentials present (never printed), proxy reachable, editor settings, MCP config. Each check has a code, a status and a fix. Exit 1 when any check fails. |

## Terminal integration

- Shell completion completes `--uuid` with rule UUIDs and names, `--technique` with ATT&CK ids and titles, `--platform` with enabled platforms first, `--file` with object paths, `explain` with diagnostic codes. Completion reads the generated exports, never the full registry, so it stays fast.
- Long runs emit OSC 9;4 progress in terminals that support it (Windows Terminal, Ghostty, kitty, WezTerm, iTerm2; detected from `WT_SESSION`, `TERM_PROGRAM`, `TERM`), only in `human` mode, cleared on exit and on Ctrl-C. `OPENTIDE_PROGRESS=0` disables it.

## TUI

`opentide tui` opens a Textual app: the catalogue as a tree (threats → objectives → rules), a detail pane with the object's YAML and its diagnostics, coverage by ATT&CK technique, and actions that run `validate`, `generate` and `deploy --dry-run` through the same `CommandResult` renderers. It is refused outside `human` mode.

## Editor

Generated JSON schemas carry `title` and `description` for every field, `markdownDescription` where Markdown helps, and per-value descriptions for vocabulary enums (`enumDescriptions` for VS Code, `x-enumDescriptions` mirrored for other editors), taken from the vocabulary TOML. The schema `$comment` and title name the tagline. Snippets carry descriptions.

## Built so far, and deviations

The whole CLI rework is merged: the output contract (#619), diagnostics and `explain` (#620), CI sinks (#621), the flow (#622), agents and MCP (#623), the crash handler (#625), `new` and `doctor` (#628), typed results and JSON indentation (#629), `validate --fix` and `--watch`, completion and terminal progress, and `opentide tui` (#632). Where it differs from the sections above, the code is right and this list says how:

| Topic | As built |
|-------|----------|
| Logs under `--json --debug` | DEBUG and above, like `--debug` in every other mode (not INFO). Without `--debug`, `--json` and the MCP server log WARNING and above. |
| JSON indentation | Built (#629). Indented when stdout is a TTY, one compact line otherwise; `OPENTIDE_JSON_INDENT=0|2` overrides, and any other value is ignored. Every document, usage errors included, ends in exactly one newline. |
| `failure` | Set on every non-zero exit, `ok` true or not, so `failure.code` tells the cases of one exit code apart; `null` exactly when `exit_code` is `0`. Codes in use: the five `usage_*` codes above plus `usage_invalid_value`, `usage_error` and `usage_watch_needs_tty` (`validate --watch` in `json`, `agent` or `mcp` mode); `command_failed`, `issues_found` (`--strict`), `not_run`; `no_tenant_reached`, `needs_human_decision`, `not_implemented`; `share_failed`, `share_unreachable`, `share_partial`, and the share preflight codes (`scope_no_match`, ...); `internal` for an unexpected exception (#625). The list is in `docs/cli/json-output.md`. |
| Outcome lines | The glyph grammar is in place. `validate`, `lint` and `info` print the counted wordings of the table above (#620), and so do `generate` (every phase and subcommand, `extract`), `deploy` (plan and real run), `deploy migrate-state`, `setup` and its subcommands, `share`, `rules unreviewed` and `migrate` (#622). The JSON `message` keeps its old text: the printed line comes from `CommandResult.outcome` (payload key `_outcome`), and its kind, when the status alone does not say, from `CommandResult.outcome_kind` (payload key `_outcome_kind`). A skipped result prints `Skipped: <message>`. A command that fails on findings it printed (`failure.code` `issues_found`) prints its outcome line as `✗ …` on stderr instead of `error: <message>`. `migrate objects` counts folders, not files (`Would move 3 folders · pass --apply to migrate`), because it moves folders. Every dry run (`migrate`, `share preview`, `deploy --dry-run`) prints its line without a glyph (`_outcome_kind: plan`). `validate query --live` cannot count rejected queries, because the validators report a rejection as a run flag: its failure counts what was checked (`Queries rejected on sentinel · 12 checked on 2 tenants`). |
| Progress | Engine modules call `opentide.core.progress.report_stage()`; the CLI's `Checklist` shows the stage beside its running step. `emit_section()` stays public and forwards to the running checklist when there is one. Plain step lines go to stderr; the outcome line stays on stdout. Generation counts the files a phase wrote by comparing modification times and sizes under the workspace before and after it. |
| Deploy plan | A platform that writes a rule by its UUID (Sentinel, Splunk, Elastic, Carbon Black, HarfangLab) cannot tell a create from an update without asking the vendor: its rows say `+ create or update`, and the tally adds `N to create or update` when N is not 0. Create and update come from `.opentide/states/deployment/` for Defender for Endpoint, SentinelOne and CrowdStrike. The tally prints without a glyph (`_outcome_kind: plan`), because nothing happened, and without `error:` when a rule would fail to deploy: each such rule prints above it as #641's code frame (`error[compile_…]: message`, `╭─▶` its file, `╰─ help:`) (`diagnostics` in JSON), and the exit code is 1. The platforms and tenants it covers are on the plan's header, so the tally fits 100 columns. A dry run sends nothing, so an unset `$VARIABLE` is one warning (`a real deploy would need $…`), not an error. |
| Brand | The pill logo, rasterised as prototyped, is 80 × 10 cells (not 73): the welcome falls back to the one-line pill below 82 columns, the home screen below 76. |
| Soft wrap | Outcome, warning, error and next-step lines are soft-wrapped in `human` mode too, not only `plain`: Rich would otherwise break a long path mid-word on a TTY. At a terminal, a line wider than the window is broken between words and continued under its text (`opentide.cli.ui.render.word_wrap`); a word is never split, so a path wider than the row stays whole. A pipe or CI log keeps one line. |
| Unexpected exceptions (#625) | Handled in the console script, `opentide.cli.main()` (and `python -m opentide`). `app()` called directly, `CliRunner` and host apps still see the exception, so tests that check `result.exception` keep catching crashes. The traceback under `--debug` is redacted like the log. Ctrl-C exits 130 with `error: interrupted` on stderr in every mode, `json` included: no document, because the run did not finish. |
| `opentide --json` with no command | The bare root still prints help, not a JSON document, and exits `0` in every mode (a person at a terminal gets the home screen, also `0`); Click's `no_args_is_help` exited `2` for the same request. A group named without its subcommand (`opentide --json mcp`) is a `usage_error` document in `json` mode and an `error:` line in `agent` mode; a person still gets the group's help. |
| `opentide tui` (#632) | Refused, with `usage_tui_needs_tty`, outside `human` mode and also when stdin or stdout is not a terminal (`OPENTIDE_OUTPUT=human` alone does not give Textual a terminal). At a terminal, a setting that selects `plain` (`NO_COLOR`, `--no-color`, CI, ...) refuses too, naming the setting, with `help: set OPENTIDE_OUTPUT=human to open it anyway`. Quit waits for a running command, since a worker thread cannot be cancelled. Its deploy actions are `deploy --dry-run --strategy PREVIEW --all` and `... RELEASE --all`. Results print through `opentide.cli.output.render_result()`, the body of `emit_result()`, into a recording console. Textual loads from `opentide.cli.tui_app` when the UI opens, never for `opentide tui --help` or a walk of the command tree. Diagnostics show the frame's header, location and help (`╭─▶ path:line`, `╰─ help: …`) without source lines, which the detail pane shows. The Results tab prints each command as the CLI does: `validate`'s findings through #641's `render_diagnostics` (source lines included) and its counted outcome line, a dry run's plan through #643's `render_plan` and its compile failures through `render_plan_diagnostics`, and next steps in their human form (`opentide validate`, not `opentide --json validate`, although the services run with `json_output` set). |
| `opentide new` (#628) | Subcommands `new threat`, `new objective` (`--threat`), `new rule` (`--platform`, `--objective`). The workspace configuration has no organisation key, so the organisation is the one most catalogue objects carry. Required values nobody chose are placeholders (the schema's first allowed value, or `...`), listed under `placeholders`, so the file validates at once. TLP starts at `amber`; a platform block starts at the first `INERT` status. A rule keeps the commented blocks of its own platforms only, with a comment pointing at the template, and each block holds what its deploy compile needs (Sentinel's schedule and grouping; `response` takes the template's defaults), so moving the status to a `PREVIEW` one is enough for `deploy --dry-run` to compile it. Generating missing templates first is a step, not a warning. Failure codes `path_exists`, `reference_not_found`, `template_missing`. |
| `opentide doctor` (#628) | Statuses `pass`, `warn`, `fail`, `skip`; each check carries `subject` too. `--offline` skips the network checks. Schema freshness checks that every schema this version generates exists (schemas carry no version stamp); template freshness compares the files with a fresh render. A skipped check prints `○`, which the grammar table above adds for it: the plan's `-` means disable. Failure code `doctor_checks_failed`. |
| Diagnostics | Built for `validate` and `lint` (#620). `end_column` is exclusive (one past the last character), so an edit replaces `[column, end_column)`. Lint's JSON `severity` stays `info` (an existing value); its frame prints `note`. Lint findings gain `code` and `field_path` too. Columns are Unicode code points, not UTF-16 units: SARIF sets `columnKind: "unicodeCodePoints"`, LSP converts. `line` points at the key of a block value, so it is not always `yaml_line + 1`. `TextEdit` has `end_line` (equal to `line` for an edit within one line). A fix is `safe` only when the values spell the same word (case, spaces, `-`, `_`) and hold no digit, so no identifier (ATT&CK id, UUID, CVE) is ever replaced unreviewed; an `invalid_ref` fix is never safe. Every suggested value still gets an unsafe fix. |
| `invalid_ref` + `vocab_unknown` | Merged in the engine (`merge_reference_findings`), so MCP and JSON see one finding as well. `invalid_ref` issues carry `context.value`. |
| YAML parse errors | `describe_yaml_error()` gives the problem, its 1-based position and the parser's context; the registry stores that text, and `validate` reports the file once (the registry logs it at DEBUG during `validate`). |
| `opentide explain <code>` | Prints the page: rendered Markdown in `human`, the Markdown source in `plain` and `agent`, `{code, meaning, markdown}` in JSON. No outcome line, like `--help`. With no code it lists every code and ends with `✓ N diagnostic codes`. |
| `validate --fix` | Applies each safe edit as a text splice at the position ruamel reported, not by dumping the document through ruamel, which re-indents and re-wraps: every byte outside the edit is kept. An edit is kept only when `is_safe_replacement()` still holds for the text found at the span (the file may have been saved since validation read it), and the file still parses and differs in that one value. Files are written to a temporary file in their directory (mode copied, symlinks resolved) and moved into place with `os.replace`, and only while they still hold the text the plan read; otherwise the outcome line says `could not write N fix(es)`. One outcome line: `✓ Fixed 3 values in 2 files · 3 objects valid · 0.9s`, or `✗ 1 error in 1 file · fixed 3 values in 2 files · 3 objects checked · 0.9s` (`no safe fix to apply` when there was none to apply), after a `fixed:` line per value. JSON: `fixed`, `summary.fixed`; every `validate` also has `summary.fixable`, and its outcome line says `3 fixable with --fix`. `--fix --dry-run` prints the diff, then the frames of findings it would not fix, and keeps validate's exit code (`1` while the files have errors); JSON `would_fix` and `diff` instead of `fixed`. `--dry-run` without `--fix` and `--watch --fix` are `usage_error`. |
| `validate --watch` | Rich `Live` directly (`opentide.cli.ui.watch`), not PR E's progress primitives. Every pass rebuilds the registry, because `run_validate` resets it; the scoped pass saves the object checks only. A pass is full when a file was added or removed, a UUID in it changed, or its object entered or left the registry (a finding in `UNREGISTERED_CODES`, `yaml_parse` or `missing_uuid`, before or after, or a scoped object count that does not match). In `plain` each pass prints the frames it produced, then its outcome line. The Live view crops the frames to the terminal height (`… N more lines`) so the outcome line and the footer stay on screen. |
| `info` with load errors | `status` is `issues` and the next step is `opentide validate`; `--strict` fails with `issues_found`. The registry logs each unreadable file at DEBUG during `info`, which counts it. |
| CI sinks | Built for `validate` and `lint` (annotations and a findings summary), `deploy` (plan summary) and `validate query` (queries per tenant) (#621). Detection is `detect_ci()`, so `GITHUB_ACTIONS`, `GITLAB_CI` or `TF_BUILD`; a plain `CI` turns nothing on. Off whenever `--json` is on, and in `mcp`. A note is a GitHub `::notice` and gets no Azure issue (Azure has no such level). GitHub's `endColumn` is inclusive, so it is `end_column - 1`, with `endLine` repeating `line`. The annotation message is the message and, on a second line, `help: …`. Paths are relative to the checkout (`GITHUB_WORKSPACE`, `CI_PROJECT_DIR`, `BUILD_SOURCESDIRECTORY`) when the file is inside it, else the workspace path. The GitLab summary is appended to `opentide-reports/summary.md` in the checkout; the Azure summary is one file per run in `AGENT_TEMPDIRECTORY`. A summary that cannot be written is skipped. `--quiet` does not reduce annotations. GitHub shows 10 annotations per level per step, so GitHub gets errors, then warnings, then notices, 10 of each (`GITHUB_ANNOTATIONS_PER_LEVEL`), then one `::notice title=opentide::N more findings: see the job summary or code scanning`; Azure is not capped. Summary cells escape `&`, `<`, `>` as entities and inline Markdown punctuation with a backslash; a summary is cut to `MAX_SUMMARY_BYTES` (256 KiB), a deploy error to two lines, and a usage failure (exit 2) writes none. The deploy "no rule to deploy" warning is a run-level annotation on GitHub and now on Azure too. |
| `--format`, `--output` | On `validate` and `lint` only: `text` (default), `sarif`, `codequality`. Without `--output` the report is the whole of stdout (no frames, no outcome, no sinks); with it, the file is written and the usual output follows. `--json --format X` without `--output`, and `--output` with `--format text`, exit 2 with `usage_invalid_value` (`check_report_options()`). Findings with no file are left out of both reports (code scanning and Code Quality need one). SARIF lists a rule for every code in `VALIDATION_CODES`, `LINT_CODES` and the explain pages, sets `columnKind` to `unicodeCodePoints` (the columns of `Diagnostic`), percent-encodes each `artifactLocation.uri` (`quote(path, safe="/")`) with `uriBaseId` `%SRCROOT%`, puts the explain page in `help.markdown` and a plain-text copy in `help.text`, names `object_uuid` as a `logicalLocations` entry of kind `object`, has `automationDetails.id` `opentide/<command>/`, and turns fixes into `fixes[].artifactChanges` whose regions end at `TextEdit.end_line`. |
| `setup ci` reports | The validate job writes reports to `opentide-reports/`. GitHub: SARIF, uploaded as an artifact; on public repositories only, a `code_scanning` job (`needs: validate`, `permissions: security-events: write` and nothing else) downloads it and runs `upload-sarif@v4` (`continue-on-error`, no `category`: the run's `automationDetails.id` is the category). The validate job keeps the default permissions. GitLab: Code Quality under `artifacts:reports:codequality`, and every job that runs opentide keeps `summary.md` (`when: always`). Azure: SARIF published as `CodeAnalysisLogs`. |
| Tests and CI variables | The root conftest removes `CI`, `GITHUB_ACTIONS`, `GITLAB_CI`, `TF_BUILD` and `GITHUB_STEP_SUMMARY` for every test, so the suite in GitHub Actions neither prints annotations nor writes to its own job summary. A test that needs a provider sets it. |
| `opentide commands` | Built (#623). `--json` gives `program`, `version`, `global_options`, `environment` (every `OPENTIDE_*` variable the code reads, the root options' own included, plus `NO_COLOR` and the agent-detection variables; `test_environment_names_every_variable_the_code_reads` greps `src/` for quoted `OPENTIDE_*` names and fails on one the list leaves out, except four that no user sets: `OPENTIDE_PERSIST_STATE_EXTERNALLY`, `OPENTIDE_DEPLOY_STARTED`, `OPENTIDE_ATTACK_STIX_DIR`, `OPENTIDE_SPECIFICATIONS_ROOT`) and `commands`: flat, depth-first, in `--help` order, each with `path`, `summary`, `help`, `group`, `runs_alone`, `subcommands`, `deprecated`, `arguments`, `options` (`flags`, `type`, `choices`, `default`, `required`, `multiple`, `is_flag`, `envvars`, `help`) and `example`. Hidden commands and options, `--help` and the completion options are left out. Values a command checks itself are listed in `choices` from `_app_choices()` (`validate --type`, `deploy --strategy`, `info`'s section; not `share --target`), and a test checks each against the command's own refusal. Option `help` is unescaped. Each entry also has `output_schema`, the JSON Schema of its `--json` document (#629): `anyOf` a `$ref` to the command's result model and to `CommandError` (a usage error, or an error with nothing else to say), resolved against the document's top-level `$defs`; `CommandError` alone for a group that only prints help (it prints a document only for a usage error) and for hidden `deploy metadata` and `deploy replay-state`; `null` for `mcp start`. The schemas are built only under `--json`. The example is the first `$ opentide …` line of the command's epilog (the help examples, `opentide.cli.help.EXAMPLES`, which every visible command has), else a placeholder: the command with its required arguments and options filled in, which may not run as it is; a group that only prints help takes its first subcommand's. Human mode prints the tree and `✓ N commands`. Walking the tree imports each root command's module once and never builds the registry. `CommandSpec.epilog` gives `commands` its `Examples` block. |
| Typed results | Built (#629). Pydantic models in `opentide.cli.ui.results`, one per command path (`RESULT_MODELS`), built from what the services return, every key optional unless every path sets it. They allow unknown keys (the contract is additive), and production code never validates against them. The test suite does: in every `cli_e2e` test, each document the CLI prints is checked against its model and its schema, and a key no model names fails (`tests/result_models_support.py`). Every command has a model: `new threat|objective|rule` (`NewResult`), `doctor` (`DoctorResult`), and `tui`, which refuses `--json` and so only prints a usage error (`CommandError`). `PENDING_MODELS` is empty; a future root command registers a model or lists itself there, and `tests/test_cli/test_result_models.py` fails otherwise. MCP payloads have no models. |
| MCP | Built (#623). `validate_rule` (`issues`) and `validation_report` (`issues`, `warnings`) gain the diagnostic fields through `annotate_report()`, like `validate`. `next_actions` are `{tool, arguments, command, reason}`: the MCP call, plus the CLI's `{command, reason}`. They appear on `validate_rule`, `validation_report` and a refused `validate_query`; other payloads are unchanged. A result with errors points at `explain` for the first error code (each issue's `explain` field names its own), then at the same validation again: within the CLI's three next steps. Every `command` runs: the deploy step passes the `--strategy` values that deploy the rule's status on that platform and `--all` (none for `INERT`), the live query step's reason says it contacts the tenant and to ask first, and an unknown rule points at `search` with an empty query. `validate_query`'s description takes its platforms from `QUERY_VALIDATION_PLATFORMS`. `explain(code)` returns the CLI's `{code, meaning, markdown}` with `found`; an empty code lists every code. The server `instructions` (`INSTRUCTIONS` in `opentide.mcp_server.server`) carry the tagline and the agent workflow. |
| Agent instruction files | Built (#623). `AGENTS.md.template`, `CLAUDE.md.template`, `copilot-instructions.md`, the `detection-workflow` pack (named `detection-ops` before #634, which still resolves through an alias) and the four authoring skills tell agents to run `opentide --json …`, branch on the exit code first and read `failure.code` for the detail, apply `fix`, follow `next_actions` and use `opentide explain`. The Quick start deploy line is `opentide deploy --dry-run --strategy PREVIEW --all`. `tests/test_cli/test_agent_instructions.py` parses every command they, the MCP `next_actions`, `INSTRUCTIONS` and the agent docs quote with Click's `make_context` (unknown options, bad choices, extra arguments and missing required options fail), and `tests/test_cli/e2e/test_agent_commands_e2e.py` runs the read-only ones on the tutorial workspace and asserts no exit 2. |
| Suggestions | A value that spells an allowed one in another case or with other separators (`AMBER`, `localised_incident`) is suggested outright, with a safe fix; otherwise `difflib` compares the values without case (`opentide.validation.vocab_resolver.closest_value`). A platform block's `status` is checked against `[[statuses]]` (deploy matches it by exact name), so `design` is a `config_enum_unknown` error with a safe fix to `DESIGN`. App-level `did you mean` (`contract.did_you_mean`) is not changed here. |
| Diagnostic messages | The printed message is the spec's wording (`'clearr' is not a TLP value`, `missing required field 'description'`, `'design' is not a configured status`); the JSON `message` of each issue keeps the engine's sentence. A missing top-level field is framed at the file's first key. |
| Files the user must fix | A TOML syntax error under `.opentide/configurations/` raises `ConfigFileError`, and an object file that `deploy` reads but is not one mapping raises `ObjectFileError` (both `opentide.core.errors.UserFileError`). `LazyTyperGroup.invoke` renders it as a frame (`config_parse`, `yaml_parse`) and exits 1 with that `failure.code`; the JSON document carries it under `diagnostics`. The outcome is `✗ 1 configuration file does not parse`. |
| `next_actions` on a failed `validate` | `opentide explain <first code>` ("how to fix it"), then `opentide validate` (`opentide --json validate` in JSON), like MCP's `validation_report`. When a fix is safe, the MCP re-run step is `opentide --json validate --fix …` (#646); the CLI's own next steps keep `opentide validate`, and its outcome line says `N fixable with --fix`. |
| `explain` pages | Failure codes have pages too (principle 4), so `opentide explain` lists both kinds and counts them as `diagnostic codes`. `config_parse` covers every configuration TOML, not only `sharing.toml`. |
| Frames on a narrow terminal | On a terminal, the header and the notes are wrapped at a space or after a `/`, and the location is shortened in the middle (`objects/…/rule.yaml:8:8`); source lines and piped output stay whole. |
| `lint --fix` | The outcome counts the findings left, then `· N fixed`; a run whose findings were all fixed passes. With more than one severity left it adds `· 2 warnings, 13 notes`. |
| Completion sources | Object UUIDs, names and paths come from the first lines of each object file (`name`, `metadata.uuid`), not from `objects.export.json`: the export is written only by `generate exports objects`, goes stale between runs, and has no file paths. ATT&CK titles come from a line scan of the bundled `att&ck.vocab.toml`, not a TOML parse. Sources attach by option name when a command loads, so every `share` subcommand completes like `share`. Completing a value does not load the command: `INDEXED_OPTIONS` lists each command path's completed options, a test keeps it equal to what the loaded commands attach, and the platform and strategy values are copies checked against `DetectionPlatform` and `DEPLOYABLE_STRATEGIES` (importing either loads the engine). A command line the index cannot read word by word (an unindexed option before the one completed, a positional argument, `--`) falls back to Click, which loads the command. Completing an option or subcommand name loads the command's module, never the engine: the command modules import their services inside the callbacks, `opentide.validation` resolves its exports lazily, `CliContext.apply_environment()` resets `IndexManager` only when it is loaded, and `setup`'s `--default-branch` callback imports its check only for a value. `validate --help` and `opentide validate --<TAB>` take about 0.3 s, against 0.6 s before. `test_completing_an_option_or_subcommand_name_imports_no_engine_module` walks every visible command path. |
| Completion install | `--install-completion` and `--show-completion` stay flags, as Typer defines them, and read the shell from the word after them (`--show-completion zsh`): the bundled Click has no optional option values. Any other word is a usage error naming the five shells. Install ends with `✓ Installed <shell> completion in <path>` (cwd- or `~`-relative) and one next step, the command that loads it. `opentide completion` is an unknown command whose `help:` names both options. |
| Terminal progress | Inside tmux, recognises the outer terminal's own variables (`KITTY_WINDOW_ID`, `WEZTERM_PANE`, `LC_TERMINAL=iTerm2` with `LC_TERMINAL_VERSION`), since tmux replaces `TERM` and `TERM_PROGRAM`. iTerm2 needs version 3.6.6 or later and Ghostty 1.2 or later (`TERM_PROGRAM_VERSION`): older iTerm2 posts a bare OSC 9 as a notification. An unknown version gets nothing, so neither `TERM=xterm-ghostty` alone nor Ghostty inside tmux is enough. Decided from the stream itself (`isatty`), not `Console.is_terminal`, which `FORCE_COLOR` sets on a pipe. `OPENTIDE_PROGRESS=1` sends it to any terminal in `human` mode. Nothing is sent under `--quiet`. A single-step run shows the busy state (3), not 0 then 100 %. |
| Help | Every option has help text (`tests/test_cli/test_flow_conformance.py` fails otherwise). The examples are printed by `opentide.cli.help.render_help`, single-spaced, and `--help` adds no newline after Rich's output, so a help screen ends with exactly one. |
| Home screen and wizard | The workspace path is relative to the current directory (`.` at its root, never cut). Below the width the next steps need, the home screen drops their descriptions. The wizard's validation message shows on the row below the field, its setup plan uses the prompts' labels, and Ctrl-C prints nothing of questionary's own. |
| Narrow streams | Consoles write each glyph as its fallback (`·` → `-`, `…` → `...`) and any other character the stream cannot encode as `?`, so a message that embeds a glyph never raises `UnicodeEncodeError`. A JSON document on such a stdout escapes non-ASCII characters as `\uXXXX` instead: the same JSON, losslessly. |
| Colour in `plain` and `agent` | Off on a terminal too, unless `FORCE_COLOR` or `PY_COLORS` forces it; bold stays, as with `NO_COLOR`. Help screens follow. |
| Recorded CLI demos | Recorded CLI GIFs/tapes (#633) dropped; a web animation may follow. |
| Post-merge end-to-end run | Fixes from a full run of the merged rework, each with a test: object files that are empty, not UTF-8, hold an impossible date or a list where a reference belongs are findings, never `error[internal]`; a read-only workspace is a failure line (`new`: `path_not_writable`); a `--repo` that does not exist is `usage_invalid_value` (exit `2`, then `→ opentide --help`) except for `setup`; `path_not_writable` ends in `→ opentide explain path_not_writable`. `deploy` counts the blocks a status kept out (`Skipped: No rule has a status PREVIEW deploys · 4 rules in DESIGN`, `skipped` and `summary.skipped` in JSON; the `rule_skipped_for_strategy` log line is DEBUG when the caller collects them), and a rule whose compile fails is a `✗ would fail` row counted apart (`N would fail`, `summary.fail`, `"fails": true` on the change). Every frame ends in `╰─ help:` (`yaml_parse`, `schema_validation` and `platform_not_enabled` have default help, and a parse frame's step fits its problem: an empty file, an impossible date, a file that is not UTF-8); `duplicate_id` is framed at the UUID with an `also:` note for the other file. An underline label that would pass the terminal edge moves to the next row. Notes alone end `lint` on `✓ N notes in M files` (`_outcome_kind: ok`; JSON `status` stays `issues`). `share` prints plan rows by object name (planned words in a preview, short skip reasons such as `status not shared`) and `info` label and value columns, not boxed tables; `setup skills discover` lists slugs. Outside a workspace, `validate`, `lint` and `deploy` end with `→ opentide setup` (`NO_WORKSPACE_STEP`). A unique prefix (`defender`) or a known name (`gitlab` → `codequality`) is a `did you mean`. The MCP server reports opentide's version. Deprecations print `warning: … is deprecated`. The crash help line is a short OSC 8 link at a terminal (`OPENTIDE_LINKS=none` keeps the whole URL). `validate` no longer parses an object with no finding a second time, and shows a transient spinner at a terminal (`opentide.cli.ui.progress.busy`). |

## Code references

What is built, and the APIs the next changes extend.

| Module | What it holds |
|--------|---------------|
| `opentide.cli.ui.mode` | `OutputMode`; `resolve_mode(json_flag=, no_color=, command=, env=, stdout=)` applies the precedence table; `set_mode()` / `get_mode()` hold the mode of the current run (`get_mode()` resolves from the environment when nothing set it); `detect_agent()`, `detect_ci()`; `start_clock()` / `elapsed_ms()` time the run for `duration_ms`. Standard library only. |
| `opentide.cli.ui.glyphs` | `GLYPHS` by name (`ok`, `failed`, `warning`, `create`, `update`, `disable`, `delete`, `next`, `separator`, `ellipsis`, `mark`, and the code-frame pieces `frame_open`, `frame_only`, `frame_bar`, `frame_note`, `frame_close`, `underline`) and `glyph(name, stream=None, encoding=None)`, which falls back by stream encoding; `encodable(text, stream=None)` applies the fallbacks to whole text, and the shared consoles call it on everything they write. |
| `opentide.cli.ui.diagnostics` | `Diagnostic(code, severity, message, path, file_path, line, column, end_column, field_path, help, fix, label, notes, object_uuid)` with `.explain`, `.fields()` (the additive JSON keys) and `.to_dict()`; `Fix(safe, edits)`, `TextEdit(line, column, end_column, replacement, end_line=None)`; `is_safe_replacement()`; `split_yaml_lines()` (YAML's line breaks only); `annotate(entry, diagnostic)` adds the fields to a JSON finding without changing a key; `SourceFiles` reads each file once and finds a field's `span()` with ruamel; adapters `diagnostic_from_issue()`, `diagnostics_from_issues()`, `diagnostic_from_lint_finding()`; `annotate_report(payload, report, workspace=, buckets=)` annotates a dumped validation report in place (used by `validate` and MCP); `LINT_CODES`. No Rich or Typer. Also importable from `opentide.cli.ui`. |
| `opentide.cli.ui.codeframe` | `render_diagnostics(console, diagnostics, sources=, mode=, quiet=, cwd=)` prints code frames grouped by file; `diagnostic_lines(..., columns=)` builds one frame; `wrap_text()` and `shorten_path()` fit it to a terminal; `link_url()` (OSC 8 target from `OPENTIDE_LINKS` / `TERM_PROGRAM`); `display_path()`. |
| `opentide.cli.ui.fixes` | `plan_fixes(diagnostics)` reads each file with a safe fix once and returns a `FixPlan` (`changes`, one `FixChange(path, file_path, line, column, code, before, after)` per value, `.diff()`, `.write()`); `safe_edits(diagnostic)`. No Rich or Typer. |
| `opentide.cli.ui.watch` | `Watcher(roots, validate, strict=, scoped_runs=, snapshot=, read_references=, clock=, sleep=)`: `start()`, `poll()`, `run(show)`; each pass is a `WatchRun` with the whole workspace's findings and `summary`. `LiveView` (Rich `Live`) and `PlainView` show a pass. `take_snapshot()`, `references()`, `Changes.between()`. |
| `opentide.core.errors` | `UserFileError(path, problem, line=, column=, end_column=)` with `code`, `title`, `help` and `outcome`; `ConfigFileError.from_toml()`, `ObjectFileError`. `opentide.cli.output.emit_file_error()` renders one. |
| `opentide.cli.services.explain` | `diagnostic_codes()`, `load_page(code)`, `reference_markdown()` (renders `docs/cli/diagnostics.md`; `scripts/build/render_diagnostics_docs.py` writes it). Pages are `src/opentide/data/diagnostics/<code>.md`; `tests/test_cli/test_explain.py` fails when an emitted code has none. |
| `opentide.cli.ui.ci` | `ci_provider()`, `active_provider(mode)` (`None` in `json` and `mcp`), `checkout_root()`, `repository_path()`; GitHub `github_escape_data()`, `github_escape_property()`, `github_command()`, `github_annotation()`; Azure `azure_escape_data()`, `azure_escape_property()`, `azure_command()`, `azure_annotation()`; `emit_annotations(diagnostics, mode=)`, `emit_warning(message, title=)`, `append_summary(markdown, command=)`; `REPORTS_DIR`, `GITLAB_SUMMARY`. Standard library only. |
| `opentide.cli.ui.summary` | Markdown for job summaries: `diagnostics_summary()`, `deploy_summary(result)`, `query_summary(result)`, and `cell()`, `code()`, `table()` (at most `MAX_ROWS` rows); `explain_url(code)`. Standard library only. |
| `opentide.cli.ui.reports` | `ReportFormat`; `sarif_report(diagnostics, command=, version=, path_for=)` with rules for `rule_codes()`, each described by its `opentide explain` page (`sarif_rule()`); `codequality_report()`; `build_report()`. |
| `opentide.cli.findings` | Command glue: `check_report_options()`, `write_report_file()`, `print_report()`, `publish_findings()` (annotations and the findings summary) and `publish_summary()`. |
| `opentide.cli.ui.contract` | `NextAction(command, reason)`, `Failure(code, message, argument, suggestion, crash_log)`, the `usage_*` codes, `COMMAND_FAILED` / `ISSUES_FOUND` / `NOT_RUN`, `did_you_mean()`. No Rich or Typer. |
| `opentide.cli.ui.render` | `render_outcome(console, kind, message)` with `kind` in `ok`, `warning`, `skipped`, `failed`; `render_warnings`, `render_notes`, `render_next_actions` (three at most), `render_error(console, message, notes=, mode=)` (adds the agent tip). All print `Text`, never markup, with `soft_wrap`. |
| `opentide.cli.ui.crash` | `handle_crash(error, argv=, command=)`, called by `opentide.cli.main()` for an exception no command handled: `error[internal]`, crash log path and issue link on stderr (traceback with `--debug`), the `internal` envelope on stdout in `json`, nothing on stdout in `mcp`; exit 1. `Redactor` / `workspace_redactor()` (URL credentials, `Authorization` values of any scheme, secret-named variables, options and keys, the tenant names, hosts, ids, resource groups and apps of `platforms/*.toml`, the destinations of `sharing.toml`), `crash_log_dir()`, `write_crash_log()` (0700 directory, last 10 kept), `issue_url()` (version, Python, OS, command path only), `report_interrupt()` (Ctrl-C: one line, exit 130). Standard library only. |
| `opentide.cli.output` | `CommandResult` gains `summary`, `next_actions` and `failure`; `envelope()` adds the JSON keys to any payload; `emit_result()` renders warnings, the outcome, notes, then next steps; `emit_error(..., code=, argument=, suggestion=)`; `emit_usage_error()` exits 2 with a `did_you_mean` suggestion. `envelope()` sets `error` to the `message` on every non-zero exit that has none, and writes each next action as `opentide --json …`. A service payload may carry `_summary`, `_next_actions`, `_failure_code`, `_failure_argument`, `_failure_suggestion` and `_outcome` (the printed outcome line); they move into the envelope or the human view. |
| `opentide.cli.usage` | Click usage errors as a `Failure` (`describe()`), and their rendering (`render_usage_error()`). |
| `opentide.cli.lazy` | `HOISTED_FLAGS` and `hoist_root_flags()`, called from `LazyTyperGroup.parse_args`; `command_words()`, the command path a command line names, never its argument values. `LazyTyperGroup.main` guesses the mode before parsing and starts the clock; `make_context` and `invoke` route usage errors through `opentide.cli.usage`, and `invoke` reports Ctrl-C in one line. |
| `opentide.core.runtime` | `boolean_env()`, `debug_requested()` (`OPENTIDE_DEBUG`, then `DEBUG` when it is a boolean literal). |
| `opentide.core.logging.render` | `OpentideConsoleRenderer` writes `label: Readable text · key: value`; `ConsoleLogHandler` styles the label and adds the time under `--debug`. |
| `opentide.cli.ui.brand` | `ICON` (28 × 28 px) and `LOGO` (80 × 20 px) as `B`/`W`/`.` grids; `render()` draws any grid with upper half-blocks (`mono=` keeps the shape without colour); `icon()`, `logo()`, `pill()`, `header()`; `can_draw(console)` (`human` mode and an encoding with the blocks); `TAGLINE`. |
| `opentide.core.progress` | `report_stage(name)`: an engine module says which stage it is in; `listen(callback)` receives them. No Rich. |
| `opentide.cli.ui.progress` | `Checklist(total=)` and `Checklist.step(name, where=, unit=)` yielding a `Step` (`done(count, where=)`, `skip(reason)`); a live checklist in `human`, `step_line()` per finished step in `plain`/`agent`, nothing in `json`, `mcp` or `--quiet`. `total` and `completed` are there for a percentage display. `plural()`, `seconds_text()`. |
| `opentide.cli.ui.terminal_progress` | `TerminalProgress(console, total=)` as a context manager, `update(completed)`; `detected(env)`, `enabled(console, mode=, quiet=, env=)`, `sequence(state, percent, tmux=)`. Only the outermost block draws. `Checklist` owns one in `human` mode; `share` opens one directly. |
| `opentide.cli.completion` | Completion sources (`object_uuids(kinds)`, `object_files(kinds)`, `object_types`, `techniques`, `platforms`, `strategies`) and `attach(command, path)`, called from `LazyTyperGroup.load` next to `decorate()`. `INDEXED_OPTIONS`, `indexed_source(group, args, incomplete)` and `complete_from_index()`, called from `LazyTyperGroup._main_shell_completion` before Click resolves the command. `install_completion` and `show_completion`, the callbacks `LazyTyperGroup.main` gives the two root options. `diagnostic_codes` completes `explain <code>`; it applies once `opentide explain` (#620) is available, and completes nothing until then. `iter_object_paths` lists object files without reading them; `read_header` takes `metadata`'s own `uuid` only; `bash_word` escapes candidates under `_OPENTIDE_COMPLETE=complete_bash`. Standard library only at import time. |
| `opentide.cli.ui.plan` | `plan_view(changes, strategies=, tenants=, scope=)`, `render_plan(console, payload)` and `render_plan_diagnostics(console, payload)`; the rows come from `opentide.cli.services.deploy_plan` (`plan_changes`, `plan_message`, `deployed_message`). |
| `opentide.cli.ui.setup` | `welcome()`, `render_summary()`, `setup_outcome()` for every `setup` command. |
| `opentide.cli.ui.home` | `gather()` reads the home screen's facts from disk; `home_view()` draws them; `next_steps()`. |
| `opentide.cli.ui.layout`, `opentide.cli.ui.paths` | `columns()` aligns rows without trailing blanks; `display_path()` shortens a path to the current directory or the workspace. |
| `opentide.cli.help` | `SUMMARIES` (≤ 60 characters) and `EXAMPLES` by command path; `decorate()` applies them when the lazy group loads a command; `render_help()` prints the examples after Typer's help and `help_option()` drops Click's extra newline. Panels come from `CommandSpec.rich_help_panel`. |
| `opentide.mcp_server.server` | `reserve_stdout()` keeps file descriptor 1 for JSON-RPC and sends `sys.stdout`, descriptor 1 and child processes to stderr while the server runs. `TAGLINE` and `INSTRUCTIONS`; tool docstrings are the descriptions agents read. |
| `opentide.mcp_server.tools` | `next_action(tool, arguments, command=, reason=)` builds an MCP next action; `tool_explain()`. |
| `opentide.cli.services.introspect` | `command_tree(root)` walks the root group into the `opentide commands` payload; `example(command, path)`; `tree_lines()` for the human tree. |

A service payload may also carry `_outcome_kind` (`plan`, `warning`) when its status alone does not say how the outcome line reads, and `_next_numbered` for next steps that form a sequence.

A diagnostic renderer adds its lines next to `render_outcome` and passes its counts as `summary`; `validate` and `lint` call `render_diagnostics` before `emit_result`, CI annotations, the job summary and the `--format` reports are built from the same list (`publish_findings`, `write_report_file`), and MCP (PR F) builds on the same `Diagnostic`. A command with a summary of its own builds the Markdown in `opentide.cli.ui.summary` and passes it to `publish_summary` before `emit_result`. A progress or plan renderer reads `get_mode()` and draws only in `human`. The crash handler builds `Failure(code="internal", crash_log=...)` and passes it to `envelope()`.
