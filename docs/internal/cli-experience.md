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
| `mcp` | Nothing but JSON-RPC on stdout. Once FastMCP owns the transport, `sys.stdout` points at stderr for everything else; `OPENTIDE_OUTPUT`, agent detection and the envelope do not apply |

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
| `+ ~ - ×` | plan: create, update, disable, delete | `+ ~ - x` |
| `→` | next step | `->` |
| `≋` | opentide mark (headers only) | `opentide` |

Every command ends with **exactly one outcome line**. Warnings print before it. At most three next steps print after it, and only when there is something to do. Engine modules stop printing directly: section headers (`emit_section`) become progress steps owned by the CLI, and Rich panels move out of services into renderers.

| Command | Outcome line (examples) |
|---------|-------------------------|
| `validate` | `✓ 3 objects valid · 0.9s` / `✗ 2 errors in 1 file · 3 objects checked · 0.9s` |
| `lint` | `✓ 42 files clean` / `! 3 findings in 2 files` (+ `→ opentide lint --fix` only when filename findings exist) |
| `info` | the table, then `1 rule · 1 threat · 1 objective · 0 load errors` |
| `generate` (all phases and subcommands) | `✓ Generated 28 files in 4.8s · 6 phases` |
| `generate extract <platform>` | `✓ Imported 14 rules from sentinel · 2 skipped` |
| `deploy --dry-run` | `Plan: 1 to create, 0 to update, 0 to disable, 0 to delete · 1 platform, 0 tenants` |
| `deploy` | `✓ Deployed 3 rules to 2 tenants · 1 created, 2 updated · 12.4s` |
| `deploy migrate-state` | `✓ Moved 6 vendor ids to .opentide/states/deployment/` |
| `validate query --live` | `✓ 12 queries valid on 2 tenants` / `✗ 1 query rejected by sentinel/prod` / `Skipped: no configured tenant reached` |
| `setup` and its subcommands | `✓ Created Tutorial Detections in ./tutorial-detections` / `✓ Wrote .vscode/settings.json` |
| `share push/preview/status/retract/targets` | `✓ Shared 4 objects to misp-prod · 3 new, 1 updated` |
| `rules unreviewed` | `! 5 rules unreviewed for 90 days` / `✓ Every rule reviewed in the last 90 days` |
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
| Typo in a command, option or choice | `did you mean …?` with the valid values, exit 2. App-level choices use `difflib.get_close_matches`. |
| `--json` after the subcommand | Accepted |
| A prompt with no TTY or under an agent | Exit 2 at once, naming the flags that answer it |
| `DEBUG='*'` in the environment | Ignored |
| Unexpected exception | `error[internal]: <Type>: <message>`, the crash log path, a pre-filled issue link; the traceback only with `--debug`. Always on stderr. The log goes to `$XDG_STATE_HOME/opentide/` (platform equivalent elsewhere), never into the repository, with proxy credentials, tokens and tenant secrets redacted. |

## Brand in the terminal

Assets: `opentidehq/.github/assets` (Pantone Reflex Blue `#001489`, white, the Material "Tsunami" icon, the pill logo, Inter SemiBold). `opentide.cli.ui.brand` holds the marks as pixel grids rendered with upper half-blocks:

| Mark | Size | Where |
|------|------|-------|
| Pill logo | 73 × 10 | `setup` wizard welcome only |
| Icon | 28 × 14 | bare `opentide` home screen |
| One-line pill `▐ ≋ opentide ▌` | 1 line | section headers, terminals narrower than 76 columns |

Rules: only in `human` mode, and only when the stream encoding can encode the block characters (otherwise none). Blue is a fill, never a text colour. `NO_COLOR` keeps the shapes. No yellow, no gradients. `print_banner()` is public API: it is deprecated with a warning and renders the new mark, and is removed in a later release. `coretide-logo.png` is removed.

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

## Docs

`docs/tapes/*.tape` (VHS) record the tutorial path, a validation failure, the plan view and the home screen. The docs workflow renders them to GIF and SVG and fails when a tape no longer runs, so screenshots never drift from the product.

## Built so far, and deviations

The output contract (#619) is in place. Where it differs from the sections above, the code is right and this list says how:

| Topic | As built |
|-------|----------|
| Logs under `--json --debug` | DEBUG and above, like `--debug` in every other mode (not INFO). Without `--debug`, `--json` and the MCP server log WARNING and above. |
| JSON indentation | Always indented. Compact output on a pipe and `OPENTIDE_JSON_INDENT` come later (PR K). |
| `failure` | Set on every non-zero exit, `ok` true or not, so `failure.code` tells the cases of one exit code apart; `null` exactly when `exit_code` is `0`. Codes in use: the five `usage_*` codes above plus `usage_invalid_value` and `usage_error`; `command_failed`, `issues_found` (`--strict`), `not_run`; `no_tenant_reached`, `needs_human_decision`, `not_implemented`; `share_failed`, `share_unreachable`, `share_partial`, and the share preflight codes (`scope_no_match`, ...). The list is in `docs/cli/json-output.md`. |
| Outcome lines | The glyph grammar is in place. `validate`, `lint` and `info` print the counted wordings of the table above (#620); the JSON `message` keeps its old text, and the printed line comes from `CommandResult.outcome` (payload key `_outcome`). Other commands keep their current message until progress (PR E). A skipped result prints `Skipped: <message>`. A command that fails on findings it printed (`failure.code` `issues_found`) prints its outcome line as `✗ …` on stderr instead of `error: <message>`. |
| Soft wrap | Outcome, warning, error and next-step lines are soft-wrapped in `human` mode too, not only `plain`: Rich would otherwise break a long path mid-word on a TTY. |
| `opentide --json` with no command | Still prints help (`no_args_is_help`), not a JSON document. |
| Diagnostics | Built for `validate` and `lint` (#620). `end_column` is exclusive (one past the last character), so an edit replaces `[column, end_column)`. Lint's JSON `severity` stays `info` (an existing value); its frame prints `note`. Lint findings gain `code` and `field_path` too. Columns are Unicode code points, not UTF-16 units: SARIF sets `columnKind: "unicodeCodePoints"`, LSP converts. `line` points at the key of a block value, so it is not always `yaml_line + 1`. `TextEdit` has `end_line` (equal to `line` for an edit within one line). A fix is `safe` only when the values spell the same word (case, spaces, `-`, `_`) and hold no digit, so no identifier (ATT&CK id, UUID, CVE) is ever replaced unreviewed; an `invalid_ref` fix is never safe. Every suggested value still gets an unsafe fix. `validate --fix` is not built yet (PR I). |
| `invalid_ref` + `vocab_unknown` | Merged in the engine (`merge_reference_findings`), so MCP and JSON see one finding as well. `invalid_ref` issues carry `context.value`. |
| YAML parse errors | `describe_yaml_error()` gives the problem, its 1-based position and the parser's context; the registry stores that text, and `validate` reports the file once (the registry logs it at DEBUG during `validate`). |
| `opentide explain <code>` | Prints the page: rendered Markdown in `human`, the Markdown source in `plain` and `agent`, `{code, meaning, markdown}` in JSON. No outcome line, like `--help`. With no code it lists every code and ends with `✓ N diagnostic codes`. |
| `info` with load errors | `status` is `issues` and the next step is `opentide validate`; `--strict` fails with `issues_found`. |
| `opentide commands` | Built (#623). `--json` gives `program`, `global_options` and `commands`: flat, depth-first, in `--help` order, each with `path`, `summary`, `help`, `group`, `runs_alone`, `subcommands`, `deprecated`, `arguments`, `options` (`flags`, `type`, `choices`, `default`, `required`, `multiple`, `is_flag`, `envvars`, `help`) and `example`. Hidden commands and options, `--help` and the completion options are left out. **No JSON Schema of each command's output**: there are no typed result models to generate it from yet. The example is the first `$ opentide …` line of the command's epilog (the help examples of PR E), else the command with its required arguments and options filled in; a group that only prints help takes its first subcommand's. Human mode prints the tree and `✓ N commands`. Walking the tree imports each root command's module once and never builds the registry. |
| MCP | Built (#623). `validate_rule` (`issues`) and `validation_report` (`issues`, `warnings`) gain the diagnostic fields through `annotate_report()`, like `validate`. `next_actions` are `{tool, arguments, command, reason}`: the MCP call, plus the CLI's `{command, reason}`. They appear on `validate_rule`, `validation_report` and a refused `validate_query`; other payloads are unchanged. `explain(code)` returns the CLI's `{code, meaning, markdown}` with `found`; an empty code lists every code. The server `instructions` (`INSTRUCTIONS` in `opentide.mcp_server.server`) carry the tagline and the agent workflow. |
| Agent instruction files | Built (#623). `AGENTS.md.template`, `CLAUDE.md.template`, `copilot-instructions.md`, the `detection-ops` pack and the four authoring skills tell agents to run `opentide --json …`, branch on the exit code and `failure.code`, apply `fix`, follow `next_actions` and use `opentide explain`. `tests/test_cli/test_agent_instructions.py` checks that every command they quote exists with its options. |

## Code references

What is built, and the APIs the next changes extend.

| Module | What it holds |
|--------|---------------|
| `opentide.cli.ui.mode` | `OutputMode`; `resolve_mode(json_flag=, no_color=, command=, env=, stdout=)` applies the precedence table; `set_mode()` / `get_mode()` hold the mode of the current run (`get_mode()` resolves from the environment when nothing set it); `detect_agent()`, `detect_ci()`; `start_clock()` / `elapsed_ms()` time the run for `duration_ms`. Standard library only. |
| `opentide.cli.ui.glyphs` | `GLYPHS` by name (`ok`, `failed`, `warning`, `create`, `update`, `disable`, `delete`, `next`, `separator`, `mark`, and the code-frame pieces `frame_open`, `frame_only`, `frame_bar`, `frame_note`, `frame_close`, `underline`) and `glyph(name, stream=None, encoding=None)`, which falls back by stream encoding. |
| `opentide.cli.ui.diagnostics` | `Diagnostic(code, severity, message, path, file_path, line, column, end_column, field_path, help, fix, label, notes, object_uuid)` with `.explain`, `.fields()` (the additive JSON keys) and `.to_dict()`; `Fix(safe, edits)`, `TextEdit(line, column, end_column, replacement, end_line=None)`; `is_safe_replacement()`; `split_yaml_lines()` (YAML's line breaks only); `annotate(entry, diagnostic)` adds the fields to a JSON finding without changing a key; `SourceFiles` reads each file once and finds a field's `span()` with ruamel; adapters `diagnostic_from_issue()`, `diagnostics_from_issues()`, `diagnostic_from_lint_finding()`; `annotate_report(payload, report, workspace=, buckets=)` annotates a dumped validation report in place (used by `validate` and MCP); `LINT_CODES`. No Rich or Typer. Also importable from `opentide.cli.ui`. |
| `opentide.cli.ui.codeframe` | `render_diagnostics(console, diagnostics, sources=, mode=, quiet=, cwd=)` prints code frames grouped by file; `diagnostic_lines()` builds one frame; `link_url()` (OSC 8 target from `OPENTIDE_LINKS` / `TERM_PROGRAM`); `display_path()`. |
| `opentide.cli.services.explain` | `diagnostic_codes()`, `load_page(code)`, `reference_markdown()` (renders `docs/cli/diagnostics.md`; `scripts/build/render_diagnostics_docs.py` writes it). Pages are `src/opentide/data/diagnostics/<code>.md`; `tests/test_cli/test_explain.py` fails when an emitted code has none. |
| `opentide.cli.ui.contract` | `NextAction(command, reason)`, `Failure(code, message, argument, suggestion, crash_log)`, the `usage_*` codes, `COMMAND_FAILED` / `ISSUES_FOUND` / `NOT_RUN`, `did_you_mean()`. No Rich or Typer. |
| `opentide.cli.ui.render` | `render_outcome(console, kind, message)` with `kind` in `ok`, `warning`, `skipped`, `failed`; `render_warnings`, `render_notes`, `render_next_actions` (three at most), `render_error(console, message, notes=, mode=)` (adds the agent tip). All print `Text`, never markup, with `soft_wrap`. |
| `opentide.cli.output` | `CommandResult` gains `summary`, `next_actions` and `failure`; `envelope()` adds the JSON keys to any payload; `emit_result()` renders warnings, the outcome, notes, then next steps; `emit_error(..., code=, argument=, suggestion=)`; `emit_usage_error()` exits 2 with a `did_you_mean` suggestion. A service payload may carry `_summary`, `_next_actions`, `_failure_code`, `_failure_argument`, `_failure_suggestion` and `_outcome` (the printed outcome line); they move into the envelope or the human view. |
| `opentide.cli.usage` | Click usage errors as a `Failure` (`describe()`), and their rendering (`render_usage_error()`). |
| `opentide.cli.lazy` | `HOISTED_FLAGS` and `hoist_root_flags()`, called from `LazyTyperGroup.parse_args`. `LazyTyperGroup.main` guesses the mode before parsing and starts the clock; `make_context` and `invoke` route usage errors through `opentide.cli.usage`. |
| `opentide.core.runtime` | `boolean_env()`, `debug_requested()` (`OPENTIDE_DEBUG`, then `DEBUG` when it is a boolean literal). |
| `opentide.core.logging.render` | `OpentideConsoleRenderer` writes `label: Readable text · key: value`; `ConsoleLogHandler` styles the label and adds the time under `--debug`. |
| `opentide.mcp_server.server` | `reserve_stdout()` keeps file descriptor 1 for JSON-RPC and sends `sys.stdout`, descriptor 1 and child processes to stderr while the server runs. `TAGLINE` and `INSTRUCTIONS`; tool docstrings are the descriptions agents read. |
| `opentide.mcp_server.tools` | `next_action(tool, arguments, command=, reason=)` builds an MCP next action; `tool_explain()`. |
| `opentide.cli.services.introspect` | `command_tree(root)` walks the root group into the `opentide commands` payload; `example(command, path)`; `tree_lines()` for the human tree. |

A diagnostic renderer adds its lines next to `render_outcome` and passes its counts as `summary`; `validate` and `lint` call `render_diagnostics` before `emit_result`, and CI annotations (PR D) and MCP (PR F) build on the same `Diagnostic`. A progress or plan renderer reads `get_mode()` and draws only in `human`. A crash handler builds `Failure(code="internal", crash_log=...)` and passes it to `envelope()`.
