---
title: opentide tui
description: Browse the catalogue, each object's YAML with what the language server and validate report, and ATT&CK coverage, and run validate, generate and deploy --dry-run, in a terminal UI.
---

# opentide tui

A terminal UI over the detection repository: the catalogue as a tree, each object's YAML coloured as your editor colours it, what the [language server](./lsp.md) and the last validate run report about it, coverage by ATT&CK technique, and the commands you run while authoring.

```bash
opentide tui
opentide --repo path/to/detections tui
```

It reads the same registry as every other command and runs the same service functions as `opentide validate`, `opentide generate` and `opentide deploy --dry-run`, so what it shows is what those commands print.

## Layout

| Tab | Key | What it shows |
|-----|-----|---------------|
| Catalogue | `1` | Threats → objectives → rules, with how many objectives and rules sit under each. Objectives that name no threat, rules whose `detection_model` names no objective in the catalogue, and files that failed to load get their own groups. The pane on the right counts what the [language server](#the-language-server) reports for the selected object and what the last validate run found (`✗ 1  ! 2  on lines 8, 28`), then shows the object as a [page](#the-object-page). `y` shows its file instead, with line numbers, coloured by the language server: Tide keys, UUIDs, schemas and vocabulary values, and the query inside a rule in its own language. Each finding is shown [in place](#findings-in-place), under the line it is about |
| Coverage | `2` | One row per ATT&CK technique named by a threat, an objective or a rule: how many rules detect it, which rules, and which threats and objectives name it. A technique counts the rules on its sub-techniques, as `opentide info --technique T1059 coverage` does. A row with `0` rules is a gap. `Enter` opens the first rule |
| Results | `3` | The output of each command run from the UI, as the command prints it: code frames, a dry run's plan, warnings, the outcome line and next steps |

The header carries the opentide pill, the tagline, the repository name and the catalogue counts. The tagline shows only where it fits whole: when the terminal is too narrow for it beside the counts, the header keeps the pill and the counts.

A name too long for the tree ends in `…`, after a whole character, and gives way before its counts; the pane on the right shows it in full. The tree never scrolls sideways. With no detection objects, the tree says so, with the workspace path relative to the current directory.

## Commands

Run them with their key, or from the command palette (`ctrl+p`), which lists them by the command line they stand for:

| Key | Palette entry | Same as |
|-----|---------------|---------|
| `v` | `opentide validate` | `opentide validate`: every object, and every rule's query offline |
| `g` | `opentide generate` | `opentide generate` (the full pipeline; it writes docs and exports into the repository) |
| `d` | `opentide deploy --dry-run --strategy PREVIEW --all` | The same command: the payloads a PREVIEW deploy of every rule file would send. No platform is called |
| | `opentide deploy --dry-run --strategy RELEASE --all` | The same command, for a RELEASE run |
| `r` | Reload the catalogue | Read every object file again, after editing one elsewhere |
| `y` | | Switch the detail pane between the object's [page](#the-object-page) and its file |
| `f` | | Open the next object or signal the selected object references (its `detection_model`, threats, chained threats) |
| `n`, `p` | | The selected object's next or previous finding, in its file: see [Findings in place](#findings-in-place) |
| `q` | | Quit. While a command runs, the UI stays up, shows `Waiting for opentide generate to finish…` and closes when it is done: a command cannot be stopped halfway, and it would otherwise go on writing files and printing into the shell after the UI had gone |

A command runs in the background, one at a time, so the UI stays responsive. When it finishes, the catalogue is read again (generate may have rewritten it), and an object with findings shows `✗ 2` (errors) or `! 1` (warnings) after its name. In the Results tab, the query lines of a code frame are coloured as at a terminal.

## The language server

Each time the catalogue is read (at start, after `r`, after each command), the TUI checks every object file the way your editor's [`opentide lsp start`](./lsp.md#lsp-start) does, with the catalog this opentide generates for the workspace. So you see what your editor would show, the queries inside rules included, before running validate:

```text illustrative
Language server
✗ 1  on line 61  · n next finding, p previous

Last validate run
Not validated yet: press v to run opentide validate.

 60      query: |
 61 ✗      SecurityEvent | wher EventID == 4688
         ╰─ error[kql_unknown_operator]: unknown tabular operator 'wher' · help: did you mean 'where'?
```

### The object page

The detail pane shows the selected object as a page read from its schema, the revision its `metadata.schema` names, as validation reads it:

- **Header:** version, created and modified dates, and the TLP as a badge in FIRST's colours with what it means. The schema revision follows.
- **Sections:** the top-level values (description, status, severity, techniques, `detection_model`) under *Overview*, then a section per block (`objective`, `threat`, `response`, `configurations`), each field under its title and each list item under its name.
- **Values explained:** a vocabulary value carries what the vocabulary says it means; a severity is a coloured badge.
- **References:** a UUID reads as the name of the objective, signal or threat it names (`→ Credential Access Objective  objective`). Click it, or press `f`, to open it.
- **Queries:** each query has its own panel, named by platform and language and coloured by the engine.
- **Not set (N):** a collapsed section listing every optional field the object's revision allows and the object does not set, each with its description and, for a vocabulary, its values; `★` marks a field the schema recommends. A block the object leaves out is one entry, not one per field inside it. An unknown revision shows its fields as written, with no list.

A finding with a field is marked under that field. `y` shows the file, and `n` opens the file at the next finding.

### Findings in place

Each finding is shown under the line it is about, with its code, message and help, so you read it without scrolling back to the top of the pane. The line's gutter carries `✗` (error), `!` (warning) or `·` (note), and the finding's span is underlined, with a tint of its severity behind it so the text keeps its colours (a terminal cannot colour an underline apart from its text). A long line wraps inside the source column, and the underline stays on its own characters. A finding with no line (one validate reports by field only) is shown in full in the block above.

- **Mouse:** hover a finding's span for a tooltip: its frame, then what your editor's hover shows there (the field's description, a vocabulary value's meaning, the object a UUID names), from the same engine.
- **Keyboard:** not every terminal passes mouse events, so `n` and `p` move to the selected object's next and previous finding: the pane scrolls to it, its annotation is marked `▶`, and the status line carries `2/5 error[code]: message · <hover>`.

The span is the range the engine reports: with an engine that puts reference findings on their value ([language-server#215](https://github.com/opentidehq/language-server/issues/215)), a dangling `detection_model` underlines the UUID; with the engine this release ships, the key.

A finding both report (the same code on the same line, such as a TLP value that is not in the vocabulary) is shown and counted once, as validate's. The query findings of validate's `queries` check come from the same engine, so they are shown once, under the language server. Notes (hints) are shown, but are not counted in the tree. [`opentide validate`](./validate.md) stays the authority on whether an object deploys.

When the analysis engine does not load, the status line and the pane say why and how to reinstall it, nothing is checked, and the file is coloured as plain YAML (see [`engine_unavailable`](./diagnostics.md#engine_unavailable)).

## Terminal required

`opentide tui` runs only in the `human` [output mode](./json-output.md#output-modes) with a terminal on stdin and stdout. Under `--json`, in a pipe, in CI or under a coding agent it does not start, and exits `2` with `failure.code` `usage_tui_needs_tty`:

```text output-of="opentide tui" exit=2
error: opentide tui needs an interactive terminal; this run is in plain mode
→ opentide info · catalogue counts and platforms
→ opentide validate · diagnostics for every object
```

```bash
opentide --json tui
```

```json output-of="opentide --json tui" exit=2
{
  "ok": false,
  "status": "failed",
  "message": "opentide tui needs an interactive terminal; this run is in json mode",
  "command": "tui",
  "exit_code": 2,
  "failure": { "code": "usage_tui_needs_tty", "argument": null, "suggestion": null }
}
```

At a terminal, `NO_COLOR`, `--no-color`, `TERM=dumb`, a CI environment and `OPENTIDE_OUTPUT=plain` select the `plain` mode too. The refusal then names the setting and how to open the UI anyway:

```text illustrative
error: opentide tui runs only in the human output mode; this run is in plain mode because NO_COLOR is set
  help: set OPENTIDE_OUTPUT=human to open it anyway
```

`NO_COLOR=1 OPENTIDE_OUTPUT=human opentide tui` opens it in monochrome. This sample is not captured: the docs harness has no terminal, so it gets the refusal above.

## Source

`src/opentide/cli/commands/tui.py` (the command, and its refusals), `src/opentide/cli/tui_app.py` (the Textual app, the only module that imports Textual, when the UI opens: `opentide tui --help` does not load it), `src/opentide/cli/services/tui.py` (the catalogue, coverage and actions)
