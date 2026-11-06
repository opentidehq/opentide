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
| Catalogue | `1` | Threats → objectives → rules, with how many objectives and rules sit under each. Objectives that name no threat, rules whose `detection_model` names no objective in the catalogue, and files that failed to load get their own groups. The pane on the right shows what the [language server](#the-language-server) reports for the selected object and what the last validate run found (`error[code]: message`, `╭─▶ path:line:column`, `╰─ help: …`), then its file with line numbers, coloured by the language server: Tide keys, UUIDs, schemas and vocabulary values, and the query inside a rule in its own language. Each line with a finding is marked, and the finding's span is underlined |
| Coverage | `2` | One row per ATT&CK technique named by a threat, an objective or a rule: how many rules detect it and how (`13  2 own · 11 inherited`), which rules, and which threats and objectives name it. A rule covers a technique it lists in its own `techniques`, and one it inherits from its objective (directly or through a signal) or that objective's threats, as `opentide info coverage --technique T1059` and `info catalog` count it. A technique counts the rules on its sub-techniques. A row with `0` rules is a gap: no rule lists or inherits it. `Enter` opens the first rule, one that lists the technique when there is one |
| Results | `3` | The output of each command run from the UI, as the command prints it: code frames, a dry run's plan, warnings, the outcome line and next steps |
| Chains | `6` | `threat.chaining` around the selected threat, drawn as attack flow: see [Chains](#chains) |

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
| `q` | | Quit. While a command runs, the UI stays up, shows `Waiting for opentide generate to finish…` and closes when it is done: a command cannot be stopped halfway, and it would otherwise go on writing files and printing into the shell after the UI had gone |

A command runs in the background, one at a time, so the UI stays responsive. When it finishes, the catalogue is read again (generate may have rewritten it), and an object with findings shows `✗ 2` (errors) or `! 1` (warnings) after its name. In the Results tab, the query lines of a code frame are coloured as at a terminal.

## Chains

The Chains tab draws `threat.chaining` around one threat: the one selected in the Catalogue, else the first with links. A whole catalogue's chaining is too much to read at once, so it starts with the threats one link away and grows by hops.

- **Sequence links** (`sequence::preceeds`, `sequence::succeeds`) run left to right as attack flow: each threat is a box, `──▶` between steps.
- **Each box** shows the rules under the threat's objectives, in red when there are none (an undetected step), and how many of the techniques it names some rule covers, own or inherited, as the [Coverage tab](#layout) counts them.
- **Supporting and atomicity links** (`support::*`, `atomicity::*`) are listed beside the flow, labelled by how they read (`enables`, `implemented by`, `synergizes with`) and coloured by relation. Threats linked only that way are shown under the flow.
- **One link, shown once:** a link written from both ends (`A preceeds B` in A, `B succeeds A` in B) is merged, with both descriptions. A link to a threat the catalogue does not have says so.
- **The list on the left** holds the threats shown. Highlighting one describes its links. `Enter` opens it in the Catalogue, `c` centres the chain on it, `+` and `-` add or remove a hop (up to 4), and `r` cycles the relations shown: all, sequence, atomicity, support.

## The language server

Each time the catalogue is read (at start, after `r`, after each command), the TUI checks every object file the way your editor's [`opentide lsp start`](./lsp.md#lsp-start) does, with the catalog this opentide generates for the workspace. So you see what your editor would show, the queries inside rules included, before running validate:

```text illustrative
Language server
error[kql_unknown_operator]: unknown tabular operator 'wher'
  ╭─▶ objects/rules/rule-sentinel.yaml:61:9
  ╰─ help: did you mean 'where'?

Last validate run
Not validated yet: press v to run opentide validate.
```

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
