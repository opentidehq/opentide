---
title: opentide tui
description: Browse the catalogue, each object's YAML and diagnostics, and ATT&CK coverage, and run validate, generate and deploy --dry-run, in a terminal UI.
---

# opentide tui

A terminal UI over the detection repository: the catalogue as a tree, each object's YAML with the diagnostics from the last validate run, coverage by ATT&CK technique, and the commands you run while authoring.

```bash
opentide tui
opentide --repo path/to/detections tui
```

It reads the same registry as every other command and runs the same service functions as `opentide validate`, `opentide generate` and `opentide deploy --dry-run`, so what it shows is what those commands print.

## Layout

| Tab | Key | What it shows |
|-----|-----|---------------|
| Catalogue | `1` | Threats → objectives → rules, with how many objectives and rules sit under each. Objectives that name no threat, rules whose `detection_model` names no objective in the catalogue, and files that failed to load get their own groups. The pane on the right shows the selected object's file with line numbers, and its diagnostics from the last validate run, each line marked |
| Coverage | `2` | One row per ATT&CK technique named by a threat, an objective or a rule: how many rules detect it, which rules, and which threats and objectives name it. A technique counts the rules on its sub-techniques, as `opentide info --technique T1059 coverage` does. A row with `0` rules is a gap. `Enter` opens the first rule |
| Results | `3` | The output of each command run from the UI, as the command prints it: diagnostics, warnings, the outcome line and next steps |

The header carries the opentide pill, the tagline, the repository name and the catalogue counts.

## Commands

Run them with their key, or from the command palette (`ctrl+p`), which lists them by the command line they stand for:

| Key | Palette entry | Same as |
|-----|---------------|---------|
| `v` | `opentide validate` | `opentide validate` |
| `g` | `opentide generate` | `opentide generate` (the full pipeline; it writes docs and exports into the repository) |
| `d` | `opentide deploy --dry-run --strategy PREVIEW --all` | The same command: the payloads a PREVIEW deploy of every rule file would send. No platform is called |
| | `opentide deploy --dry-run --strategy RELEASE --all` | The same command, for a RELEASE run |
| `r` | Reload the catalogue | Read every object file again, after editing one elsewhere |
| `q` | | Quit. While a command runs, the UI stays up, shows `Waiting for opentide generate to finish…` and closes when it is done: a command cannot be stopped halfway, and it would otherwise go on writing files and printing into the shell after the UI had gone |

A command runs in the background, one at a time, so the UI stays responsive. When it finishes, the catalogue is read again (generate may have rewritten it), and an object the last validate run found issues in shows `✗ 2` (errors) or `! 1` (warnings) after its name.

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

`src/opentide/cli/commands/tui.py` (the Textual app, the only module that imports Textual), `src/opentide/cli/services/tui.py` (the catalogue, coverage and actions)
