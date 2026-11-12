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
| Coverage | `2` | One row per ATT&CK technique named by a threat, an objective or a rule: how many rules detect it and how (`13  2 own · 11 inherited`), which rules, and which threats and objectives name it. A rule covers a technique it lists in its own `techniques`, and one it inherits from its objective (directly or through a signal) or that objective's threats, as `opentide info coverage --technique T1059` and `info catalog` count it. A technique counts the rules on its sub-techniques. A row with `0` rules is a gap: no rule lists or inherits it. `Enter` opens the first rule, one that lists the technique when there is one |
| Results | `3` | The output of each command run from the UI, as the command prints it: code frames, a dry run's plan, warnings, the outcome line and next steps |
| Visibility | `4` | The log sources `.opentide/configurations/visibility.toml` declares and the detections that use them: see [Visibility](#visibility) |
| Configuration | `5` | `deployment.toml`, `lint.toml`, `documentation.toml`, `sharing.toml` and each `platforms/*.toml`, read rather than as TOML: see [Configuration](#configuration) |
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
| `y` | | Switch the detail pane between the object's [page](#the-object-page) and its file |
| `f` | | Open the next object or signal the selected object references (its `detection_model`, threats, chained threats) |
| `n`, `p` | | The selected object's next or previous finding, in its file: see [Findings in place](#findings-in-place) |
| `q` | | Quit. While a command runs, the UI stays up, shows `Waiting for opentide generate to finish…` and closes when it is done: a command cannot be stopped halfway, and it would otherwise go on writing files and printing into the shell after the UI had gone |

A command runs in the background, one at a time, so the UI stays responsive. When it finishes, the catalogue is read again (generate may have rewritten it), and an object with findings shows `✗ 2` (errors) or `! 1` (warnings) after its name. In the Results tab, the query lines of a code frame are coloured as at a terminal.

## Visibility

The Visibility tab reads `.opentide/configurations/visibility.toml` as a table, not as TOML:

- **Tiles** at the top: log sources per system, how many declare columns and how many are used, then what needs attention: log sources with no columns (the column checks cannot run on them), log sources no rule uses, and datasets rules read that no log source declares.
- **The table:** each log source with its system, column count, how many rules use it, what needs attention and its description, then each dataset rules read that is not declared, in red. Type in the filter to narrow it by name or description, or `system:sentinel` by system.
- **The drill-down** below shows the highlighted log source's columns with their types and descriptions, the rules whose queries read it, the rules that use it through a signal, and the objectives whose signals name it. `Enter` opens the first rule that uses it.

A rule uses a log source in two ways. Its query reads the dataset: the table, sourcetype or index pattern, as the analysis engine reads the query, custom tables its catalog does not list (`MyApp_CL`) included. Names match as the query checks match them: `*` is the only wildcard, in a declared pattern (`logs-*` covers `logs-windows`) or in one a query reads, and Splunk sourcetypes ignore case. Or it implements a signal, or the objective of a signal, whose `data.logsources` names it, without regard to case. A dataset read that no log source of its system declares is listed even when the system declares none; the query checks only warn about it (`kql_table_not_declared`) once the system declares one. Without the engine, the datasets queries read are not known, and the tab says so.
## Configuration

The Configuration tab lists the configuration files on the left and shows the highlighted one on the right:

- **Each setting** by section, with its effective value (the bundled file, the workspace's and the parent instance merged, as every command reads them), whether the workspace sets it (`set here`) or it is the bundled `default`, and what it does: the description its schema gives, or for `lint.toml` the bundled file's comment.
- **Findings** from the configuration checks `opentide validate` runs, under the setting they are about.
- **Not set (N):** the options nothing sets, with their descriptions.
- **A platform file** starts with its card: enabled or not, the rules with a block for it, and each tenant with its strategies, whether it is `manual`, its credentials, and the rules a deploy run reaches it with (a rule that lists tenants reaches those; otherwise a tenant that is not `manual` takes the rules whose status a strategy it accepts deploys).
- **`t`** shows the raw file instead.

No credential value appears anywhere, the raw file included. A value with a `setup` table, or a key that names a secret (`key`, `token`, `password`, `secret`, `auth`, `credentials`…), anywhere on its key path, such as each value under `[platform.credentials]`, reads as its variable name and whether the environment sets it (`${AZURE_CLIENT_SECRET}  unset`), as [`opentide doctor`](./doctor.md) reports it, or as `•••• hidden` when it is a literal. The user and password of a URL are hidden too, up to the last `@` before the host. A switch such as `ssl = true` is shown as it is.

The raw file is redacted however its TOML writes a value (inline tables and arrays, quoted keys and headers, strings over several lines), then read back to check that no credential is left in it. A file that is not valid TOML has no raw view: `t` says where the error is (`not valid TOML: line 3, column 14`), never what the line holds. A file whose redaction cannot be proven, for example because a comment quotes a credential the file also sets, has no raw view either; its settings are still listed.
## Chains

The Chains tab draws `threat.chaining` around one threat: the one selected in the Catalogue, else the first with links. A whole catalogue's chaining is too much to read at once, so it starts with the threats one link away and grows by hops.

- **Sequence links** (`sequence::preceeds`, `sequence::succeeds`) run left to right as attack flow: each threat is a box, `──▶` between steps.
- **Each box** shows the rules under the threat's objectives, in red when there are none (an undetected step), and how many of the techniques it names some rule covers, own or inherited, as the [Coverage tab](#layout) counts them.
- **Supporting and atomicity links** (`support::*`, `atomicity::*`) are listed beside the flow, labelled by how they read (`enables`, `implemented by`, `synergizes with`) and coloured by relation. Threats linked only that way are shown under the flow.
- **One link, shown once:** a link written from both ends (`A preceeds B` in A, `B succeeds A` in B) is merged, with both descriptions. A link to a threat the catalogue does not have says so.
- **The list on the left** holds the threats shown. Highlighting one describes its links. `Enter` opens it in the Catalogue, `c` centres the chain on it, `+` and `-` add or remove a hop (up to 4), and `l` cycles the relations shown: all, sequence, atomicity, support (`r` stays Reload).

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

The Rust command line has its own UI on ratatui (`crates/opentide-cli/src/tui/`), with the same tabs, keys and actions. `opentide tui` still opens the Python one: the Rust UI's Configuration tab and `generate` (the full pipeline) are not ported yet.
