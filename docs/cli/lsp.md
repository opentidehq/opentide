---
title: opentide lsp
description: The opentide language server for editors, and the diagnostics it shows, on the command line.
---

# opentide lsp

`pip install opentide` installs the opentide language server: the analysis engine from [opentidehq/language-server](https://github.com/opentidehq/language-server), compiled into the opentide package. There is no second package and no extra. It understands KQL (Sentinel and Defender), SPL, ES|QL, EQL, Kibana KQL (`kuery`), Lucene and Tide YAML objects, including the queries inside a rule.

```bash
opentide lsp start
opentide lsp check
opentide lsp check objects/rules/suspicious-lsass-access.yaml
opentide --json lsp check hunting/lsass.kql
```

## lsp start

Serves the [language server protocol](https://microsoft.github.io/language-server-protocol/) on stdin and stdout until the editor sends `exit` or closes stdin. The editor starts it; you do not run it yourself. `--stdio` is accepted, and changes nothing, for editors that pass it: stdio is the only transport.

| Feature | What you get |
|---------|--------------|
| Diagnostics | Each query checked in its platform's language, and the object's fields, references and vocabulary, as you type |
| Hover, completion, signature help | Query commands, functions, tables and fields; Tide fields and vocabulary values with their descriptions |
| Definition, references, symbols | Object UUIDs across the workspace |
| Semantic tokens | Highlighting for objects and the queries inside them |

Like `opentide mcp start`, it runs in the `mcp` [output mode](./global-options.md): stdout carries the protocol and nothing else, logs go to stderr. When the engine does not load, it prints one `error:` line on stderr and exits `1` before any protocol byte (see [`engine_unavailable`](./diagnostics.md#engine_unavailable)). At a terminal it says on stderr what it is for. Ctrl-C stops it with exit `130`.

Hover, completion and the object checks come from a catalog of every field of every schema revision. Each object is checked against the revision its `metadata.schema` names, as [`opentide validate`](./validate.md#schema-identifier) checks it: a field that revision requires and is missing, or a key it does not define (`metadata.reviewed` in a `rule::1.0`), is a `schema_validation` error. `opentide lsp start` generates the catalog from this opentide's models and the configuration of the workspace it starts in (log sources, statuses), so it is never behind your opentide, and caches it under the user cache directory (`OPENTIDE_CACHE_DIR` overrides it). It does not read the copy [`opentide generate schemas`](./generate.md) writes to `.opentide/lsp/catalogs/generated/`: that copy is for editors that run the `opentide-lsp` binary on its own, and for when generation fails, in which case the server uses it, or the catalog compiled into the engine, and says so on stderr. `opentide doctor` checks both (`lsp_catalog`).

### Configuring an editor

Run `opentide lsp start` as the server command, for YAML files under `objects/` and for query files (`.kql`, `.spl`, `.esql`, `.eql`, `.kuery`, `.lucene`). Turn off other YAML language servers for `objects/**`: opentide reports those files' diagnostics itself.

Neovim (0.11 or later):

```lua
vim.lsp.config("opentide", {
  cmd = { "opentide", "lsp", "start" },
  filetypes = { "yaml", "kql", "spl", "esql", "eql", "kuery", "lucene" },
  root_markers = { ".opentide" },
})
vim.lsp.enable("opentide")
```

Helix (`languages.toml`):

```toml
[language-server.opentide]
command = "opentide"
args = ["lsp", "start"]
```

Then add `opentide` to the `language-servers` of the languages you edit. Zed and VS Code take the same command; the language server repository has [samples for each](https://github.com/opentidehq/language-server/tree/main/editors).

## lsp check

Prints what the language server reports for each file, as code frames, then one outcome line: the diagnostics your editor shows, without an editor. At a terminal, the query lines of a frame are coloured as the editor colours them. With no path it checks every object file of the workspace. In a folder it checks the query files (the extensions above) and the YAML files that are objects of the workspace, and skips hidden files and folders, so `opentide lsp check .` leaves CI workflows and templates alone; a file you name is always checked. A file's language comes from its extension; `--language` reads every file as one language.

| Flag | Purpose |
|------|---------|
| `PATH`… | Files or folders to check. Default: every object file |
| `--language` | Read every file as `kql`, `spl`, `esql`, `eql`, `kuery`, `lucene` or `opentide-yaml` |
| `--strict` | Fail on warnings too |

```text illustrative
warning[kql_where_not_first]: `where` is not the first operator after the table reference; filter before later operators
  ╭─▶ hunting/lsass.kql:3:3
  │
2 │ | summarize count() by Account
3 │ | where Account != ""
  │   ━━━━━━━━━━━━━━━━━━━
  │
  ╰─ help: the KQL reference: https://learn.microsoft.com/kusto/query/

! 1 warning in 1 file · 1 file checked
```

Errors fail the run with exit `1` (`failure.code` `issues_found`); warnings only under `--strict`. Notes (hints such as a Lucene term without a field) never fail it. A path that does not exist, or a file whose language its name does not say, exits `2` (`usage_invalid_value`). In CI the findings become annotations, as for [`validate`](./validate.md#reports-and-ci-annotations).

Each finding has a stable code; `opentide explain <code>` prints what it means and links the language's reference ([Diagnostic codes](./diagnostics.md) lists them). Columns count Unicode code points, as in every opentide diagnostic.

`lsp check` and `opentide validate` read the same objects but are not the same check. [`opentide validate`](./validate.md) is the authority for objects: its schema, vocabulary and reference checks decide whether a rule deploys. The language server reports similar findings, sometimes with its own code (`filename_slug`, `missing_author`), for the editor. To check every rule's query on top of `validate`, run `opentide validate --deep`. [`opentide tui`](./tui.md#the-language-server) shows these findings for each object as you browse, with the file coloured as the editor colours it.

With `--json`:

| Key | Value |
|-----|-------|
| `files_checked` | Files read |
| `diagnostics` | Each finding with `code`, `severity` (`error`, `warning`, `note`), `message`, `path`, `line`, `column`, `end_column`, `field_path`, `help` and `explain` |
| `catalog` | `{source, opentide, path, problem}`: `opentide` when this opentide generated it, `workspace` (the committed copy) or `bundled` (the engine's) when it could not, and why |
| `engine` | `{engine}`: the version of the language-server crates compiled into opentide |
| `summary` | `files`, `errors`, `warnings`, `notes`, `error_files`, `warning_files` |

## Supported languages and platforms

| Platform | Query language | Offline check |
|----------|----------------|:-------------:|
| Sentinel | KQL (Sentinel tables) | ✅ |
| Defender for Endpoint | KQL (Defender tables) | ✅ |
| Splunk | SPL | ✅ |
| Elastic | ES\|QL, EQL, Kibana KQL, Lucene (by the block's `type` and `language`; ES\|QL against the tenants' `setup.version`) | ✅ |
| Carbon Black Cloud | Lucene (Carbon Black dialect) | ✅ |
| SentinelOne | S1QL | ❌ tenant only: `opentide validate query --platform sentinel_one --live` |
| CrowdStrike, HarfangLab | — | ❌ never validated |

## Source

`src/opentide/cli/lsp_app.py`, `src/opentide/cli/services/lsp.py`, `src/opentide/analysis.py`, and the bindings in `analysis/`.
