---
title: opentide lsp
description: The opentide language server, for editors.
---

# opentide lsp

`pip install opentide` installs the opentide language server: the analysis engine from [opentidehq/language-server](https://github.com/opentidehq/language-server), compiled into the opentide package. There is no second package and no extra. It understands KQL (Sentinel and Defender), SPL, ES|QL, EQL, Kibana KQL (`kuery`), Lucene and Tide YAML objects, including the queries inside a rule.

```bash
opentide lsp start
```

`opentide lsp` serves editors. On the command line, opentide's own verbs report what the engine finds: [`opentide validate`](./validate.md#queries) the queries a platform would reject, [`opentide validate query`](./validate.md#query-validation) the same for a rule or a query file (`--file hunting/lsass.kql`), and [`opentide lint`](./lint.md#queries) their style. [`opentide tui`](./tui.md#the-language-server) shows the editor's findings for each object as you browse.

## lsp start

Serves the [language server protocol](https://microsoft.github.io/language-server-protocol/) on stdin and stdout until the editor sends `exit` or closes stdin. The editor starts it; you do not run it yourself. `--stdio` is accepted, and changes nothing, for editors that pass it: stdio is the only transport.

| Feature | What you get |
|---------|--------------|
| Diagnostics | Each query checked in its platform's language, and the object's fields, references and vocabulary, as you type |
| Hover, completion, signature help | Query commands, functions, tables and fields; Tide fields and vocabulary values with their descriptions |
| Definition, references, symbols | Object UUIDs across the workspace |
| Semantic tokens | Highlighting for objects and the queries inside them |

Like `opentide mcp start`, it runs in the `mcp` [output mode](./global-options.md): stdout carries the protocol and nothing else, logs go to stderr. When the engine does not load, it prints one `error:` line on stderr and exits `1` before any protocol byte (see [`engine_unavailable`](./diagnostics.md#engine_unavailable)). At a terminal it says on stderr what it is for. Ctrl-C stops it with exit `130`.

Hover, completion and the object checks come from a catalog of every field of every schema revision. Each object is checked against the revision its `metadata.schema` names, as [`opentide validate`](./validate.md#schema-identifier) checks it: a field that revision requires and is missing, or a key it does not define (`metadata.reviewed` in a `rule::1.0`), is a `schema_validation` error. `opentide lsp start` generates the catalog from this opentide's models and the configuration of the workspace it starts in (log sources, statuses), so it is never behind your opentide, and caches it under the user cache directory (`OPENTIDE_CACHE_DIR` overrides it). It does not read the copy [`opentide generate schemas`](./generate.md) writes to `.opentide/lsp/catalogs/generated/`: that copy is for editors that run the `opentide-lsp` binary on its own, and for when generation fails, in which case the server uses it, or the catalog compiled into the engine, and says so on stderr. `opentide doctor` checks both (`lsp_catalog`). The tables, indexes and index patterns the log sources of `visibility.toml` name ([The datasets a log source fills](../usage/configuration.md#the-datasets-a-log-source-fills)) are read at start-up too: restart the server after changing them.

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
