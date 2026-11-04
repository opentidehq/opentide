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
| Diagnostics | Each query checked in its platform's language, and the object's fields, references and vocabulary, as you type. Configuration files under `.opentide/configurations/` checked as `opentide validate` checks them |
| Hover, completion, signature help | Query commands, functions, tables and fields; Tide fields and vocabulary values with their descriptions; configuration keys and their allowed values |
| Definition, references, symbols | Object UUIDs across the workspace; each object's outline (sections, platform blocks, queries) |
| Links, lenses, inlay hints | ATT&CK ids to attack.mitre.org and UUIDs to the object's file; "N rules use this objective" on an objective or threat; the name of each object a UUID names |
| Quick fixes | Each suggestion, one at a time or all at once (`source.fixAll.opentide`) |
| Semantic tokens | Highlighting for objects and the queries inside them |

Each workspace folder the editor opens is a workspace of its own, with its own objects, `visibility.toml` and configuration. The server tells the editor it runs inside opentide: `initialize` answers `capabilities.experimental.opentide.host` = `{ "name": "opentide", "version": <this opentide> }`, which the `opentide-lsp` binary on its own leaves `null` (see the language server's `docs/EDITORS.md`).

Like `opentide mcp start`, it runs in the `mcp` [output mode](./global-options.md): stdout carries the protocol and nothing else, logs go to stderr. When the engine does not load, it prints one `error:` line on stderr and exits `1` before any protocol byte (see [`engine_unavailable`](./diagnostics.md#engine_unavailable)). At a terminal it says on stderr what it is for. As the protocol specifies, it exits `0` when the editor sends `shutdown` and then `exit`, and `1` when the editor exits or closes stdin without `shutdown`. Ctrl-C stops it with exit `130`.

Hover, completion and the object checks come from a catalog of every field of every schema revision. Each object is checked against the revision its `metadata.schema` names, as [`opentide validate`](./validate.md#schema-identifier) checks it: a field that revision requires and is missing, or a key it does not define (`metadata.reviewed` in a `rule::1.0`), is a `schema_validation` error. `opentide lsp start` generates the catalog from this opentide's models and the configuration of the workspace it starts in (log sources, statuses), so it is never behind your opentide, and caches it under the user cache directory (`OPENTIDE_CACHE_DIR` overrides it). It does not read the copy [`opentide generate schemas`](./generate.md) writes to `.opentide/lsp/catalogs/generated/`: that copy is for editors that run the `opentide-lsp` binary on its own, and for when generation fails, in which case the server uses it, or the catalog compiled into the engine, and says so on stderr. `opentide doctor` checks both (`lsp_catalog`). The tables, sourcetypes and index patterns the log sources of `.opentide/configurations/visibility.toml` name ([The datasets a log source fills](../usage/configuration.md#the-datasets-a-log-source-fills)) are read from the file itself, at start-up and whenever it changes: an edit in the editor applies before it is saved, an edit on disk once the editor reports it (the server asks to watch the file), and every open document is checked again.

### Configuration files

A TOML file under `.opentide/configurations/` (`deployment.toml`, `sharing.toml`, `platforms/sentinel.toml`, ...) is checked as you type with the same models and checks [`opentide validate`](./validate.md) runs (`configuration`, and `sharing-config` for `sharing.toml`). Each finding is on the key it names. A key the file lacks is reported on its table or `[[block]]` header.

- **Layers.** The file is a partial override: it is merged onto the bundled file and the parent instance's file before it is checked. A block that restates only `name` and what it changes is not reported for the keys it inherits.
- **Open buffers.** The statuses `sharing.toml` may name come from an open `deployment.toml`, saved or not. Editing one configuration file checks the others again.
- **`configurations/sharing/`** is reported as `sharing_directory` when it exists.
- **No model.** A file opentide has no model for (`resources.toml`, `lint.toml`) gets no findings.
- **Hover and completion** come from the JSON Schema of each file's model, which `python -m opentide.generation.configuration_schemas` also exports. Hover shows a key's title, type, description, allowed values and default, never its value. Completion offers the keys a table may still take, table names in a header, and allowed values after `=`.
- **Highlighting** is your editor's TOML grammar: the server sends no semantic tokens for these files.

Only `opentide lsp start` checks configuration files. The `opentide-lsp` binary on its own reports nothing for them.

### Configuring an editor

Run `opentide lsp start` as the server command, for YAML files under `objects/`, for query files (`.kql`, `.spl`, `.esql`, `.eql`, `.kuery`, `.lucene`, `.falco`), and for `.opentide/configurations/**/*.toml`. The server reads a TOML file under `.opentide/configurations/` as language `opentide-config`, whatever id the editor sends, and no other `.toml`. Turn off other YAML language servers for `objects/**`, and other TOML language servers (Taplo, Even Better TOML) for `.opentide/configurations/**`: opentide reports those files' diagnostics itself.

Neovim (0.11 or later):

```lua
vim.lsp.config("opentide", {
  cmd = { "opentide", "lsp", "start" },
  filetypes = { "yaml", "kql", "spl", "esql", "eql", "kuery", "lucene", "falco" },
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
