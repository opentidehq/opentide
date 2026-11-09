---
title: opentide lsp
description: The opentide language server, for editors.
---

# opentide lsp

`pip install opentide` installs the opentide language server: the analysis engine from [opentidehq/language-server](https://github.com/opentidehq/language-server), compiled into the opentide package. There is no second package and no extra. It understands KQL (Sentinel and Defender), SPL, ES|QL, EQL, Kibana KQL (`kuery`), Lucene, Falco (Sysdig Secure) and Tide YAML objects, including the queries inside a rule, and opentide's configuration files.

```bash
opentide lsp start
```

`opentide lsp` serves editors. On the command line, opentide's own verbs report what the engine finds: [`opentide validate`](./validate.md#queries) the queries a platform would reject, [`opentide validate query`](./validate.md#query-validation) the same for a rule or a query file (`--file hunting/lsass.kql`), and [`opentide lint`](./lint.md#queries) their style. [`opentide tui`](./tui.md#the-language-server) shows the editor's findings for each object as you browse.

## lsp start

Serves the [language server protocol](https://microsoft.github.io/language-server-protocol/) on stdin and stdout until the editor sends `exit` or closes stdin. The editor starts it; you do not run it yourself. `--stdio` is accepted, and changes nothing, for editors that pass it: stdio is the only transport.

| Feature | What you get |
|---------|--------------|
| Diagnostics | Each query checked in its platform's language, and the object's fields, references and vocabulary, as you type. Configuration files under `.opentide/configurations/` checked as `opentide validate` checks them. Pushed, or pulled by a client that pulls ([Diagnostics](#diagnostics)) |
| Hover, completion, signature help | Query commands, functions, tables and fields; Tide fields and vocabulary values with their descriptions; configuration keys and their allowed values |
| Definition, references | Object UUIDs across the workspace: go to the object a UUID names, or list every object that names it |
| Document and workspace symbols | Each object's outline (sections, platform blocks, queries); every object of every workspace folder by name, UUID or family |
| Links, lenses, inlay hints | ATT&CK ids to attack.mitre.org and UUIDs to the object's file; "N rules use this objective" on an objective or threat ([Code lens](#code-lens)); the family and name of each object a UUID names |
| Highlights, folding, selection ranges | Every occurrence of the UUID under the cursor; a fold for each indented block; selection that grows by indentation |
| Quick fixes | Each suggestion, one at a time or all at once (`source.fixAll.opentide`), and a missing dataset declared in `visibility.toml` ([Code actions](#code-actions)) |
| Semantic tokens | Highlighting for objects and the queries inside them |

Each workspace folder the editor opens is a workspace of its own, with its own objects, `visibility.toml` and configuration; folders added or removed while it runs (`workspace/didChangeWorkspaceFolders`) are followed. The server tells the editor it runs inside opentide ([Server identity](#server-identity)).

`opentide lsp` on its own does not start the server: it names `start` and exits `2` (`usage_error`), as [`opentide mcp`](./mcp.md#mcp) does.

Like `opentide mcp start`, it runs in the `mcp` [output mode](./global-options.md): stdout carries the protocol and nothing else, logs go to stderr. When the engine does not load, it prints one `error:` line on stderr and exits `1` before any protocol byte (see [`engine_unavailable`](./diagnostics.md#engine_unavailable)). At a terminal it says on stderr what it is for. As the protocol specifies, it exits `0` when the editor sends `shutdown` and then `exit`, and `1` when the editor exits or closes stdin without `shutdown`. Ctrl-C stops it with exit `130`.

Hover, completion and the object checks come from a catalog of every field of every schema revision. Each object is checked against the revision its `metadata.schema` names, as [`opentide validate`](./validate.md#schema-identifier) checks it: a field that revision requires and is missing, or a key it does not define (`metadata.reviewed` in a `rule::1.0`), is a `schema_validation` error. `opentide lsp start` generates the catalog from this opentide's models and the configuration of the workspace it starts in (log sources, statuses), so it is never behind your opentide, and caches it under the user cache directory (`OPENTIDE_CACHE_DIR` overrides it). It does not read the copy [`opentide generate schemas`](./generate.md) writes to `.opentide/lsp/catalogs/generated/`: that copy is for editors that run the `opentide-lsp` binary on its own, and for when generation fails, in which case the server uses it, or the catalog compiled into the engine, and says so on stderr. `opentide doctor` checks both (`lsp_catalog`). The tables, sourcetypes and index patterns the log sources of `.opentide/configurations/visibility.toml` name ([The datasets a log source fills](../usage/configuration.md#the-datasets-a-log-source-fills)) are read from the file itself, at start-up and whenever it changes: an edit in the editor applies before it is saved, an edit on disk once the editor reports it (the server asks to watch the file), and every open document is checked again.

### Languages

The server picks each document's language once, when the editor opens it:

1. A `.toml` file under `.opentide/configurations/` is `opentide-config`, whatever id the editor sends. No other `.toml` is read.
2. Otherwise the editor's language id, when it is one of the ids below or an alias.
3. Otherwise the file's extension: `.kql`, `.spl`, `.esql`, `.eql`, `.kuery`, `.lucene`, `.falco`, `.cql`.
4. Otherwise Tide YAML. A YAML document is analysed only when the editor sends `opentide-yaml`, the file is under an `objects/` folder, or it names a Tide schema (`metadata.schema: rule::1.0`), so CI workflows and other YAML files get no findings.

| Language id | Aliases | Files |
|-------------|---------|-------|
| `opentide-yaml` | `yaml`, `tide`, `tide-yaml` | Threats, objectives and rules |
| `kql` | `kusto`, `opentide-kql` | `.kql`: Sentinel and Defender queries |
| `spl` | `opentide-spl` | `.spl`: Splunk searches |
| `esql` | `opentide-esql` | `.esql` |
| `eql` | `opentide-eql` | `.eql` |
| `kuery` | `kibana-kql`, `opentide-kuery` | `.kuery`: Kibana KQL, never confused with Microsoft KQL |
| `lucene` | `opentide-lucene` | `.lucene` |
| `falco` | `opentide-falco` | `.falco`: Falco conditions (Sysdig Secure) |
| `cql` | `opentide-cql`, `logscale`, `crowdstrike` | `.cql`: the CrowdStrike Query Language (Falcon LogScale and Next-Gen SIEM) |
| `opentide-config` | — | `.opentide/configurations/**/*.toml` |

There is no `sql` language. Inside a rule, each query is analysed in the language of its block: `configurations.sentinel.query` and `configurations.defender_for_endpoint.query` as KQL, `configurations.splunk.query` as SPL, `configurations.carbon_black_cloud.query` as Lucene, `configurations.sysdig.condition` as Falco, `configurations.crowdstrike.query` as CQL (a Next-Gen SIEM correlation rule), and an Elastic query by the block's `type` and `language`. A hunt's search takes the language of its `system`.

### Diagnostics

Each diagnostic carries `range`, `severity` (error `1`, warning `2`, information `3`, hint `4`), `code`, `message`, `source: "opentide"` and `data: { field_path, suggestion }`. For a client that declares support for them, it also carries `codeDescription.href`, the code's section of [Diagnostic codes](./diagnostics.md) (`https://opentide.org/docs/cli/diagnostics/#<code>`, the page `opentide explain <code>` prints), the `Deprecated` tag on a deprecation code, the other file of a `duplicate_id` in `relatedInformation`, and the document `version` on a published set.

The server publishes diagnostics as documents change (`textDocument/publishDiagnostics`). A client that pulls (`textDocument.diagnostic` and `workspace.diagnostics.refreshSupport` in its capabilities) gets a `diagnosticProvider` instead: `textDocument/diagnostic` answers one document, `unchanged` when it is the same as the report its `previousResultId` names, and `workspace/diagnostic` every object file of every folder that no editor has open, with the findings that need the whole workspace (`duplicate_id`, `invalid_ref`). When something every document depends on changes (`visibility.toml`, a configuration file, an object another references), the server asks the client to pull again, and to refresh its semantic tokens, inlay hints and lenses.

### Code actions

`textDocument/codeAction` offers `quickfix` actions for the diagnostics in `context.diagnostics`, or, when the client sends none, for those on the requested lines. Each names its diagnostic and is preferred.

- **Apply a suggestion.** A diagnostic with a `suggestion` gets `Apply suggestion: <suggestion>`, an edit that replaces the diagnostic's range: the bad name in a query, the key in a Tide object. Which codes carry one is in the language server's [`docs/EDITORS.md`](https://github.com/opentidehq/language-server/blob/main/docs/EDITORS.md).
- **Declare a dataset.** In a workspace folder, `kql_table_not_declared`, a `kql_unknown_table` that names `visibility.toml`, `spl_dataset_not_declared` and `elastic_dataset_not_declared` get `Add a [[logsources]] entry declaring '<name>' to visibility.toml`. The edit appends a log source (`name`, an empty `description` to fill in, and `system`) to `.opentide/configurations/visibility.toml` and never edits an existing one. When the file is missing, the edit creates it for a client that can create files (`workspaceEdit.documentChanges` and `resourceOperations: ["create"]`); other clients get no action then. See [The datasets a log source fills](../usage/configuration.md#the-datasets-a-log-source-fills).
- **Fix all.** `source.fixAll.opentide`, only when `context.only` asks for it (`source`, `source.fixAll`): every suggestion of the document as one edit. Editors run it on save when you enable fix-all for the source.

### Code lens

On an objective's or a threat's `metadata.uuid`, the lens reads `N rules use this objective`, counted by family, or `No object uses this objective`. Its command is `opentide.showReferences` with the arguments `[uri, position, locations]`. The server does not run it: an editor registers that command to show the locations (in VS Code, call `editor.action.showReferences` with the arguments converted to its types). An editor that does not register it shows the lens without an action.

### Server identity

`initialize` answers `serverInfo` `{ "name": "opentide-lsp", "version": <engine version> }`, `positionEncoding` `utf-16`, incremental document sync, and `capabilities.experimental.opentide`:

```json illustrative
{
  "host": { "name": "opentide", "version": "0.21.0" },
  "engine": "0.9.1",
  "catalog": "host",
  "configurationChecks": true,
  "configurationSchemas": true
}
```

| Key | Meaning |
|-----|---------|
| `host` | `opentide` and its version under `opentide lsp start`; `null` from the `opentide-lsp` binary on its own |
| `engine` | The language server's version, the engine compiled into opentide |
| `catalog` | Where the Tide catalog came from: `host` (generated by this opentide for the workspace), `workspace` (`.opentide/lsp/catalogs/generated/`) or `bundled` (compiled into the engine) |
| `configurationChecks`, `configurationSchemas` | Whether configuration files are checked, and have hover and completion: `true` only under `opentide lsp start` |

A key is added in a minor release and never removed. An editor extension reads it to tell what it is talking to. The example above is not captured output: the versions are this release's.

### Requests beyond LSP

The server answers a few requests of its own, for editor extensions and tools that know them. Params and results are JSON; positions are UTF-16, as everywhere.

| Method | Params | Result |
|--------|--------|--------|
| `opentide/analyze` | `{ text, language?, uri? }` | `{ diagnostics }`: the engine's findings for a text that need not be open, each `{ code, message, severity, range, suggestion? }` with `severity` as a word (`error`, `warning`, …). `uri` places it in a workspace folder, for its `visibility.toml` |
| `opentide/highlight` | `{ text, language? }` | `{ language_id, legend, tokens }`: the highlight tokens, each with its `capture`, `range`, `span` (bytes) and `token_type` (an index into `legend`) |
| `opentide/compiledKql` | `{ query, tenant? }` | `{ compiled }`: the KQL Sentinel runs for the query |
| `opentide/compiledSpl` | `{ query }` | `{ compiled }`: the search Splunk runs, which is the search as written |
| `opentide/fs/read` | `{ path }` | `{ text }`: a workspace file as the server sees it, the open buffer first; empty when there is none |

`language` takes the ids and aliases of [Languages](#languages). Without it, `opentide/analyze` reads the text as Tide YAML and `opentide/highlight` as KQL. A method the server does not know is `MethodNotFound` (`-32601`), and params that do not parse are `InvalidParams` (`-32602`).

`initialize` may also carry `initializationOptions.workspace`: `{ objects: [{ uuid, schema, name }], documents: [{ uri, text }], visibility }`. It is for clients without a filesystem to index, such as the engine in a browser worker; a document the editor opens replaces the one supplied with its UUID, and a folder's own files win over what is supplied.

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

Run `opentide lsp start` as the server command, for YAML files under `objects/`, for query files (`.kql`, `.spl`, `.esql`, `.eql`, `.kuery`, `.lucene`, `.falco`, `.cql`), and for `.opentide/configurations/**/*.toml`. The completion triggers are `|`, space, `:`, `.`, `(`, `,`, `` ` `` and `=`; signature help opens on `(`, `,`, `=` and `` ` ``. The server reads a TOML file under `.opentide/configurations/` as language `opentide-config`, whatever id the editor sends, and no other `.toml`. Turn off other YAML language servers for `objects/**`, and other TOML language servers (Taplo, Even Better TOML) for `.opentide/configurations/**`: opentide reports those files' diagnostics itself.

Neovim (0.11 or later):

```lua
vim.lsp.config("opentide", {
  cmd = { "opentide", "lsp", "start" },
  filetypes = { "yaml", "kql", "spl", "esql", "eql", "kuery", "lucene", "falco", "cql" },
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

Then add `opentide` to the `language-servers` of the languages you edit. Zed takes the same command; the language server repository has [samples for Helix, Neovim and Zed](https://github.com/opentidehq/language-server/tree/main/editors). In VS Code, install the opentide extension (`opentidehq.opentide`), which brings the language server.

## Supported languages and platforms

| Platform | Query language | Offline check |
|----------|----------------|:-------------:|
| Sentinel | KQL (Sentinel tables) | ✅ |
| Defender for Endpoint | KQL (Defender tables) | ✅ |
| Splunk | SPL | ✅ |
| Elastic | ES\|QL, EQL, Kibana KQL, Lucene (by the block's `type` and `language`; ES\|QL against the tenants' `setup.version`) | ✅ |
| Carbon Black Cloud | Lucene (Carbon Black dialect) | ✅ |
| Sysdig Secure | Falco (the block's `condition`, exceptions, macros and lists) | ✅ |
| SentinelOne | S1QL | ❌ tenant only: `opentide validate query --platform sentinel_one --live` |
| CrowdStrike | CQL (the block's `query`, a correlation rule; a hunt with `system: crowdstrike`) | ✅ |
| HarfangLab | — | ❌ never validated |

## opentide lsp start and opentide-lsp

The engine is also published on its own, as the `opentide-lsp` binary ([releases](https://github.com/opentidehq/language-server/releases) and crates.io). `opentide lsp start` runs the same server, with what only opentide can add:

| | `opentide lsp start` | `opentide-lsp --stdio` |
|---|---|---|
| Tide catalog | Generated from this opentide's models and the workspace's configuration | `.opentide/lsp/catalogs/generated/` from [`opentide generate schemas`](./generate.md), else the one compiled into the engine |
| Configuration files | Checked, with hover and completion | Not read |
| `capabilities.experimental.opentide.host` | `opentide` and its version | `null` |

Use `opentide lsp start` when opentide is installed; the binary on its own suits an editor without Python. Its own command line (`--listen` for TCP, `--version --json`, `analyze`, `highlight`) is documented in the language server repository.

## Source

`src/opentide/cli/lsp_app.py`, `src/opentide/cli/services/lsp.py`, `src/opentide/analysis.py`, the bindings in `analysis/`, and the engine in `crates/`.
