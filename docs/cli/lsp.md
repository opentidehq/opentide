---
title: opentide lsp
description: The opentide language server, for editors.
---

# opentide lsp

`pip install opentide` installs the opentide language server: the analysis engine and the server, built from this repository's Rust workspace ([`crates/opentide-lsp`](https://github.com/opentidehq/opentide/tree/development/crates/opentide-lsp)) and compiled into the opentide package. There is no second package and no extra. The same server ships on its own as the `opentide-lsp` binary ([opentide lsp start and opentide-lsp](#opentide-lsp-start-and-opentide-lsp)). It used to come from opentidehq/language-server; if your editor runs a binary from there, see [Moving from the language-server distribution](../usage/migration/language-server.md). It understands KQL (Sentinel and Defender), SPL, ES|QL, EQL, Kibana KQL (`kuery`), Lucene, Falco (Sysdig Secure), CQL (CrowdStrike), YARA (HarfangLab and Bitdefender), Exabeam and YARA-L (Google Security Operations) queries, and Tide YAML objects, including the queries inside a rule, and opentide's configuration files.

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

A field whose values come from a vocabulary (ATT&CK techniques, threat actors, impact, TLP) offers each value once, with its name beside it: `T1548.002  Abuse Elevation Control Mechanism: Bypass User Account Control`. Typing a word of the name or of an alias finds the value too (`bypass`, `Comment Crew`). The value is inserted on its own, and the editor shows the entry's name, identifier, vocabulary and description when you select it (the server sends it in `completionItem/resolve`, so the list carries no descriptions). An editor that shows nothing beside a label shows the name as the item's detail. The JSON Schemas [`opentide generate schemas`](./generate.md) writes still list each such value a second time as `T1548 #Abuse Elevation Control Mechanism`, for editors that know only the schema: YAML reads what follows ` #` as a comment, so what such an editor inserts is still the value.

Hover, completion and the object checks come from a catalog of every field of every schema revision. Each object is checked against the revision its `metadata.schema` names, as [`opentide validate`](./validate.md#schema-identifier) checks it: a field that revision requires and is missing, or a key it does not define (`metadata.reviewed` in a `rule::1.0`), is a `schema_validation` error. `opentide lsp start` generates the catalog from this opentide's models and the configuration of the workspace it starts in (log sources, statuses), in memory each time it starts, so it is never behind your opentide; nothing is cached on disk. The `opentide-lsp` binary on its own generates the same catalog from the models it was built with and the configuration of each workspace folder. Neither reads the copy [`opentide generate schemas`](./generate.md) writes to `.opentide/lsp/catalogs/generated/`. `opentide doctor` checks both (`lsp_catalog`). The tables, sourcetypes and index patterns the log sources of `.opentide/configurations/visibility.toml` name ([The datasets a log source fills](../usage/configuration.md#the-datasets-a-log-source-fills)) are read from the file itself, at start-up and whenever it changes: an edit in the editor applies before it is saved, an edit on disk once the editor reports it (the server asks to watch the file), and every open document is checked again.

### Languages

The server picks each document's language once, when the editor opens it:

1. A `.toml` file under `.opentide/configurations/` is `opentide-config`, whatever id the editor sends. No other `.toml` is read.
2. Otherwise the editor's language id, when it is one of the ids below or an alias.
3. Otherwise the file's extension: `.kql`, `.spl`, `.esql`, `.eql`, `.kuery`, `.lucene`, `.falco`, `.cql`, `.yar`, `.yara`, `.exabeam`, `.yaral`, `.yl2`.
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
| `yara` | `opentide-yara` | `.yar`, `.yara`: YARA rules (HarfangLab and Bitdefender) |
| `exabeam` | `opentide-exabeam` | `.exabeam`: the Exabeam Query Language |
| `yaral` | `opentide-yaral`, `yara-l` | `.yaral`, `.yl2`: YARA-L 2.0 (Google Security Operations) |
| `opentide-config` | — | `.opentide/configurations/**/*.toml` |

There is no `sql` language. Inside a rule, each query is analysed in the language of its block: `configurations.sentinel.query` and `configurations.defender_for_endpoint.query` as KQL, `configurations.splunk.query` as SPL, `configurations.carbon_black_cloud.query` and `configurations.graylog.query` as Lucene (in each one's dialect), `configurations.sysdig.condition` as Falco, `configurations.crowdstrike.query` as CQL (a Next-Gen SIEM correlation rule), a Google SecOps block's `setup`, `events`, `outcome`, `condition` and `export` as YARA-L (together, as the one rule deploy assembles), a HarfangLab block's `yara.signature` as YARA and its decomposed `imports`, `strings` and `condition` as the one YARA rule deploy assembles (both under the HarfangLab profile), a Bitdefender block's `yara.signature` as YARA under the Bitdefender profile, an Exabeam block's sequence filters in the Exabeam Query Language, and an Elastic query by the block's `type` and `language`. A hunt's search takes the language of its `system`.

### Diagnostics

Each diagnostic carries `range`, `severity` (error `1`, warning `2`, information `3`, hint `4`), `code`, `message`, `source: "opentide"` and `data: { field_path, suggestion }`. For a client that declares support for them, it also carries `codeDescription.href`, the code's section of [Diagnostic codes](./diagnostics.md) (`https://opentide.org/docs/cli/diagnostics/#<code>`, the page `opentide explain <code>` prints), the `Deprecated` tag on a deprecation code, the other file of a `duplicate_id` in `relatedInformation`, and the document `version` on a published set.

The server publishes diagnostics as documents change (`textDocument/publishDiagnostics`). A client that pulls (`textDocument.diagnostic` and `workspace.diagnostics.refreshSupport` in its capabilities) gets a `diagnosticProvider` instead: `textDocument/diagnostic` answers one document, `unchanged` when it is the same as the report its `previousResultId` names, and `workspace/diagnostic` every object file of every folder that no editor has open, with the findings that need the whole workspace (`duplicate_id`, `invalid_ref`). The workspace pull also reports each deployment state shard under `.opentide/states/deployment/` that `opentide validate` finds a problem with (`deployment_state_shape`, `deployment_state_uuid_mismatch`, `deployment_state_platform`), at the start of the shard, so it shows in the editor's problems list though no editor opens the shard with the server. A rule open in the editor also shows its own shard's finding, over its first line, as `opentide validate --file` on that rule does; a closed rule does not, as a full `opentide validate` run files it on the shard alone. A shard that is fixed or deleted gets an empty report, which clears what the client showed; with a file watcher, a shard written on disk (by `opentide deploy`, a branch switch) is checked again without checking every object. A document pull that arrives before the document's `didOpen` (a client that restarts replays its open documents, and the pulls can overtake the opens) is answered from the object file on disk, with the findings and the `resultId` the workspace pull gives it, and when the document is then opened the server asks the client to pull again (`workspace/diagnostic/refresh`, once), since the text it opens with may not be the file's. A pull the server cannot answer, for a file under no workspace folder or one the workspace holds no object of (yet), is refused with `ServerCancelled` and `data.retriggerRequest: true`, for the client to ask again, where an empty report is one a client keeps until the document changes. It is refused once for a document (until it is opened): a client asks again at once, with no delay, for as long as it is refused, so the second pull is answered, with nothing to report, and a `didOpen` that comes after has the client pull again. A client that only takes pushed diagnostics is shown them on an open rule only: no document of its own holds a shard. When something every document depends on changes (`visibility.toml`, a configuration file, an object another references), the server asks the client to pull again, and to refresh its semantic tokens, inlay hints and lenses.

### Code actions

`textDocument/codeAction` offers `quickfix` actions for the diagnostics in `context.diagnostics`, or, when the client sends none, for those on the requested lines. Each names its diagnostic and is preferred.

- **Apply a suggestion.** A diagnostic with a `suggestion` gets `Apply suggestion: <suggestion>`, an edit that replaces the diagnostic's range: the bad name in a query, the key in a Tide object. Which codes carry one is in the engine's [editor notes](https://github.com/opentidehq/opentide/blob/development/docs/engine/EDITORS.md).
- **Declare a dataset.** In a workspace folder, `kql_table_not_declared`, `kql_table_misspelt`, a `kql_unknown_table` that names `visibility.toml`, `spl_dataset_not_declared` and `elastic_dataset_not_declared` get `Add a [[logsources]] entry declaring '<name>' to visibility.toml`. The edit appends a log source (`name`, an empty `description` to fill in, and `system`) to `.opentide/configurations/visibility.toml` and never edits an existing one. When the file is missing, the edit creates it for a client that can create files (`workspaceEdit.documentChanges` and `resourceOperations: ["create"]`); other clients get no action then. See [The datasets a log source fills](../usage/configuration.md#the-datasets-a-log-source-fills).
- **Fix all.** `source.fixAll.opentide`, only when `context.only` asks for it (`source`, `source.fixAll`): every suggestion of the document as one edit. Editors run it on save when you enable fix-all for the source.

### Code lens

On an objective's or a threat's `metadata.uuid`, the lens reads `N rules use this objective`, counted by family, or `No object uses this objective`. Its command is `opentide.showReferences` with the arguments `[uri, position, locations]`. The server does not run it: an editor registers that command to show the locations (in VS Code, call `editor.action.showReferences` with the arguments converted to its types). An editor that does not register it shows the lens without an action.

### Server identity

`initialize` answers `serverInfo` `{ "name": "opentide-lsp", "version": <engine version> }`, `positionEncoding` `utf-16`, incremental document sync, and `capabilities.experimental.opentide`:

```json illustrative
{
  "host": { "name": "opentide", "version": "0.21.0" },
  "engine": "1.0.0",
  "catalog": "models",
  "configurationChecks": true,
  "configurationSchemas": true,
  "workspaceUpdates": true
}
```

| Key | Meaning |
|-----|---------|
| `host` | `opentide` and its version under `opentide lsp start`; `null` from the `opentide-lsp` binary on its own |
| `engine` | The language server's version, the engine compiled into opentide |
| `catalog` | Where the Tide catalog came from: `models` (generated by the server from the models it was built with, for each workspace folder's configuration), which `opentide lsp start` always reports. `host` means a host handed the server its own catalogs, as `opentide lsp start` did on Python before this release. Earlier servers also said `workspace` (`.opentide/lsp/catalogs/generated/`) or `bundled` (compiled into the engine) |
| `configurationChecks` | Whether configuration files are checked: always `true`, the checks are the server's own |
| `configurationSchemas` | Whether configuration files have hover and completion: always `true`, under `opentide lsp start` and from the `opentide-lsp` binary alike (`opentide-lsp --version --json` prints the same object) |
| `workspaceUpdates` | Whether the server takes `opentide/didChangeWorkspace`: always `true` |

A key is added in a minor release and never removed. An editor extension reads it to tell what it is talking to. The example above is not captured output: the versions are this release's.

### Requests beyond LSP

The server answers a few requests of its own, for editor extensions and tools that know them. Params and results are JSON; positions are UTF-16, as everywhere.

| Method | Params | Result |
|--------|--------|--------|
| `opentide/analyze` | `{ text, language?, uri? }` | `{ diagnostics }`: the engine's findings for a text that need not be open, each `{ code, message, severity, range, suggestion? }` with `severity` as a word (`error`, `warning`, …). `uri` places it in a workspace folder, for its `visibility.toml` |
| `opentide/highlight` | `{ text, language? }` | `{ language_id, legend, tokens }`: the highlight tokens, each with its `capture`, `range`, `span` (bytes) and `token_type` (an index into `legend`) |
| `opentide/compiledKql` | `{ query, tenant? }` | `{ compiled }`: the KQL Sentinel runs for the query |
| `opentide/compiledSpl` | `{ query }` | `{ compiled }`: the search Splunk runs, which is the search as written |
| `opentide/fs/read` | `{ path }` | `{ text }`: a workspace file as the server sees it, the open buffer first; empty when there is none. `path` is absolute, or relative to a workspace folder (each folder is tried in order; `./` parts are dropped) |
| `opentide/catalog` | `{ root? }`, or none | `{ roots: [{ root, objects }] }`: each workspace folder's indexed objects (`uuid`, `object_type`, `schema`, `name`, `uri`, `range`, and the `refs` each makes), open documents read as edited. `root`, a folder's URI, narrows it to that folder |

`language` takes the ids and aliases of [Languages](#languages). Without it, `opentide/analyze` reads the text as Tide YAML and `opentide/highlight` as KQL; a `language` that is none of them (`sql`) is `InvalidParams`, never "no diagnostics", and so is `opentide-config`: a configuration file is checked as the file the editor opens. A method the server does not know is `MethodNotFound` (`-32601`), and params that do not parse are `InvalidParams` (`-32602`).

Two notifications go with `opentide/catalog`: the client sends `opentide/didChangeWorkspace` (`{ documents?, objects?, removed?, visibility? }`) when the workspace it supplied on `initialize` changes, and the server sends `opentide/catalogChanged` (`{ root }`) when a folder's index changes after the client asked for its catalog. Their shapes are in the engine's [editor notes](https://github.com/opentidehq/opentide/blob/development/docs/engine/EDITORS.md#custom-rpcs).

`initialize` may also carry `initializationOptions.workspace`: `{ objects: [{ uuid, schema, name }], documents: [{ uri, text }], visibility }`. It is for clients without a filesystem to index, such as the engine in a browser worker; a document the editor opens replaces the one supplied with its UUID, and a folder's own files win over what is supplied.

### Configuration files

A TOML file under `.opentide/configurations/` (`deployment.toml`, `sharing.toml`, `platforms/sentinel.toml`, ...) is checked as you type with the same models and checks [`opentide validate`](./validate.md) runs (`configuration`, and `sharing-config` for `sharing.toml`). Each finding is on the key it names. A key the file lacks is reported on its table or `[[block]]` header.

- **Layers.** The file is a partial override: it is merged onto the bundled file and the parent instance's file before it is checked. A block that restates only `name` and what it changes is not reported for the keys it inherits.
- **Open buffers.** The statuses `sharing.toml` may name come from an open `deployment.toml`, saved or not. Editing one configuration file checks the others again.
- **`configurations/sharing/`** is reported as `sharing_directory` when it exists.
- **No model.** A file opentide has no model for (`resources.toml`) gets no findings.
- **Hover and completion** come from the JSON Schema of each file's model, which the server generates from the models and `opentide generate schemas` writes too. Hover shows a key's title, type, description, allowed values and default, never its value. Completion offers the keys a table may still take, table names in a header, and allowed values after `=`.
- **Highlighting** is your editor's TOML grammar: the server sends no semantic tokens for these files.

The `opentide-lsp` binary on its own checks configuration files the same way, with hover and completion.

### Configuring an editor

Run `opentide lsp start` as the server command, for YAML files under `objects/`, for query files (`.kql`, `.spl`, `.esql`, `.eql`, `.kuery`, `.lucene`, `.falco`, `.cql`, `.yar`, `.yara`, `.exabeam`, `.yaral`, `.yl2`), and for `.opentide/configurations/**/*.toml`. The completion triggers are `|`, space, `:`, `.`, `(`, `,`, `` ` `` and `=`; signature help opens on `(`, `,`, `=` and `` ` ``. The server reads a TOML file under `.opentide/configurations/` as language `opentide-config`, whatever id the editor sends, and no other `.toml`. Turn off other YAML language servers for `objects/**`, and other TOML language servers (Taplo, Even Better TOML) for `.opentide/configurations/**`: opentide reports those files' diagnostics itself.

Neovim (0.11 or later). Neovim knows few of the query file types, and reads `.cql` as Cassandra's `cqlang`, so name them first:

```lua
vim.filetype.add({
  extension = {
    kql = "kql", spl = "spl", esql = "esql", eql = "eql", kuery = "kuery", lucene = "lucene",
    falco = "falco", cql = "cql", yar = "yara", yara = "yara", exabeam = "exabeam",
    yaral = "yaral", yl2 = "yaral",
  },
  pattern = { [".*/%.opentide/configurations/.*%.toml"] = "opentide-config" },
})
vim.lsp.config("opentide", {
  cmd = { "opentide", "lsp", "start" },
  filetypes = { "yaml", "kql", "spl", "esql", "eql", "kuery", "lucene", "falco", "cql",
                "yara", "exabeam", "yaral", "opentide-config" },
  root_markers = { ".opentide" },
})
vim.lsp.enable("opentide")
```

The repository's [Neovim sample](https://github.com/opentidehq/opentide/tree/development/editors/nvim) also runs on Neovim 0.9 and 0.10.

Helix (`languages.toml`):

```toml
[language-server.opentide]
command = "opentide"
args = ["lsp", "start"]
```

Then add `opentide` to the `language-servers` of the languages you edit. Zed takes the same command; this repository has [samples for Helix, Neovim and Zed](https://github.com/opentidehq/opentide/tree/development/editors), which run `opentide-lsp`. In VS Code, install the opentide extension (`opentidehq.opentide`), which brings the language server.

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
| Exabeam New-Scale SIEM | the Exabeam Query Language (each sequence's filter, profile `rule`; `system: exabeam` hunts and `.exabeam` files, profile `search`) | ✅ |
| Google Security Operations | YARA-L 2.0 (the block's sections as the assembled rule; `system: google_secops` hunts as searches; `.yaral` and `.yl2` files) | ✅ |
| HarfangLab | YARA (`yara.signature`, and the rule the decomposed form assembles) | ✅ |

## opentide lsp start and opentide-lsp

The engine is also published on its own, as the `opentide-lsp` binary: each opentide [GitHub Release](https://github.com/opentidehq/opentide/releases) carries it for glibc Linux and macOS (`opentide-installer.sh` installs it with `opentide`), and crates.io has it (`cargo binstall opentide-lsp`, or `cargo install opentide-lsp`). No Windows binary ships: on Windows, install opentide with `uv tool install opentide` (or pip, pipx, npm) and point the editor at `opentide lsp start` ([Installation](../usage/installation.md#windows)). It has the version of the opentide release it ships with. `opentide lsp start` runs the same server, with what only opentide can add:

| | `opentide lsp start` | `opentide-lsp --stdio` |
|---|---|---|
| Tide catalog | Generated from this opentide's models and the workspace's configuration | Generated from the models the binary was built with and each workspace folder's configuration |
| Configuration files | Checked, with hover and completion | Checked, with hover and completion |
| `capabilities.experimental.opentide.host` | `opentide` and its version | `null` |

Use `opentide lsp start` when opentide is installed; the binary on its own suits an editor without Python. Its own command line (`--listen` for TCP, `--version --json`, `analyze`, `highlight`) is documented in [`crates/opentide-lsp`](https://github.com/opentidehq/opentide/tree/development/crates/opentide-lsp#command-line).

## Source

`crates/opentide-cli/src/commands/lsp.rs`, the server in `crates/opentide-lsp/`, and the engine in `crates/`.
