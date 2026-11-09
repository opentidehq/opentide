---
title: "Editor hosts"
description: "How an editor hosts the opentide language server: language ids, the TypeScript client, TextMate grammars, settings and the custom requests."
---

# Editor hosts

The opentide LSP owns Tide diagnostics. Disable yamlls / Red Hat YAML on `objects/**`.

Languages: `opentide-yaml`, `kql`, `spl`, `esql`, `eql`, `kuery` (Kibana KQL), `lucene`, `falco`, `cql` (CrowdStrike Query Language) and `opentide-config`. There is no `sql`.

Semantic tokens come from the server. TextMate grammars must be **copied from the language-server highlight zip**, never hand-authored.

The Tide grammar (`tide.tmLanguage.json`, `source.opentide-yaml`) marks the queries whose path fixes their language as embedded regions of that language's grammar (#171): `configurations.sentinel.query` and `configurations.defender_for_endpoint.query` are `meta.embedded.block.kql`, `configurations.splunk.query` (and the legacy `search`) `meta.embedded.block.spl`, `configurations.carbon_black_cloud.query` `meta.embedded.block.lucene`, `configurations.sysdig.condition` `meta.embedded.block.falco`, and `configurations.crowdstrike.query` `meta.embedded.block.cql`, for a block scalar (`query: |`) or a value on the key's line. Comment toggling and bracket matching inside them follow the query language. Elastic queries get no region: their language follows the block's `type` and `language`, which a grammar cannot read, so semantic tokens colour them. An editor that maps regions to languages copies `generated/package-contributions.json` from the zip: its `embeddedLanguages` maps each region to the language id.

## Configuration TOML

`.opentide/configurations/**/*.toml` is `opentide-config`, whatever language id the editor sends. Any other `.toml` (`Cargo.toml`, `pyproject.toml`) is not read.

- **opentide checks it.** The findings are opentide's own (`configuration_text_issues`, the check `opentide validate` runs), placed on the keys they name. Only `opentide lsp start` has them. `opentide-lsp` on its own has no checker, so it reports nothing for these files and never guesses. Hover and completion come from the schemas `opentide lsp start` hands the server, so they need it too. See [ARCHITECTURE.md](ARCHITECTURE.md#configuration-toml).
- **The editor's TOML grammar highlights it.** The server sends no semantic tokens for `opentide-config`, and there is no opentide TOML grammar.
- **Keep generic TOML language servers off `.opentide/configurations/**`** (taplo, Even Better TOML, tombi), so a file is not reported twice. Give the glob its own language (`opentide-config`), as the samples do.
- Editing one configuration file re-checks the others that are open: a status added to `deployment.toml` is one `sharing.toml` may name. `visibility.toml` still declares datasets live, and is checked like the other files.

## Helix

See `editors/helix/languages.toml`.

## Neovim

See `editors/nvim/opentide.lua`.

## Zed

See `editors/zed/opentide.json`.

## VS Code

Lives in **opentidehq/vscode-extension** (other repository, #17). MIT client, EUPL engine notices.

Language ids are the server's: `opentide-yaml`, `kql`, `spl`, `esql`, `eql`, `kuery`, `lucene`, `falco`, `cql`, `opentide-config`. Use `DOCUMENT_SELECTOR` from `@opentide/lsp-client`, which matches each language by id and by file pattern (`opentide-config` is `**/.opentide/configurations/**/*.toml`). Its patterns match `file:` URIs only. On vscode.dev and github.dev, where documents are `vscode-vfs:` and other virtual URIs, use `WEB_DOCUMENT_SELECTOR`: the same filters with no scheme ([#197](https://github.com/opentidehq/language-server/issues/197)).

Both are plain arrays, so they are vscode-languageclient's `documentSelector` as they are:

```ts
import { DOCUMENT_SELECTOR, WEB_DOCUMENT_SELECTOR } from "@opentide/lsp-client";
import * as vscode from "vscode";
import type { LanguageClientOptions } from "vscode-languageclient";

const clientOptions: LanguageClientOptions = {
  documentSelector: vscode.env.uiKind === vscode.UIKind.Web ? WEB_DOCUMENT_SELECTOR : DOCUMENT_SELECTOR,
};
```

`esql` is also the id of Elastic's own ES|QL extension. The ids are the shared vocabulary, so the opentide extension registers `esql` too, never a second id for the same language. Its TextMate grammar uses the scope `source.opentide.esql`, not Elastic's `source.esql`, so the two grammars never collide. The server's semantic tokens are authoritative for colour either way. The other three Elastic ids (`eql`, `kuery`, `lucene`) have no prior VS Code owner.

`cql` is the CrowdStrike Query Language, not Cassandra's CQL, which uses the same `.cql` extension (and, in some VS Code extensions, the `cql` id). The samples here map `.cql` to opentide's `cql`, as each other language's extension is mapped. In a workspace that holds Cassandra scripts, match opentide's `cql` by language id alone (leave out the `**/*.cql` pattern) or by a narrower glob.

TextMate scopes ([#195](https://github.com/opentidehq/language-server/issues/195)): `highlights/generated/esql.tmLanguage.json` is `source.opentide.esql`. VS Code keeps one grammar per scope, so a second `source.esql` would replace Elastic's grammar or be replaced by it. `highlights/generated/cql.tmLanguage.json` is `source.opentide.cql` for the same reason: Cassandra CQL extensions already contribute `source.cql`, so CrowdStrike's CQL starts in the opentide namespace. The other grammars keep `source.<id>` (`source.kql`, `source.spl`, `source.eql`, `source.kuery`, `source.lucene`, `source.falco`) and Tide objects `source.opentide-yaml`. No published extension we know of contributes those scopes. Renaming them would break every editor that already includes them, for no collision. A grammar moves to `source.opentide.<id>` when one is found to collide, as ES|QL did, in the same change as its CHANGELOG entry. The scope is not a HighlightSpec capture: renaming it leaves `highlights/spec.toml` at its version, and every capture keeps its TextMate scope. `opentide_highlight::tm_scope_name` gives each grammar's scope.

## Structure providers

`initialize` advertises these providers. The behavior below is
`crates/opentide-lsp/src/handlers.rs`; which parts a client gets follows its
capabilities ([.agents/skills/lsp-host](../../.agents/skills/lsp-host/SKILL.md#dispatch-and-capabilities)).

| Method | Behavior |
| --- | --- |
| `textDocument/documentSymbol` | Tide YAML: a tree. The object (kind Class, `5`, named by `name`, `detail` = `metadata.uuid`) holds each top-level section (Namespace, `3`); `configurations` holds each platform block (Object, `19`), and a platform block or `response` holds each query (String, `15`, `detail` = its language). Raw query files list the engine's symbols. |
| `workspace/symbol` | Indexed Tide objects of every root whose name, UUID, or schema family (`rule`, `objective`, `threat`) contains the query, ignoring case. Kind Class (`5`), `containerName` = the family. Range is the first occurrence of the name in the file. |
| `textDocument/documentHighlight` | Every occurrence of the UUID under the cursor in that file (kind Text, `1`). Empty when the cursor is not on a UUID. |
| `textDocument/inlayHint` | Tide YAML only. After each UUID that matches an indexed object, a label part `{family} {name}` (kind Type, `1`) whose `location` is the object's UUID in its file: Ctrl-click opens it. The document's own `metadata.uuid` is skipped. Only hints on the requested lines are returned. |
| `textDocument/documentLink` | Tide YAML only. Each ATT&CK technique (`T1059`, `T1059.001`) or tactic (`TA0002`) id links to its attack.mitre.org page; each UUID of another indexed object links to that object's file. |
| `textDocument/codeLens` | Tide YAML only. On the object's `metadata.uuid`: `N rules use this objective` (counted by family, from the index), or `No object uses this objective` for an objective or threat nothing references. The command is `opentide.showReferences` with `[uri, position, locations]`; a client registers that command to show the locations (VS Code: `editor.action.showReferences` after converting the arguments). |
| `textDocument/foldingRange` | For each line followed by more-indented lines, one `region` from that line to the last of them. Only spaces count as indent, and blank lines are skipped. A region from the first line to the last line is omitted. |
| `textDocument/selectionRange` | Inner range is the whole cursor line. Parent runs from the nearest earlier less-indented line through the last more-indented line after it. |
| `textDocument/codeAction` | `quickfix` actions (below) for the diagnostics the client sends in `context.diagnostics`, read back from their `data`, or for those on the requested lines when it sends none; each names its diagnostic and is `isPreferred`. `source.fixAll.opentide`, only when `context.only` asks for it (`source`, `source.fixAll`): every suggestion of the document as one edit. |
| `textDocument/diagnostic` | Pull diagnostics (`interFileDependencies: true`, `workspaceDiagnostics: true`), for a client that pulls; a report repeated with its `previousResultId` is `unchanged`. |
| `workspace/diagnostic` | Every object file of every root that no editor has open, with its `duplicate_id`, `invalid_ref` and the rest. |

Diagnostics carry `range`, `severity` (error 1, warning 2, information 3,
hint 4), `code`, `message`, `source: "opentide"` and `data: { field_path,
suggestion }`, pushed or pulled. A client that reads them also gets
`codeDescription.href` (`https://opentide.org/docs/cli/diagnostics/#<code>`),
the `Deprecated` tag on deprecation codes, the other file of a `duplicate_id`
in `relatedInformation`, and the document `version` on a published set.

`capabilities.experimental.opentide` says who runs the server: `{ host:
{ name, version } | null, engine, catalog: "host" | "workspace" | "bundled",
configurationChecks, configurationSchemas, workspaceUpdates }`.
`workspaceUpdates` is `true` when the server takes `opentide/didChangeWorkspace`
(the release after 0.10.0 on); a client of an older server restarts it to give it a new
workspace. `opentide lsp start` sets the
host to `opentide`; the binary alone has none. `opentide-lsp --version --json`
prints the same object without starting a session, so an extension can check
a binary before it uses it. The object is stable for clients: a key is added in
a minor release and never removed.

Code actions:

- **Apply a suggestion.** A diagnostic with a `suggestion` gets `Apply suggestion: {suggestion}`. The edit replaces the diagnostic's range with the suggestion string.
- **Declare a dataset.** When the document has a workspace root, `kql_table_not_declared`, a `kql_unknown_table` whose message names `visibility.toml` (the Sentinel warning, and the Defender error once the workspace declares Defender tables), `spl_dataset_not_declared` and `elastic_dataset_not_declared` get `Add a [[logsources]] entry declaring '{name}' to visibility.toml`. The edit appends a new log source (`name` = the table, sourcetype or index pattern, an empty `description` to fill in, and `system`) to the root's `.opentide/configurations/visibility.toml`, never edits an existing one, and creates the file when it is missing, for a client that can create files (`workspaceEdit.documentChanges` and `resourceOperations: ["create"]`); other clients get no action while the file is missing. The server reads that file live: [kql/columns.md](kql/columns.md).

Suggestions the KQL, SPL and Tide engines attach:

| Code | Range | Suggestion |
| --- | --- | --- |
| `kql_unknown_operator` | the operator | closest catalog operator, edit distance ≤ 3 |
| `kql_unknown_function` (scalar) | the function name | closest non-deprecated catalog function, distance 1–2. No diagnostic when nothing is that close |
| `kql_unknown_function` (evaluate plugin) | the plugin name | closest catalog plugin, distance ≤ 2 |
| `kql_deprecated_function`, `kql_deprecated_operator` | the function name, the operator | the replacement the catalog names |
| `kql_unknown_table` | the table reference | closest catalog table, distance ≤ 4, ignoring case. Only names that start with an ASCII uppercase letter are reported |
| `kql_table_not_declared` | the table reference | closest declared table, distance ≤ 2; otherwise, for a table the catalog lacks, the closest catalog table |
| `kql_unknown_column` | the column | closest column of the source, distance ≤ 2 and less than half the name's length ([kql/columns.md](kql/columns.md)) |
| `spl_unknown_command` | the command | closest catalog command within three edits, an adjacent swap counting half |
| `spl_search_operator` | the operator | `=`, `!=`, `>=` or `<=` ([spl/search-syntax.md](spl/search-syntax.md)) |
| `spl_command_without_pipe` | the command word | `\| {command}` |
| `spl_unknown_datamodel`, `spl_unknown_datamodel_field` | the data model reference | the corrected name ([spl/cim-fields.md](spl/cim-fields.md)) |
| `invalid_ref` on `detection_model` | the UUID value | the objective or signal UUID within two edits of the value, ignoring case (a mistyped or swapped character); none when nothing is that close, so an unrelated objective is never offered |
| `schema_validation` (string where a list is required) | the field key | `- {text}` |
| `filename_slug` | the `name` value | `{stem}.yaml` (`{stem}.debug.yaml` for a debug file), the stem `[filenames] style` derives from the name (`slug` or `name`, [OBJECTS.md](OBJECTS.md)), a file name: the quick fix renames the file (`RenameFile`, for a client with `workspaceEdit.documentChanges` and `resourceOperations: ["rename"]`) beside it, only for a `file:` document and when no other file, open document or supplied document has that name (the same file under another case is renamed), and is never a text edit nor part of `source.fixAll.opentide` |

A reference finding (`invalid_ref` on `detection_model`, on each
`objective.threats` entry and on a `threat.chaining` `vector`) is on the UUID
value, so applying its edit replaces the value and the YAML stays valid
([#215](https://github.com/opentidehq/language-server/issues/215)); a value
the text does not spell out after its key (an alias, whose UUID is at its anchor) keeps the key's range. On other Tide
keys the range is the key, so applying the edit overwrites the key text. On query tokens the range is the bad name, so the edit replaces that
name. The Elastic engines attach suggestions too ([LANGUAGE.md](LANGUAGE.md)).

## Custom RPCs

Requests beyond LSP, for clients that know them (`crates/opentide-lsp/src/handlers.rs`, `mod custom`). Params and results are JSON objects, and positions are UTF-16, as everywhere. Params that do not deserialize are `InvalidParams` (-32602); a method the server does not know is `MethodNotFound` (-32601). `language` takes a language id or one of its aliases (`kusto` for `kql`, `kibana-kql` for `kuery`, `yaml` and `tide` for `opentide-yaml`, `opentide-<id>` for each), as `LanguageId::parse` reads them.

| Method | Params | Result |
| --- | --- | --- |
| `opentide/analyze` | `{ text, language?, uri? }` | `{ diagnostics }`, in the engine's own shape: `{ code, message, severity, range, suggestion? }`, `severity` a word (`error`, `warning`, `information`, `hint`). The text need not be open. Without `language` it is Tide YAML. `uri` picks the root whose workspace (`visibility.toml`, the index) the analysis reads; without it the text is analysed as `memory`, outside every root |
| `opentide/highlight` | `{ text, language? }` | `{ language_id, legend, tokens }`: each token's `capture` (a HighlightSpec capture), `range`, `span` (bytes) and `token_type` (an index into `legend`). Without `language` it is KQL |
| `opentide/compiledKql` | `{ query, tenant? }` | `{ compiled }`: the KQL Sentinel runs for the query on `tenant` (`opentide_kql::compile_kql_query`, with no exclusions) |
| `opentide/compiledSpl` | `{ query }` | `{ compiled }`: the search Splunk runs, the authored text (an implicit leading `\| search` is not a rewrite) |
| `opentide/fs/read` | `{ path }` | `{ text }`: the file as the server sees it, the open buffer first, else the file on disk; `""` when there is neither |
| `opentide/didChangeWorkspace` (notification) | `{ documents?, objects?, removed?, visibility? }` | None. The workspace a host supplied on `initialize` changed (below): `documents` and `objects` as on `initialize`, added or replacing what has their URI; `removed`, the URIs of files that are gone (`opentide-object:<uuid>` for an object supplied with no `uri`); `visibility`, the new text of `visibility.toml`, or `null` when it is gone (absent: unchanged). The index is rebuilt, open documents are checked again (or the client asked to pull), and a catalog the client got that changed gets `opentide/catalogChanged`. Params that are not an object are logged and ignored |

Debug builds also answer `opentide/__panic`, `opentide/__sleep` and `opentide/__stats`, for the server's own tests. Release builds do not have them.

### `opentide/catalog`

The workspace index, for catalogue, graph and search views that follow unsaved edits, on the web too ([#198](https://github.com/opentidehq/language-server/issues/198)). Params `{ root? }`: a root's URI, as the catalog reports it, or every root without it (params `{}`, `null` or none). A root on disk is its `file:` URI; a workspace folder of another scheme (`vscode-vfs://github/org/repo` on vscode.dev and github.dev) is the folder's own URI, as are its objects'. A `root` the server does not have gives `{ roots: [] }`.

```jsonc
{
  "roots": [{
    "root": "file:///w",                 // null when there is no root: the documents outside every root
    "objects": [{
      "uuid": "00000000-0000-4000-8003-000000000001",
      "object_type": "rule",             // the schema family
      "schema": "rule::1.0",             // metadata.schema as written
      "name": "Sentinel KQL Rule",
      "uri": "file:///w/objects/rules/rule.yaml",
      "range": { "start": { "line": 0, "character": 6 }, "end": { "line": 0, "character": 23 } },
      "refs": [{
        "uuid": "00000000-0000-4000-8002-000000000001",
        "field_path": "detection_model",  // keys and list indexes joined with "."
        "range": { "start": { "line": 16, "character": 17 }, "end": { "line": 16, "character": 53 } }
      }]
    }]
  }]
}
```

- **Objects** are the ones the other requests see: each object file of the root, an open document in place of its file, and the objects a host supplied on `initialize` (`initializationOptions.workspace`; one known by its metadata alone has the `uri` the host gave, else `opentide-object:<uuid>`, and no refs). They are sorted by path, then UUID.
- **`range`** is the `name` value's (the key's when the value is not on its line; the file's start without a `name`). Positions are UTF-16, as everywhere.
- **`refs`** are the values the reference fields of the body hold, other than the object's own `metadata.uuid` and empty ones, in document order: a rule's `detection_model`, an objective's `objective.threats.<i>` and `objective.signals.<i>.parent`, and a threat's `threat.chaining.<i>.vector`. A signal's own UUID is listed too (`objective.signals.0.uuid`): signals live inside their objective and are not objects here, so this is where a client finds them, and a rule's `detection_model` naming a signal is a ref to one of those. Other UUID-valued fields identify something that is not an object and are not refs: `metadata.organisation.uuid`, a platform's ids (`configurations.sentinel.template.uuid`). Any other ref whose `uuid` no object of the root carries dangles (the object's diagnostics say `invalid_ref` where the check applies). A value that is not a UUID (a typo, `TODO`) is such a ref too, with that value as its `uuid`, as `invalid_ref` reports it. Ranges are those of the indexed text: the open buffer, else the file.
- The references are kept in the index, found once per text; `textDocument/references` and the reference lens read them too.

### `opentide/catalogChanged`

A notification, `{ root }` (the same `root` as above), sent at the end of a batch, once the client has asked for a catalog:

- for a root whose catalog the client got and whose index changed: an object file created, saved with other contents, or deleted, or a folder of objects under `objects/` deleted, created or moved (reported by the client's file watcher, which reports a deleted folder as one event for the folder; without one, the server notices on the next request that reads the workspace), or an open object's UUID, name, schema or references edited. An edit that changes only ranges or prose sends none;
- for a root the client got that is gone: a workspace folder removed (`workspace/didChangeWorkspaceFolders`), or `root: null` once the documents outside every root have a root;
- for a root that appeared, once the client has asked for every root (`{}`): a folder added, or the `.opentide/` or `objects/` ancestor of a document opened outside every folder. That root is followed from then on.

The client asks for `opentide/catalog` again.

## TypeScript client

`@opentide/lsp-client` reaches the engine three ways. Each answers `highlight()`, `legend()` and, where the transport has an analyzer, `analyze()`. A transport that cannot answer rejects; it never returns an empty result in place of one.

| Transport | Runs | `analyze` |
| --- | --- | --- |
| `stdio` | `opentide-lsp --stdio` (`command`, default `opentide-lsp` on `PATH`), started once, over JSON-RPC | yes |
| `worker` | the language server in a Web Worker you pass as `worker` (`serveLanguageServer` from `@opentide/lsp-worker`), over JSON-RPC; or, given a `module` instead, `highlight()` in this thread | yes with `worker`; no with `module` |
| `wasi` | the `wasm32-wasip1` CLI you pass as `wasi`, under `node:wasi`, once per call | yes |

```ts
import { createOpentideClient } from "@opentide/lsp-client";

const client = createOpentideClient({ transport: "stdio" });
const { diagnostics } = await client.analyze("kql", "SecurityEvent | take 1");
await client.dispose();
```

In a browser, run the language server itself in a Web Worker. `serveLanguageServer` answers one JSON-RPC message per `postMessage`, the messages any LSP client sends without `Content-Length` headers, so `@codemirror/lsp-client` talks to it through a `Transport` that posts and receives them, and `createOpentideClient` through its `worker` option:

```ts
// worker.ts
import * as glue from "./opentide_wasm.js"; // wasm-bindgen --target web
import { loadLanguageServer, serveLanguageServer } from "@opentide/lsp-worker";

serveLanguageServer(self, loadLanguageServer(glue, new URL("./opentide_wasm_bg.wasm", import.meta.url)));

// the page
const worker = new Worker(new URL("./worker.ts", import.meta.url), { type: "module" });
const client = createOpentideClient({ transport: "worker", worker });
const { diagnostics } = await client.analyze("kql", "SecurityEvent | take 1");
```

The browser has no filesystem to index, so pass the workspace on `initialize`: `workspace: { objects: [{ uuid, schema, name }], documents: [{ uri, text }], visibility }` (`initializationOptions.workspace` for any other client). Without it, a rule's `detection_model` is an `invalid_ref`. A document the client opens is that object, not a second one with its UUID, and a root's own files win over what is supplied. A supplied document under a workspace folder belongs to that folder's root alone, as a file on disk would, so a reference from one folder to another's object is an `invalid_ref`, as the CLI reports it; an object supplied with no `uri`, or one outside every folder, is every root's. A root's `.opentide/configurations/visibility.toml` among the documents declares that root's datasets; `visibility` declares them for a root that has none. A root's `.opentide/configurations/lint.toml` among the documents sets its filename and metadata checks ([OBJECTS.md](OBJECTS.md#linttoml)). When those files change, send `opentide/didChangeWorkspace` with what changed ([Custom RPCs](#custom-rpcs)), `client.updateWorkspace(change)` with `createOpentideClient`: the server has no file watcher to read, since it has no files.

To highlight in the same thread instead, load the module with `loadHighlightModule` and hand it over as `module`:

```ts
import { loadHighlightModule } from "@opentide/lsp-worker";

const module = await loadHighlightModule("/opentide/opentide_wasm.js"); // wasm-bindgen --target web
const client = createOpentideClient({ transport: "worker", module });
```
