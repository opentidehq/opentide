# Editor hosts

The opentide LSP owns Tide diagnostics. Disable yamlls / Red Hat YAML on `objects/**`.

Languages: `opentide-yaml`, `kql`, `spl`, `esql`, `eql`, `kuery` (Kibana KQL), `lucene` (never `sql`).

Semantic tokens come from the server. TextMate grammars must be **copied from the language-server highlight zip**, never hand-authored.

## Helix

See `editors/helix/languages.toml`.

## Neovim

See `editors/nvim/opentide.lua`.

## Zed

See `editors/zed/opentide.json`.

## VS Code

Lives in **opentidehq/vscode-extension** (other repository, #17). MIT client, EUPL engine notices.

Language ids are the server's: `opentide-yaml`, `kql`, `spl`, `esql`, `eql`, `kuery`, `lucene`. Use `DOCUMENT_SELECTOR` from `@opentide/lsp-client`, which matches each language by id and by file pattern.

`esql` is also the id of Elastic's own ES|QL extension. The ids are the shared vocabulary, so the opentide extension registers `esql` too, never a second id for the same language. Its TextMate grammar uses the scope `source.opentide.esql`, not Elastic's `source.esql`, so the two grammars never collide. The server's semantic tokens are authoritative for colour either way. The other three Elastic ids (`eql`, `kuery`, `lucene`) have no prior VS Code owner.

## Structure providers

`initialize` advertises these providers. The behavior below is
`crates/opentide-lsp/src/server.rs`.

| Method | Behavior |
| --- | --- |
| `textDocument/documentSymbol` | Tide YAML with a `name`: one symbol, the name string, kind Class (`5`), `detail` = `metadata.uuid`, range = the first `name:` key. Raw query files have none. |
| `workspace/symbol` | Indexed Tide objects whose name, UUID, or schema family (`rule`, `objective`, `threat`) contains the query, ignoring case. Kind Class (`5`), `containerName` = the family. Range is the first occurrence of the name in the file's open text, or `0:0`–`0:1` when the file is not open. |
| `textDocument/documentHighlight` | Every occurrence of the UUID under the cursor in that file (kind Text, `1`). Empty when the cursor is not on a UUID. |
| `textDocument/inlayHint` | Tide YAML only. After each UUID that matches an indexed object, label `{family} {name}` (kind Type, `1`). The document's own `metadata.uuid` is skipped. Only hints on the requested lines are returned. |
| `textDocument/foldingRange` | For each line followed by more-indented lines, one `region` from that line to the last of them. Only spaces count as indent, and blank lines are skipped. A region from the first line to the last line is omitted. |
| `textDocument/selectionRange` | Inner range is the whole cursor line. Parent runs from the nearest earlier less-indented line through the last more-indented line after it. |
| `textDocument/codeAction` | `quickfix` actions for diagnostics on the requested lines, of two kinds (below). |
| `textDocument/diagnostic` | Pull diagnostics (`interFileDependencies: true`, `workspaceDiagnostics: false`). Items carry `range`, `severity`, `code`, `message` and `source: "opentide"`. Severity map: error 1, warning 2, information 3, hint 4. |

Code actions:

- **Apply a suggestion.** A diagnostic with a `suggestion` gets `Apply suggestion: {suggestion}`. The edit replaces the diagnostic's range with the suggestion string.
- **Declare a dataset.** When the server has a workspace root, `kql_table_not_declared`, the `kql_unknown_table` warning, `spl_dataset_not_declared` and `elastic_dataset_not_declared` get `Declare '{name}' in log source "{log source}" (visibility.toml)`. The edit adds the name to `.opentide/configurations/visibility.toml`, and creates the file when it is missing. The server reads that file live: [kql/columns.md](kql/columns.md).

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
| `invalid_ref` on `detection_model` | the `detection_model` key | UUID of the first indexed objective, when one exists |
| `schema_validation` (string where a list is required) | the field key | `- {text}` |
| `filename_slug` | the first `name:` key | `{slug}.yaml` |

On Tide keys the range is the key, so applying the edit overwrites the key
text. On query tokens the range is the bad name, so the edit replaces that
name. The Elastic engines attach suggestions too ([LANGUAGE.md](LANGUAGE.md)).

## TypeScript client

`@opentide/lsp-client` reaches the engine three ways. Each answers `highlight()`, `legend()` and, where the transport has an analyzer, `analyze()`. A transport that cannot answer rejects; it never returns an empty result in place of one.

| Transport | Runs | `analyze` |
| --- | --- | --- |
| `stdio` | `opentide-lsp --stdio` (`command`, default `opentide-lsp` on `PATH`), started once, over JSON-RPC | yes |
| `worker` | the `opentide-wasm` module you pass as `module` | no: the browser module only highlights |
| `wasi` | the `wasm32-wasip1` CLI you pass as `wasi`, under `node:wasi`, once per call | yes |

```ts
import { createOpentideClient } from "@opentide/lsp-client";

const client = createOpentideClient({ transport: "stdio" });
const { diagnostics } = await client.analyze("kql", "SecurityEvent | take 1");
await client.dispose();
```

For Monaco, load the module inside your Web Worker with `@opentide/lsp-worker`, then hand it to the client:

```ts
import { loadHighlightModule } from "@opentide/lsp-worker";

const module = await loadHighlightModule("/opentide/opentide_wasm.js"); // wasm-bindgen --target web
const client = createOpentideClient({ transport: "worker", module });
```
