---
name: lsp-host
description: Implement the opentide stdio language server. Covers the lsp-server/lsp-types host (batches, lifecycle, capabilities), UTF-16 positions, semantic tokens, and the opentide/* custom RPCs. The CLI never speaks JSON-RPC. Use when editing crates/opentide-lsp, editors/, or LSP tests. Do not introduce tower-lsp.
license: EUPL-1.2
metadata:
  author: opentidehq
---

# LSP host

`opentide-lsp` is a synchronous stdio (and optional TCP) server on `lsp-server` 0.10 (framing) and `lsp-types` 0.97 (typed messages) — the rust-analyzer stack, without an async runtime, so wasip1 and the PyO3 thread run it unchanged (#90, #185). It is not `tower-lsp` or `async-lsp`; do not add either.

| File | Holds |
| --- | --- |
| `src/protocol.rs` | frames (`lsp_server::Message::read`/`write`), the lifecycle, batches, cancellation, `ContentModified`, panic isolation, the two sources |
| `src/session.rs` | open documents, workspace roots and their disk objects, client capabilities, the analysis cache, coalesced publishing, the outgoing request queue (`ReqQueue`), logs |
| `src/handlers.rs` | one typed function per method, the `Dispatcher`, `ServerCapabilities`, the `opentide/*` request types |
| `src/server.rs` | the public entry points, catalogs, host info, the workspace walk |
| `src/uri.rs` | `file:` URI ↔ path through the `url` crate |

Read `references/wire-format.md` before adding a method.

## Two protocols, one binary

The server is also a library: `opentide_lsp::run_stdio_status()` is what the `opentide` Python package calls for `opentide lsp start`. Keep it free of process-wide side effects beyond stdin, stdout, the catalog install and the host info, and never print to stdout outside the protocol.

| Invocation | Bytes on stdout |
| --- | --- |
| `--stdio` | LSP `Content-Length` frames |
| `--listen 127.0.0.1:2087` | the same frames, after one TCP accept |
| `--version [--json]` | the version, or `host_info()` as JSON |
| `analyze <file>` | pretty JSON array of diagnostics |
| `highlight <file>` | pretty JSON highlight result, or HTML with `--html` |
| `generate-highlights` | writes `highlights/generated/`; `--check` exits non-zero on drift |

`main` handles `--version`, `--stdio` and `--listen` before the clap subcommand. A subcommand never writes a frame.

## The loop

`protocol::run` takes batches from a `Source`: every message the client sent that the server has not handled yet. `Threaded` (stdio and `--listen` on native targets) reads on its own thread, so what arrives while a request runs is the next batch. `Direct` (`serve`, and stdio on wasip1, which has no threads) reads on the caller's thread and batches the frames already buffered. In a batch:

- notifications apply in order; `$/cancelRequest` answers its queued request `RequestCanceled` (-32800);
- a semantic tokens, code action, inlay hint, pulled diagnostic, code lens or document link request for a document a later `didChange` in the batch edits gets `ContentModified` (-32801);
- diagnostics are published once, after the batch, for each document it changed (`Session::mark`, `mark_open`, `mark_all`), so twenty queued keystrokes cost one analysis and one publish.

The lifecycle is enforced before a handler sees a message: before `initialize` a request gets `-32002` and a notification is dropped; after `shutdown` a request gets `-32600` and nothing is published (what was pending is published before the `shutdown` reply); a second `initialize` gets `-32600`; `exit` or the end of input ends the loop, and the status says whether `shutdown` came first (the binary exits 0 or 1).

A body `lsp-server` cannot parse is answered from the bytes it read (`Recording`): not JSON `-32700`, a batch or another non-message `-32600`, with the id it names or `id: null`; `"id": null` is `-32600` with `id: null`. A response with an id the server never sent is logged. A broken header ends the session. Each message runs under `catch_unwind`: a panicking request gets `-32603`. Debug builds add `opentide/__panic`, `opentide/__sleep` (`{ ms }`, so tests can queue a batch) and `opentide/__stats` (`{ analyses }`).

## Dispatch and capabilities

`handlers::request` chains `Dispatcher::on::<R>` for each `lsp_types::request::Request`; params that do not deserialize are `-32602`, an unknown method `-32601`. Notifications go through the same pattern and an invalid one is logged. A custom method is a `Request` impl in `handlers::custom`. Never read params with `Value::pointer`.

`initialize` reads the client's capabilities once into `ClientCaps` and builds `ServerCapabilities` from them. When you add a provider, advertise it there and route the method in the same change. What is gated on the client:

| Client capability | Effect |
| --- | --- |
| `textDocument.diagnostic` + `workspace.diagnostics.refreshSupport` | pull only (`diagnosticProvider`, with `workspaceDiagnostics`), `workspace/diagnostic/refresh` instead of publishing; otherwise push only. Never both: VS Code would show each diagnostic twice |
| `hover.contentFormat`, `completionItem.documentationFormat` without Markdown | plain text |
| `workspaceEdit.documentChanges` + `resourceOperations: ["create"]` | the quick fix that creates `visibility.toml`; left out otherwise |
| `publishDiagnostics.codeDescriptionSupport` / `tagSupport` / `relatedInformation` / `versionSupport` | `codeDescription.href` (`DIAGNOSTICS_DOCS#<code>`), `Deprecated` on deprecation codes, the other file of a `duplicate_id`, the document version |
| `workspace.{semanticTokens,inlayHint,codeLens}.refreshSupport` | a refresh request after a change beyond one document |
| `didChangeWatchedFiles.dynamicRegistration` | watchers for `objects/` and everything in it (`**/objects`, `**/objects/**`: a client reports a deleted folder as one event for the folder, which re-reads the root's objects), `.opentide/configurations/**/*.toml` and the generated catalogs; an analysis is then cached across batches |
| `workspace.workspaceFolders` | `workspace.workspaceFolders` with change notifications |

`positionEncoding` is always `utf-16`. `capabilities.experimental.opentide` is `host_info()` (#172): `{ host, engine, catalog, configurationChecks, configurationSchemas, workspaceUpdates }`, the same as `--version --json` (`workspaceUpdates`: the server takes `opentide/didChangeWorkspace`); a key is added in a minor release and never removed.

Providers: incremental sync, hover, completion (resolve, trigger characters; a space opens no list in Tide YAML), signature help, definition, references, document symbol (a tree for Tide: object, sections, platform blocks, queries), workspace symbol, document highlight, code action (`quickfix`, `source.fixAll.opentide`), folding, selection range, inlay hints (label parts that lead to the object), document links (ATT&CK ids, object UUIDs), code lens (`opentide.showReferences` with `[uri, position, locations]`), pull and workspace diagnostics, semantic tokens (full).

Custom methods: `opentide/analyze`, `opentide/highlight`, `opentide/compiledKql`, `opentide/compiledSpl`, `opentide/fs/read`, the notification `opentide/didChangeWorkspace` (a host with no filesystem updates what it supplied on `initialize`: `Supplied::apply`, then `Session::supplied_changed`; a supplied file is its root's, `Session::owning_root`), `opentide/catalog` (#198; the notification `opentide/catalogChanged` goes out from `Session::flush_publishes` when a root's catalog digest changes, once the client asked for that root). An index entry's references are found once in `index_object`; a handler reads `IndexedObject::refs`, never walks bodies.

## Session

Documents are keyed by the URI the client sent, with their language, text, version and root. `language_for` returns `opentide-config` for a TOML file under `.opentide/configurations/` whatever id the client reports, and `None` (not read, nothing published) for any other `.toml`. Otherwise it uses a reported language id when `LanguageId::parse` accepts it (never `opentide-config`), else the URI suffix (`.kql`, `.spl`, `.esql`, `.eql`, `.kuery`, `.lucene`, `.falco`, else Tide YAML); YAML is Tide only under `objects/`, with an `opentide-yaml` id, or when it names a Tide schema. A `didChange` whose version is not newer than the document's is ignored.

Roots are the workspace folders (`workspaceFolders`, else `rootUri`, else `rootPath`), plus the `.opentide/`/`objects/` ancestor (`server::workspace_root`, shared with `analyze`) of a document opened outside every folder. A document belongs to the deepest root holding it, else the first. Each root has its own disk objects, index, `visibility.toml` and catalogs; the engine's catalog and dataset layers are process-wide, so `Session::activate` installs the root's before a request reads them (once, with one root). The engine never calls `std::fs`; the host does.

`Session::analysis(uri)` is the one place that analyses an open document: cached per document state and workspace generation (bumped by any edit, file change, `visibility.toml` or root change), and shared by publish, pull, semantic tokens, code actions, symbols, lenses and links. Without a file watcher the cache lives for one batch, and each batch reads the disk again.

A host that supplies its own catalogs calls `opentide_analysis::set_default_catalog` and `opentide_lsp::use_host_catalogs()`; `opentide lsp start` does both, and `set_host_info("opentide", <version>)`. Configuration diagnostics come from the host's checker (`opentide_analysis::set_configuration_checker`, #158): with none installed, an `opentide-config` document gets none. `.opentide/configurations/platforms/elastic.toml` reaches the analysis through the host: its tenants' `setup.version` decides the Elastic stack.

Logs go to the client as `window/logMessage` once it is initialized (catalog and `visibility.toml` loads and failures, a failed server request), and a broken file on disk is shown once per session (`window/showMessage`). Frame errors and panics are stderr traces.

## Positions

LSP positions are zero-based line and UTF-16 `character`. Ranges leave the process through `opentide_core::span_to_range` / `LineIndex`; never send byte offsets as `character`. An inbound position becomes a byte offset once, in `handlers::offset` (over `opentide_core::position_to_offset`, which always returns a char boundary), before an engine sees it; the engines take byte offsets only.

Semantic tokens are `[deltaLine, deltaStartChar, length, tokenType, tokenModifiers]` from `encode_lsp_semantic_tokens`, sent as `lsp_types::SemanticToken`. The legend is `opentide_highlight::LSP_TOKEN_TYPES` (the standard VS Code token types), **not** `HighlightSpec.legend`. TextMate / Monaco / Helix scopes still come from `highlights/spec.toml`.

## Diagnostics

Diagnostics carry `source: "opentide"`, the stable `code`, an LSP severity, and `data: { field_path, suggestion }`, which a code action reads back from `context.diagnostics`. Tide object checks match the Pydantic issue's `{code, field_path, severity}` and add a range. Do not drop a code to make a fixture quiet; fix the document or the engine. `DIAGNOSTICS_DOCS` is where every code has a section (opentide's `docs/cli/diagnostics.md`).

CrowdStrike paths produce `crowdstrike_unsupported` or no fake success. Do not parse Falcon FQL here.

## Editors in this repo

`editors/helix/languages.toml`, `editors/nvim/opentide.lua`, `editors/zed/opentide.json`. VS Code is a separate repository. Samples disable yamlls on `objects/**`. Semantic tokens come from this server. TextMate grammars are generated (`generate-highlights`), never hand-authored in an editor repo.

Language ids in editors: `opentide-yaml`, `kql`, `spl`, `esql`, `eql`, `kuery`, `lucene`, `falco`, `opentide-config` (`.opentide/configurations/**/*.toml`, the editor's TOML grammar, generic TOML servers off). Not `sql`. Not `otide`.

## Tests

`tests/common/mod.rs` is the one test client: it spawns `CARGO_BIN_EXE_opentide-lsp --stdio`, writes real frames, gives each `didChange` a version, and skips `window/logMessage` in `read` (`read_any` keeps it). `tests/e2e_stdio.rs` covers the features, `tests/protocol.rs` the host (capabilities, batches, cancellation, cache, refresh, roots, watchers, code actions, logs), `tests/host_configuration.rs` an in-process `serve` with a host checker. A new method gets a test there: `initialize`, `initialized`, the request, then assert the response `id` and payload. The Windows CI job runs this crate's tests; the informational `clients` job drives real clients: `scripts/engine/clients` (pytest-lsp with the capabilities VS Code, Neovim and Emacs record) and `scripts/engine/nvim-smoke.lua` (Neovim's own client, one diagnostic each).

```bash
cargo test -p opentide-lsp
```

Stderr is the server log. Stdout is protocol only. Do not `println!` from the server.
