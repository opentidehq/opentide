---
name: lsp-host
description: Implement the OpenTide stdio language server. Covers Content-Length JSON-RPC, UTF-16 positions, semantic tokens, and the opentide/* custom RPCs. The CLI never speaks JSON-RPC. Use when editing crates/opentide-lsp, editors/, or LSP tests. Do not introduce tower-lsp.
license: EUPL-1.2
metadata:
  author: OpenTideHQ
---

# LSP host

`opentide-lsp` is a blocking stdio (and optional TCP) server. The protocol code is `crates/opentide-lsp/src/jsonrpc.rs` and `server.rs`. It is not `tower-lsp`, not `lsp-server`, and not an `lsp-types` typed loop. `lsp-types` 0.97.0 is declared on the crate and is not imported. Leave it that way unless a change needs a canonical LSP struct **and** the JSON it produces matches the existing `serde_json::json!` shape. Adding `tower-lsp` replaces the loop the e2e tests speak and is out of scope.

Read `references/wire-format.md` before adding a method.

## Two protocols, one binary

| Invocation | Bytes on stdout |
| --- | --- |
| `--stdio` | LSP `Content-Length` frames |
| `--listen 127.0.0.1:2087` | the same frames, after one TCP accept |
| `analyze <file>` | pretty JSON array of diagnostics |
| `highlight <file>` | pretty JSON highlight result, or HTML with `--html` |
| `generate-highlights` | writes `highlights/generated/`; `--check` exits non-zero on drift |

`main` handles `--stdio` and `--listen` before the clap subcommand. A subcommand must not call `jsonrpc::write_message`. The CLI never speaks JSON-RPC.

## Session

`Session` maps URI → (`LanguageId`, text). `language_for` uses a reported language id when `LanguageId::parse` accepts it, otherwise the URI suffix (`.kql`, `.spl`, else Tide YAML). An unknown reported id is ignored. `.sql` is Tide YAML and is not validated as SQL.

The analysis crate sees a `MemoryWorkspace` built from open documents plus YAML files under the workspace `objects/` directory. The engine still does not call `std::fs`. The host does.

`initialize` reads `rootUri` and installs the Tide deprecation overlay from `.opentide/lsp/catalogs/generated/deprecations.json` when that file exists. Capabilities are the JSON object in the `initialize` arm. When you add a provider, advertise it there and handle the method in the same change. An unhandled request that still has an `id` hits the `_` arm and returns `-32601`, so the client unblocks with a failure instead of waiting.

Current providers: incremental sync (`textDocumentSync: 2`), hover, completion (resolve, trigger characters), signature help, definition, references, document symbol, workspace symbol, document highlight, code action, folding, selection range, inlay hints, pull diagnostics, semantic tokens (full).

Custom methods:

- `opentide/analyze`
- `opentide/highlight`
- `opentide/compiledKql`
- `opentide/compiledSpl`
- `opentide/fs/read`

`shutdown` returns a null result. `exit` stops the loop. Notifications (`initialized`, `didOpen`, `didChange`, `didClose`) have no `id` and get no response. Requests always get `id` plus `result` or `error`.

## Positions

LSP positions are zero-based line and UTF-16 `character`. `opentide_core::offset_to_position` is the UTF-8 byte → position conversion for every range that leaves the process (`range_json`). Do not send byte offsets as `character`.

Inbound conversion is not the same function. `apply_content_changes` walks `contentChanges` in order and splices with `offset_at`, which treats `character` as a byte index into the line. Completion uses `position_to_offset`, which counts Unicode scalars. See `skills/rust-engine/SKILL.md`. New protocol code calls one of those helpers instead of slicing the source with `position.character`.

Semantic tokens are the LSP integer array `[deltaLine, deltaStartChar, length, tokenType, tokenModifiers]` from `encode_lsp_semantic_tokens`. A token cannot cross a newline; `length` is the UTF-16 length on the start line. Split multiline comments and strings before encoding. `tokenModifiers` is 0.

The legend advertised at `initialize` is `opentide_highlight::LSP_TOKEN_TYPES` (the standard VS Code token types: `keyword`, `function`, `operator`, …). It is **not** `HighlightSpec.legend`. Captures such as `operator.pipe` and `tide.keyword` are mapped onto those standard types in `lsp_token_type_index`, because default themes do not style OpenTide capture names. Do not replace `tokenTypes` with the HighlightSpec legend. TextMate / Monaco / Helix scopes still come from `highlights/spec.toml`.

## Diagnostics

`textDocument/publishDiagnostics` uses `source: "opentide"`, the stable `code`, and a numeric severity (error 1, warning 2, information 3, hint 4). Tide object checks match the Pydantic issue's `{code, field_path, severity}` and add a range. Extra query diagnostics inside an injected `query: |` block are allowed. Do not drop a code to make a fixture quiet; fix the document or the engine.

CrowdStrike paths produce `crowdstrike_unsupported` or no fake success. Do not parse Falcon FQL here.

## Editors in this repo

`editors/helix/languages.toml`, `editors/nvim/opentide.lua`, `editors/zed/opentide.json`. VS Code is `OpenTideHQ/vscode-extension`, a different repository. Samples disable yamlls on `objects/**`. Semantic tokens come from this server. TextMate grammars are generated (`generate-highlights`), never hand-authored in an editor repo.

Language ids in editors: `opentide-yaml`, `kql`, `spl`. Not `sql`. Not `otide`.

## Tests

`crates/opentide-lsp/tests/e2e_stdio.rs` spawns `CARGO_BIN_EXE_opentide-lsp --stdio` and writes real frames. A new method gets a frame in that test: `initialize`, `initialized`, the request, then assert the response `id` and payload. Run:

```bash
cargo test -p opentide-lsp --test e2e_stdio
```

Stderr is the server log. Stdout is protocol only. Do not `println!` from the server. Use `eprintln!` for listen-address and generator logs.
