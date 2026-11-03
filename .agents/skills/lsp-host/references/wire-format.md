# Wire format

Framing is `lsp-server` 0.10 (`Message::read` / `Message::write`, `crates/opentide-lsp/src/protocol.rs`); message types are `lsp-types` 0.97. Spec: LSP 3.17 base protocol. <https://microsoft.github.io/language-server-protocol/specifications/lsp/3.17/specification/#headerPart>

## Framing

```
Content-Length: <utf-8 byte length>\r\n
\r\n
{json body}
```

Header names match in any case; headers other than `Content-Length` are ignored; lines end in `\r\n`. A broken header ends the session; a body that is not a message is answered (`-32700`/`-32600`) and reading goes on. EOF before a header ends the loop.

## Messages

`lsp_server::Message` is a `Request` (`id` an integer or a string), a `Response` or a `Notification`; `jsonrpc` is optional on input and always written. Build replies with `Response::new_ok` / `Response::new_err` and `ErrorCode`: `-32700` parse, `-32600` invalid request, `-32601` method not found, `-32602` invalid params, `-32603` internal, `-32002` not initialized, `-32800` cancelled, `-32801` content modified. Do not invent a success payload on an unknown method; the dispatcher answers `-32601` with the request id.

A handler is a typed function `fn(&mut Session, R::Params) -> R::Result` routed with `Dispatcher::on::<R>`. A server-to-client request goes through `Session::send_request::<R>` (ids from `ReqQueue`), a notification through `Session::notify::<N>`; both are written after the message that queued them, before its reply.

## Sync

`textDocumentSync` is incremental (`2`). `didChange` applies `contentChanges` in order, and carries a version: one not newer than the document's is ignored. The host stores the full text after the change and re-analyzes. Do not switch the capability to full (`1`) without updating the clients and the tests.

## Semantic tokens

`textDocument/semanticTokens/full` returns `{ "data": [u32, ...] }`. The encoder is delta-based:

- first token: `deltaLine` is the line, `deltaStartChar` is the character
- next token on the same line: `deltaLine` is 0, `deltaStartChar` is the difference of characters
- next token on a later line: `deltaLine` is the line difference, `deltaStartChar` is the absolute character (not a delta from the previous line)

Tokens are sorted by `(line, character)`. An unsorted slice produces a negative delta that `saturating_sub` turns into a huge token. Sort before encoding. Overlapping spans are removed in `query_captures` before this step.

## Hover and completion

Hover is `MarkupContent`, Markdown unless the client renders only plain text. Completion items map the engine's `CompletionItem` (`label`, `detail`, `kind`, `documentation`) onto `lsp_types::CompletionItem`; kinds are strings mapped in `completion_kind`. An item carries `data: { language, schema?, field_path? }`: `completionItem/resolve` documents a Tide value from that field and keeps the item's `textEdit` and `filterText`.

Trigger characters are part of the capability. A space never opens a list in Tide YAML. Removing `|`, `(`, or `` ` `` changes KQL and SPL completion and needs a test.

## Custom RPCs

`opentide/analyze` and `opentide/highlight` take the same logical input as the CLI and return the same JSON the CLI prints, inside a JSON-RPC result. Editors that cannot spawn the CLI use these. Do not make the CLI call itself over stdio to implement `analyze`.

`opentide/fs/read` returns a file as the server sees it: an open buffer, an object file the index read, or a root's Elastic configuration. It never reads another path.

`opentide/compiledKql` and `opentide/compiledSpl` return the compiled query the engine already produces. They are not a second compiler.
