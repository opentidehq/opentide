# JSON-RPC wire format

Implementation: `crates/opentide-lsp/src/jsonrpc.rs`. Spec: LSP base protocol, `Content-Length` headers. <https://microsoft.github.io/language-server-protocol/specifications/lsp/3.17/specification/#headerPart>

## Framing

```
Content-Length: <utf-8 byte length>\r\n
\r\n
{json body}
```

`read_message` ignores headers other than `Content-Length`, then reads exactly that many bytes. The next frame starts after the body. `write_message` writes the header, `\r\n\r\n`, the body, and flushes. The length is the JSON byte length, not the character length, and not including the header.

A missing `Content-Length` is an error. A short read is an error. EOF before a header returns `Ok(None)` and the stdio loop exits.

## Messages

Request:

```json
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}
```

Notification (no `id`):

```json
{"jsonrpc":"2.0","method":"initialized","params":{}}
```

Success:

```json
{"jsonrpc":"2.0","id":1,"result":{}}
```

Failure:

```json
{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"method not found"}}
```

Use the helpers `success`, `failure`, and `notify`. Standard codes: `-32700` parse, `-32600` invalid request, `-32601` method not found, `-32602` invalid params, `-32603` internal. Do not invent a success payload on an unknown method; return an error with the request id so the client unblocks.

`Incoming.id` is `Option<serde_json::Value>` because ids may be numbers or strings. Echo the same JSON value back. Do not coerce it to `i64`.

## Sync

`textDocumentSync: 2` means incremental. `didChange` applies `contentChanges` in order. The host stores the full text after the change and re-analyzes. Do not switch the capability to full (`1`) without updating the client and the e2e test. Do not assume the client sends the whole document on every keystroke.

## Semantic tokens

`textDocument/semanticTokens/full` returns `{ "data": [u32, ...] }`. The encoder is delta-based:

- first token: `deltaLine` is the line, `deltaStartChar` is the character
- next token on the same line: `deltaLine` is 0, `deltaStartChar` is the difference of characters
- next token on a later line: `deltaLine` is the line difference, `deltaStartChar` is the absolute character (not a delta from the previous line)

Tokens are sorted by `(line, character)`. An unsorted slice produces a negative delta that `saturating_sub` turns into a huge token. Sort before encoding. Overlapping spans are removed in `query_captures` before this step.

## Hover and completion

Hover returns a `contents` value the e2e test already understands (markup or a string). Completion items use the engine's `CompletionItem` (`label`, `detail`, `kind`, `documentation`). Kinds are strings the server maps onto LSP completion kinds. Do not return the engine struct unchanged if the test expects LSP numeric kinds; follow the existing mapper in `server.rs`.

Trigger characters are part of the capability. Adding a trigger without handling it in completion is harmless. Removing `|`, `(`, or `` ` `` changes KQL and SPL completion and needs a test.

## Custom RPCs

`opentide/analyze` and `opentide/highlight` take the same logical input as the CLI and return the same JSON the CLI prints, inside a JSON-RPC result. Editors that cannot spawn the CLI use these. Do not make the CLI call itself over stdio to implement `analyze`.

`opentide/fs/read` is a host method. The engine never reads the path. Validate the path stays inside the workspace the client initialized. Do not widen it into an arbitrary file read.

`opentide/compiledKql` and `opentide/compiledSpl` return the compiled query the engine already produces. They are not a second compiler.
