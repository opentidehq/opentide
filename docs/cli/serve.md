---
title: opentide serve
description: Run CLI commands in one warm process, for editors, over newline-delimited JSON-RPC on stdio.
---

# opentide serve

`opentide serve` runs opentide commands in one long-lived process, for editors. Each command answers as `opentide --json <command>` would, without starting Python, importing the models and rebuilding the registry from every YAML file each time. The VS Code extension uses it for the commands it runs on every save and click (`validate --file`, `info`, `lint`, `explain`), and spawns `opentide` when the installed version has no `serve`.

```bash
opentide serve
```

The editor starts the process and owns it: it ends on `exit`, or when the editor closes stdin. Either cancels the running command, and no queued one runs. Like [`opentide mcp start`](../mcp/index.md) and [`opentide lsp start`](./lsp.md), it runs in the `mcp` [output mode](./json-output.md#output-modes): stdout carries the protocol and nothing else, logs go to stderr. Root options given to `serve` (`--repo`, `--data`, `--proxy`, `--debug`) are the defaults of every run.

## The protocol

JSON-RPC 2.0, one JSON message per line, on stdin and stdout, as MCP's stdio transport is.

| Message | Kind | Params | Result |
|---------|------|--------|--------|
| `initialize` | request | `{}` | `{protocol: 1, version, commands_digest}` |
| `run` | request | `{argv: string[], cwd?: string, env?: {name: string}}` | `{document: object, exit_code: number}` |
| `invalidate` | notification | `{paths: string[]}`, absolute | — |
| `progress` | notification, server to client | `{id: <run request id>, event: <progress event>}` | — |
| `$/cancelRequest` | notification | `{id}` | the cancelled `run` answers with exit code `130` |
| `shutdown` | request | — | `null` |
| `exit` | notification | — | the running `run` is cancelled, each queued one answers `130` without running, and the process exits `0` |

`version` is the opentide version. `commands_digest` is the sha256 of the document `opentide --json commands` prints, without `duration_ms`, with sorted keys and no spaces: a client that keeps a copy of the command tree reads it again only when the digest changes.

```json illustrative
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}
{"jsonrpc":"2.0","id":1,"result":{"protocol":1,"version":"<version>","commands_digest":"4fe0…"}}
{"jsonrpc":"2.0","id":2,"method":"run","params":{"argv":["validate","--file","objects/rules/lsass.yaml"],"cwd":"/work/detections"}}
{"jsonrpc":"2.0","method":"progress","params":{"id":2,"event":{"event":"progress","step":"objects","done":1,"total":1}}}
{"jsonrpc":"2.0","id":2,"result":{"document":{"ok":true,"command":"validate","exit_code":0,"…":"…"},"exit_code":0}}
```

## run

`argv` is what follows `opentide` on a command line, without `--json`: `["validate", "--file", "objects/rules/x.yaml"]`. Every run behaves as under `--json`, and `--repo` may appear in `argv`.

- **The document.** `document` is the JSON document `opentide --json <argv>` prints, the [envelope](./json-output.md#the-envelope) included, and `exit_code` the exit code that command would have had. Only timings (`duration_ms`, and a command's own such as `stats.wall_ms`) differ between the two. A command that prints text rather than a document (`--help`) answers `{ok, status, message, text, …}` with the text under `text`.
- **A failed command is a result.** A run that fails answers its document and its non-zero exit code, as the command would. JSON-RPC errors are only for protocol problems: a line that is not JSON (`-32700`), a message with no `method` (`-32600`), an unknown method (`-32601`), and a `run` without `argv` or with `cwd` or `env` of the wrong type (`-32602`).
- **Prompts.** A command that would prompt exits `2` with [`usage_needs_input`](./json-output.md#failure-codes), as under `--json`.
- **A crash.** An exception no command handles answers `failure.code` [`internal`](./diagnostics.md#internal), with `failure.crash_log` naming the redacted crash log, and the server keeps serving.
- **Stdin.** A run, and any process it starts, reads an empty stdin: the server reads the requests from its own copy of the stream. `query -` exits `2` (`usage_invalid_value`, no query given); pass the query in `argv` or with `--query-file`.
- **Not here.** `serve`, `mcp start` and `lsp start` would serve a protocol on stdin, and `tui` needs a terminal: a run of one exits `2` with `usage_error`.

### The workspace

Each run resolves its workspace from, in order:

1. `--repo` in `argv`;
2. `cwd`;
3. `OPENTIDE_REPO_ROOT` in `env`;
4. the server's own: its `--repo`, its `OPENTIDE_REPO_ROOT`, or its working directory.

So one server serves every folder of a multi-root window. A run starts from the environment the server started with, plus its `env`, and in its `cwd`; both are put back after it.

### Order, caching and invalidate

Requests are handled one at a time, in the order they arrive. `$/cancelRequest` is read while a run executes, and acts at once. `invalidate` is queued with the requests: it takes effect after the running command and before the next one.

The server keeps its imports and the command modules it has loaded. For the commands that only read the workspace (`validate`, `lint`, `info`, `explain` and `commands`, without `--fix`) it also keeps the registry it built, per workspace and environment, so a repeat `validate --file` does not parse every object file again. Any other command (`new`, `generate`, `deploy`, `setup`, a `--fix`) builds its own, and drops every registry kept, since it may have written any workspace.

Before reusing a kept registry, a run compares the object folders, `.opentide/schemas/`, `.opentide/templates/` and the configuration folders with what they held when it was built (each file's path, modification time and size): a file edited, created or deleted there since makes the run build it again, whether or not an `invalidate` has arrived. `invalidate` is for what that check does not see, such as a file a configuration points at elsewhere: after the client edits, creates or deletes a file, it sends `invalidate` with the file's absolute path, and the next run reads the workspace again. A path inside a workspace, its `.opentide/` or the bundled data drops what was kept for that workspace; a path inside no workspace drops everything.

At 500 rules on 4 CPUs, a repeat `validate --file` answers in about 0.3 s, against 1.6 s for `opentide --json validate --file` started afresh. The first run in a workspace, and the first after an `invalidate`, builds the registry, about 1 s.

### The Rust engine

Every run runs inside the server, on the Rust core ([the implementation](./json-output.md#the-implementation)), with the run's environment and working directory, and answers with the document it prints, as `opentide --json <argv>` would.

A read-only Rust run keeps its workspace loaded for the next one, per workspace and environment. Each run brings it up to date first: the object and configuration folders are listed again and compared with what they held when they were last read (each file's path, modification time and size), and only the files edited, created or deleted since are read again; a configuration change resolves the configuration again. `invalidate` reaches it as it reaches the registry: the next run takes the paths into account, and a path inside no workspace loads the workspace again. A command that may write drops every kept workspace. The Rust run's progress events arrive as `progress` notifications when it answers, not while it runs.

### The Rust host

The server is Rust: the protocol, the order, cancel and the signals are as described here, and so is every answer. Where it differs from opentide 0.28.1's Python host: a message that Python's `json` reads but JSON does not allow (`NaN`, a lone surrogate, nesting deeper than 128 levels) is a parse error; request ids are compared as written (`1.0` is not `1`); and a SIGTERM or SIGHUP the server was started ignoring stops it. `opentide serve` runs the host in its own process, so a SIGTERM sent to it reaches the host.

### Cancel

`$/cancelRequest {id}` stops the run *id* as Ctrl-C would: a Rust run is interrupted and answers `130` with a document whose `failure.code` is `interrupted`; for a Python run `KeyboardInterrupt` is raised in the thread that runs it, so its cleanup runs (a CrowdStrike search is stopped), and it answers `exit_code` `130` with a document whose `failure.code` is [`interrupted`](./diagnostics.md#interrupted). A run blocked in one call (waiting on a tenant's answer) stops when that call returns. A cancel for a queued run answers it with `130` without running it; a cancel for a run that has answered, or for an id no request carries, changes nothing, also for a later request that reuses the id.

SIGTERM and SIGHUP stop the server as the end of input does: the running command is cancelled, its cleanup runs (a `setup --plan` removes its copy of the repository), it answers `130`, queued runs answer `130` unrun, and the server exits `128` plus the signal's number (`143` for SIGTERM). A second signal ends it at once. A signal the server was started ignoring stays ignored.

### Progress

The [progress events](./json-output.md#progress-events) a run emits arrive as `progress` notifications carrying the run's request `id`, whether or not `OPENTIDE_PROGRESS` is set, and never on stderr.

## Related

- [JSON output](./json-output.md)
- [opentide lsp](./lsp.md)
- [MCP server](../mcp/index.md)
