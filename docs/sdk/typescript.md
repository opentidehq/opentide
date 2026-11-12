---
title: TypeScript SDK
description: The @opentide/opentide npm package — the opentide SDK and command line for Node.js: open a Tide workspace, validate and lint it, read its catalogue and coverage, plan a deploy, and run the CLI with npx.
---

# TypeScript SDK

`@opentide/opentide` is opentide for Node.js. As on PyPI, one package is both the SDK and the `opentide` command line, and both run the same Rust core in Node's own process: the [Rust SDK](./rust.md)'s `opentide` crate, bound with [napi-rs](https://napi.rs). Its TypeScript declarations ship with it.

## Install

The packages are not on npm yet; they are built and tested from this repository until the release that publishes them. Once they are published:

```bash
npm install @opentide/opentide
```

npm installs the one native package your machine needs (`@opentide/opentide-<platform>`, an optional dependency) beside it: Linux x64 and arm64 (glibc; there is no musl build, so not Alpine), macOS x64 and arm64, and Windows x64 and arm64, on Node.js 18 or later.

Until then, build it from a checkout. It needs the Rust release `rust-toolchain.toml` names and a C compiler (for the query engines' grammars):

```bash
cd bindings/node
npm ci
npm run build
```

## The command line with npx

The package's `opentide` command is the opentide command line in Rust, the program the PyPI console script runs for every command ported to it: the same commands, flags, `--json` documents and exit codes. `npx @opentide/opentide --json commands` prints the same command tree as `opentide --json commands` from PyPI. Two things still differ from the PyPI CLI, which answers them in Python: `--help` prints the Rust command line's help, and `opentide doctor` reports its Python environment checks as not checked.

```bash
npx @opentide/opentide --json validate
npx @opentide/opentide info coverage --technique T1059
npx @opentide/opentide deploy --dry-run --all --strategy PREVIEW
```

The plain `opentide` package is an alias that depends on `@opentide/opentide`, so `npx opentide` runs the same command. The command runs in Node's process, not in a child: Ctrl-C stops the run, which exits 130.

## Open a workspace

`Workspace.open` takes the repository's folder (the one with `.opentide/` and `objects/`). `Workspace.fromFiles` opens one held in memory, for an editor's buffers or a test: each key is a path relative to the root, each value the file's text.

```js
const { Workspace } = require('@opentide/opentide')

const ws = Workspace.fromFiles('/ws', {
  'objects/rules/example.yaml':
    'name: Example\nmetadata:\n  uuid: 11111111-1111-4111-8111-111111111111\n  schema: rule::1.1\n',
})
console.log(ws.info().counts.rules) // 1
const validation = ws.validate({ queries: 'off' })
for (const finding of [...validation.report.issues, ...validation.report.warnings]) {
  console.log(`${finding.code}: ${finding.message}`)
}
```

Opening reads every object file once into one index; each method then reads the index, so keep the `Workspace` and call as many methods on it as you need. Every method runs synchronously.

## Validate and lint

`validate` runs every check of `opentide validate` and returns `checks`, `report` and `summary` as `validate --json` writes them, with `failed` and `exitCode`. Each finding has its code, severity, file, 1-based line and column, field path, suggestion and fix. The options are the command's flags: `check`, `files`, `uuids`, `types`, `strict` and `queries` (`'error'`, `'warn'` or `'off'`).

```js
const { Workspace } = require('@opentide/opentide')

const ws = Workspace.open('.')
const validation = ws.validate({ types: ['rule'], strict: true })
for (const finding of validation.report.issues) {
  console.log(`${finding.path}:${finding.line}: ${finding.message}`)
}
console.log(validation.summary.objects, 'objects checked')

const lint = ws.lint({ checks: ['filenames', 'metadata'] })
console.log(lint.status, lint.findings.length)
process.exitCode = validation.exitCode
```

`lint` runs `opentide lint` without `--fix`: its `findings` and `summary` are those of `lint --json`.

## Read the catalogue and coverage

`info`, `catalog` and `coverage` return the data of `opentide info`, `info catalog` and `info coverage`, with the command line's keys in its order.

```js
const { Workspace } = require('@opentide/opentide')

const ws = Workspace.open('.')
const info = ws.info()
console.log(`${info.counts.rules} rules, ${info.load_errors} load errors`)
const catalogue = ws.catalog()
console.log(catalogue.objects.length, 'objects,', catalogue.edges.length, 'edges')
const coverage = ws.coverage('T1059')
console.log(`${coverage.count} rules cover ${coverage.technique}`)
```

## Plan a deploy

`deployPlan` is `opentide deploy --dry-run`: the rules a strategy selects, the tenants each reaches and the request bodies a real run would send. Nothing is sent and nothing is written. `document` is the `result` of `deploy --dry-run --json`.

```js
const { Workspace } = require('@opentide/opentide')

const ws = Workspace.open('.')
const plan = ws.deployPlan({ strategies: ['PREVIEW'] })
console.log(plan.ok, plan.document.strategies, Object.keys(plan.document.plan))
```

## Run a command

`runJson(argv)` runs one command in the process and returns its `--json` document, parsed, with the command line's keys in its order: the envelope (`ok`, `command`, `result`, `failure`, ...) or, for `commands`, the command tree. A command that fails still returns its document, with `ok: false` and `failure.code`. `main(argv)` is the whole program, on the process's streams; it returns the exit code.

```js
const { runJson } = require('@opentide/opentide')

const info = runJson(['--repo', '.', 'info'])
console.log(info.ok, info.counts.rules)
const tree = runJson(['commands'])
console.log(tree.program, tree.version)
```

## Errors

A call that cannot run throws an `Error` whose `code` is a stable code: `configuration_invalid` or the configuration check's own code (`config_parse`, ...), `io_error`, `usage_invalid_choice` for an option the command line would refuse, `no_json_document` when `runJson`'s command writes no document (`--version`). Match on the code, not the message. Findings about the workspace are not errors: they are in the report.

```js
const { runJson } = require('@opentide/opentide')

try {
  runJson(['--version'])
} catch (error) {
  console.log(error.code) // no_json_document
}
```

## Types

The declarations (`index.d.ts`) are generated from the Rust binding by napi-rs and checked in; CI fails when a build changes them, and type-checks a sample consumer with `tsc --noEmit`. The options are typed, with the choices the command line accepts. The documents (`report`, `catalog()`, `document`) are typed `any` for now: their types, generated from the Rust structs, come with a later release.

## Stability

The package's version is opentide's. The SDK follows the [Rust SDK](./rust.md#stability)'s promise: the documents follow the command line's JSON contract ([JSON output](../cli/json-output.md)), which only grows.
