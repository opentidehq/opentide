---
title: TypeScript SDK
description: The @opentide/opentide npm package — the opentide SDK and command line for Node.js: open a Tide workspace, validate and lint it, read its catalogue and coverage, plan a deploy, query, check and deploy on its tenants with promises, and run the CLI with npx.
---

# TypeScript SDK

`@opentide/opentide` is opentide for Node.js. As on PyPI, one package is both the SDK and the `opentide` command line, and both run the same Rust core in Node's own process: the [Rust SDK](./rust.md)'s `opentide` crate, bound with [napi-rs](https://napi.rs). Its TypeScript declarations ship with it.

## Install

The packages are not on npm yet; they are built and tested from this repository until the release that publishes them. Once they are published:

```bash
npm install @opentide/opentide
```

npm installs the one native package your machine needs (`@opentide/opentide-<platform>`, an optional dependency) beside it: Linux x64 and arm64 (glibc; there is no musl build, so not Alpine), macOS x64 and arm64, and Windows x64 and arm64, on Node.js 18 or later.

On any other platform the install succeeds, but loading the package fails with the loader's error naming the native package it looked for: there is no WebAssembly fallback, which could not reach your tenants.

Until then, build it from a checkout. It needs the Rust release `rust-toolchain.toml` names and a C compiler (for the query engines' grammars):

```bash
cd bindings/node
npm ci
npm run build
```

## The command line with npx

The package's `opentide` command is opentide's command line, the program the PyPI console script runs: the same commands, flags, `--json` documents and exit codes. `npx @opentide/opentide --json commands` prints the same command tree as `opentide --json commands` from PyPI. It cannot load [platform plugins](./platforms.md#platform-plugins), which are Python packages.

```bash
npx @opentide/opentide --json validate
npx @opentide/opentide info coverage --technique T1059
npx @opentide/opentide deploy --dry-run --all --strategy PREVIEW
```

The plain `opentide` package is an alias that depends on `@opentide/opentide`, so `npx opentide` runs the same command. The command runs in Node's process, not in a child: Ctrl-C stops the run, which exits 130.

## Open a workspace

`Workspace.open` takes the repository's folder (the one with `.opentide/` and `objects/`) and returns a promise of the workspace: it reads and indexes the files off Node's event loop. `Workspace.fromFiles` opens one held in memory, synchronously, for an editor's buffers or a test: each key is a path relative to the root, each value the file's text.

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

Opening reads every object file once into one index; each method then reads the index, so keep the `Workspace` and call as many methods on it as you need. Its methods that read the index (`validate`, `lint`, `info`, `catalog`, `rules`, `coverage`, `tenants`) run synchronously; `deployPlan`, which compiles every rule it selects, returns a promise, as do `Workspace.open`, `runJson` and `main`, which run off Node's event loop. The operations on a tenant, which wait on the network, return promises too: see [Tenant operations](#tenant-operations).

## Validate and lint

`validate` runs every check of `opentide validate` and returns `checks`, `report` and `summary` as `validate --json` writes them, with `failed` and `exitCode`. Each finding has its code, severity, file, 1-based line and column, field path, suggestion and fix. The options are the command's flags: `check`, `files`, `uuids`, `types`, `strict` and `queries` (`'error'`, `'warn'` or `'off'`).

```js
const { Workspace } = require('@opentide/opentide')

async function main() {
  const ws = await Workspace.open('.')
  const validation = ws.validate({ types: ['rule'], strict: true })
  for (const finding of validation.report.issues) {
    console.log(`${finding.path}:${finding.line}: ${finding.message}`)
  }
  console.log(validation.summary.objects, 'objects checked')

  const lint = ws.lint({ checks: ['filenames', 'metadata'] })
  console.log(lint.status, lint.findings.length)
  process.exitCode = validation.exitCode
}

main()
```

`lint` runs `opentide lint` without `--fix`: its `findings` and `summary` are those of `lint --json`.

## Read the catalogue and coverage

`info`, `catalog` and `coverage` return the data of `opentide info`, `info catalog` and `info coverage`, with the command line's keys in its order. `rules`, `objectives` and `threats` return each family's rows of the catalogue, in index order, as the Python SDK's methods of the same names do.

```js
const { Workspace } = require('@opentide/opentide')

Workspace.open('.').then((ws) => {
  const info = ws.info()
  console.log(`${info.counts.rules} rules, ${info.load_errors} load errors`)
  const catalogue = ws.catalog()
  console.log(catalogue.objects.length, 'objects,', catalogue.edges.length, 'edges')
  const coverage = ws.coverage('T1059')
  console.log(`${coverage.count} rules cover ${coverage.technique}`)
  for (const rule of ws.rules()) console.log(rule.uuid, rule.name)
  console.log(ws.objectives().length, 'objectives,', ws.threats().length, 'threats')
})
```

## Plan a deploy

`deployPlan` is `opentide deploy --dry-run`: the rules a strategy selects, the tenants each reaches and the request bodies a real run would send. Nothing is sent and nothing is written. It returns a promise of `{ document, summary, ok }`; `document` is the `result` of `deploy --dry-run --json`. `environment` is where the tenants' `$NAME` credentials are looked up to say which are unset, and a HarfangLab tenant's `type` is read (a plan fails a tenant whose `type` the deploy could not read), as `Connection.open` takes one, and `ws.info(environment)` reports each variable as set or not in it; without one, the process's.

```js
const { Workspace } = require('@opentide/opentide')

async function main() {
  const ws = await Workspace.open('.')
  const plan = await ws.deployPlan({ strategies: ['PREVIEW'] })
  console.log(plan.ok, plan.document.strategies, Object.keys(plan.document.plan))
}

main()
```

## Tenant operations

A `Connection` is one tenant's client: it runs a query (`opentide query`), checks a query live (`opentide validate query --live`) and deploys one compiled rule, through the same platform connectors as the command line and the [Python SDK](./workspace.md#tenant-operations). `ws.tenants(platform)` returns the tenants the workspace configures, in file order, each a `TenantConfig`:

```toml
# .opentide/configurations/platforms/sentinel_one.toml
[[tenants]]
name = "soc"
[tenants.setup]
url = "$S1_URL"
api_token = "$S1_API_TOKEN"
account_id = 42
```

`Connection.open(tenant, options)` resolves the tenant's `$NAME` credentials (an unset one throws `credential_unset`, naming the variable) and builds its client from that tenant's own settings: TLS, CA bundle, proxy, timeout. It sends nothing. TLS roots are the system's store, which the process's `SSL_CERT_FILE` and `SSL_CERT_DIR` replace (read once per process, whatever `environment` says), plus the CA bundles `environment` names (`SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`). The options are `environment`, which replaces the process's environment for the credentials (Google SecOps's Application Default Credentials too: `GOOGLE_APPLICATION_CREDENTIALS`, gcloud's well-known file (`CLOUDSDK_CONFIG`, else under `HOME`), `GCE_METADATA_HOST`; an `environment` that names none of them leaves Google SecOps the metadata server), CA bundles and proxies, `proxy`, used before the environment's, and `timeout`, how long in seconds the tenant may take to answer a read in a query or a live check (a deploy waits as long as `opentide deploy` does). `capabilities` says what the platform's connector can do. A tenant can also be configured in code: `new TenantConfig('sentinel_one', 'soc', { url, api_token: '$S1_API_TOKEN' })`; `setupKeys` names its keys, never their values.

`query`, `validateQuery` and `deploy` return promises. Each operation runs on the Rust core's own threads (a tokio runtime the first operation starts) and settles back on Node's thread, so the event loop keeps running and one connection serves many operations at once:

```js
const { Connection, Workspace } = require('@opentide/opentide')

async function hunt() {
  const ws = await Workspace.open('.')
  const tenant = ws.tenants('sentinel_one')[0]
  console.log(tenant.name) // soc
  const connection = Connection.open(tenant)
  console.log(connection.capabilities.liveValidation) // true
  const [check, found] = await Promise.all([
    connection.validateQuery("EventType = 'Process Creation'"),
    connection.query("EventType = 'Process Creation'", { limit: 10 }),
  ])
  console.log(check.errors, found.columns, found.truncated)
  return found.rows
}

hunt().then((rows) => console.log(rows.length)) // 2
```

`query(text, options)` searches the 24 hours before now unless given `start` and `end` (each a `Date` or an RFC 3339 instant such as `'2026-11-12T09:00:00Z'`; an invalid `Date` rejects with `usage_invalid_value`), resolves to at most `limit` rows (100 by default) as a `QueryResult` (`columns`, `rows`, `truncated`, `partial`, `warnings`, `vendorQueryId`, `sent`, `language`) and saves nothing on the tenant. Each row is an object of its columns in the order they came. `language` is the query's (`kql`, `esql`, `s1ql`; unset takes the platform's first), `index` the Elastic indices, the HarfangLab telemetry source or the CrowdStrike repository, `dataView` Elastic's, and `timeout` how long, in seconds, an asynchronous search may run. `validateQuery` takes the same options and searches for one row over the minute before now; it resolves to a `LiveCheck` (`result`, `errors`, `warnings`) for a query the tenant accepts, whose `errors` are why validation still fails it (Defender's required columns).

`deploy(ruleId, operation, body)` creates, updates, disables or deletes one rule on the tenant, sending `body` (a `Buffer`, `Uint8Array` or string: the request `opentide deploy` compiles for this tenant) as its bytes, and resolves to a `DeployOutcome` with the platform's identifier of the rule (`remoteId`) and the deploy's `warnings`. `ruleId` is the rule's identifier on the platform, which a deploy keeps in its deployment state; a deletion takes no body (`deploy(ruleId, 'delete')`), and the other operations reject with `usage_invalid_value` without one (`null` or nothing; an empty body is sent as it is). Sysdig adds a rule to its runtime policies, and takes a disabled or deleted rule out of them: `options.policies` (pass the plan entry's `policies`, which a block that names its own carries), else the tenant setup's `policies`, as `opentide deploy` chooses them. A Google SecOps payload from `deploy_plan` carries, beside the rule's `text`, the `run_state` of its status strategy (a PREVIEW rule deploys without alerting), its `run_frequency` and its `sections`, which the deploy sends; a body with the text alone deploys under RELEASE's run state, and a `disable` always disables. Graylog bodies from `deploy_plan` are compiled for Graylog 7.2, and every one carries `tags` (opentide always tags its definitions), which only 7.2 takes. The tenant's version is read first: below 6.3 it is refused; below 7.2, a create, update or disable is refused before any write with the code `graylog_field_unsupported_version`, so through the SDK such a tenant takes deletions only, and `opentide deploy`, which compiles for the tenant's version, deploys the rest. A body that fits is sent in the shape the version takes. An Elastic body is `{"payload": <the Kibana rule>, "block": <the rule's elastic block>}`, as `opentide deploy` sends it and `deploy_plan` holds it, compiled for the entry's `tenant` (the first Elastic tenant the plan reaches) as `opentide deploy` compiles it, with that tenant's modifiers and `setup`, so another tenant with other modifiers, `tags`, `index` or `suppression` gets another Kibana rule: the rule is checked against Elasticsearch (the block's sources, else the tenant's `index`), then created, replaced or, when its type changes, created again, so `create` and `update` do the same, and `disable` writes it disabled; the Kibana rule's `rule_id` must be the request's, else the rule fails and nothing is sent; a bare Kibana rule deploys without those checks, which read the block, and says so with the warning `elastic_checks_skipped` (not raised). A tenant whose Graylog version does not revoke access tokens reliably adds the outcome's `graylog_version_vulnerable` warning: `warnings` lists what a deploy raised without failing, each `{code, message, raised}` with the `code` `opentide deploy` logs, such as a rule created again because the tenant lost it, and whether it raises the run's warnings (`false` for Splunk's `splunk_alert_deleted`, which only says what was done). `events` lists what the deploy did, each `{name, fields}` with its fields as `[key, value]` pairs in order, as `opentide deploy` logs them at info level; it is empty for now on every platform but Bitdefender (`bitdefender_rule_created`, with the new `rule_id`, and `bitdefender_rule_deleted`), Sysdig (`sysdig_rule_created`, with the new `rule_id`), Exabeam (`exabeam_rule_created`, `_updated`, `_disabled`, `_deleted`, with the `rule_id`), Graylog (`graylog_definition_created`, `_updated`, `_deleted`, with the `definition_id`) Google SecOps (`google_secops_rule_created`, with the new `rule_id`) and Elastic (`elastic_rule_created`, `_updated`, `_recreated`, `_deleted`, with the `rule_id`). A whole deploy run, with its plan, deployment state and retirements, is `runJson(['deploy', ...])`.

```js
const { Connection, Workspace } = require('@opentide/opentide')

async function main() {
  const connection = Connection.open((await Workspace.open('.')).tenants('sentinel_one')[0])
  const rule = { data: { name: 'Example', queryType: 'events' } }
  const outcome = await connection.deploy('11111111-1111-4111-8111-111111111111', 'create', JSON.stringify(rule))
  console.log(outcome.operation, outcome.warnings) // create []
}

main()
```

`query`, `validateQuery` and `deploy` each take a `signal` option, an `AbortSignal`, that stops that one operation: when it aborts, the promise rejects with `interrupted` and a search it stops is stopped on the tenant where the API allows it (CrowdStrike); the connection's other operations run on. A signal already aborted rejects at once. `deploy` takes it as its fourth argument, `{ signal }`; a deploy aborted after the tenant received it may have been applied.

```js
const { Connection, Workspace } = require('@opentide/opentide')

async function main() {
  const connection = Connection.open((await Workspace.open('.')).tenants('sentinel_one')[0])
  const end = new Date()
  const start = new Date(end.getTime() - 60 * 60 * 1000)
  try {
    const found = await connection.query("EventType = 'Process Creation'", {
      start,
      end,
      signal: AbortSignal.timeout(30_000),
    })
    console.log(found.rows.length) // 2
  } catch (error) {
    console.error(error.code) // `interrupted` if the search outlives 30 s
  }
}

main()
```

`connection.canceller()` returns a `Canceller` that stops every operation of the connection from elsewhere, a `SIGINT` handler or a timer: the running one, and every later one, rejects with `interrupted`, and a search it stops is stopped on the tenant where the API allows it (CrowdStrike).

A platform that cannot do an operation rejects with `operation_unsupported`, never a faked result: CrowdStrike, HarfangLab and Sysdig cannot check a query live, and Sysdig runs no queries. A tenant that refuses a query rejects with `tenant_refused`, with the vendor's words in `detail`:

```js
const { Connection, Workspace } = require('@opentide/opentide')

async function main() {
  const connection = Connection.open((await Workspace.open('.')).tenants('sentinel_one')[0])
  try {
    await connection.query("EventType = 'Process Creation' | syntax")
  } catch (error) {
    console.log(error.code) // tenant_refused
    console.log(error.detail)
  }
}

main()
```

The other codes are `tenant_unreachable`, `tenant_timeout`, `query_timed_out`, `authentication_failed`, `tenant_gateway`, `tenant_answer_invalid`, `tenant_setup_invalid`, `credential_unset`, `connector_crashed`, `interrupted`, `runtime_unavailable` and `usage_invalid_value` (a window or a timeout that does not read). `platforms()` lists the platforms with a connector, and `capabilities(platform)` says what one can do.

## Run a command

`runJson(argv)` runs one command in the process, off Node's event loop, and resolves to its `--json` document, parsed, with the command line's keys in its order: the envelope (`ok`, `command`, `result`, `failure`, ...) or, for `commands`, the command tree. A command that fails still returns its document, with `ok: false` and `failure.code`. `main(argv)` is the whole program, on the process's streams; it resolves to the exit code. Both read the process's working directory and environment when the command starts, on the Rust core's thread: pass `--repo` rather than `process.chdir` between runs, and leave `process.env` unchanged while one is pending (Node and the core would write and read it at once).

```js
const { runJson } = require('@opentide/opentide')

async function main() {
  const info = await runJson(['--repo', '.', 'info'])
  console.log(info.ok, info.counts.rules)
  const tree = await runJson(['commands'])
  console.log(tree.program, tree.version)
}

main()
```

## Errors

A call that cannot run throws an `Error`, or rejects its promise with one, whose `code` is a stable code: `configuration_invalid` or the configuration check's own code (`config_parse`, ...), `io_error`, `usage_invalid_choice` for an option the command line would refuse, `no_json_document` when `runJson`'s command writes no document (`--version`), and the [tenant operations](#tenant-operations)' codes, with which their promises reject. A failure inside the Rust core itself is `internal_error` (or `GenericFailure` from a synchronous method), never a crash of Node. Match on the code, not the message; `detail` holds the vendor's own words when a tenant gave a reason, and is `null` otherwise. A failed deploy always rejects, never resolves to an outcome, and its error also says what it stops: `scope` is `'rule'` (the tenant refused or could not take this rule; its other rules can deploy) or `'tenant'` (the tenant cannot take any rule: unreachable, refused credentials), `status` is the HTTP status the tenant answered with when it gave one, and `fields` is an object that locates the failure (`platform`, `tenant`, `address`, `detail`, in order). `partial` is what the deploy did before failing, when you must keep it: a `DeployOutcome` whose `remoteId` is the id the tenant gave the rule (a rule created, then refused; record it), with the warnings and events raised first, or `null` (only Sysdig's, Exabeam's, Bitdefender's and Google SecOps's for now). SentinelOne's refusals have codes of their own: `sentinel_one_rule_invalid` (400), `sentinel_one_unauthorized` (401, the tenant's), `sentinel_one_rule_not_found` (404), `sentinel_one_request_failed` (any other status), and `deployment_id_invalid` for a stored id that is not a number. `moreFailures` lists the rule's further failures, in order, each `{code, message, detail, scope, status, fields}`, when the deploy failed more than once (a Google SecOps rule whose text and then its deployment could not be written). Any other error's `scope`, `status` and `partial` are `null` and its `fields` and `moreFailures` empty. Findings about the workspace are not errors: they are in the report.

```js
const { runJson } = require('@opentide/opentide')

runJson(['--version']).catch((error) => {
  console.log(error.code) // no_json_document
})
```

## Types

The declarations (`index.d.ts`) are generated from the Rust binding by napi-rs and checked in; CI fails when a build changes them, and type-checks a sample consumer with `tsc --noEmit`. The options are typed, with the choices the command line accepts. The tenant operations' results (`QueryResult`, `LiveCheck`, `DeployOutcome`, `Capabilities`) are typed. The documents (`report`, `catalog()`, `rules()`, `document`, a query's rows) are typed `any` for now: their types, generated from the Rust structs, come with a later release.

## Stability

The package's version is opentide's. The SDK follows the [Rust SDK](./rust.md#stability)'s promise: the documents follow the command line's JSON contract ([JSON output](../cli/json-output.md)), which only grows.
