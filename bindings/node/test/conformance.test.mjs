// The Node runner of the cross-SDK conformance suite (UC-5.4, #839).
//
// It runs every operation of tests/conformance/manifest.json on every corpus
// of a plan through @opentide/opentide (Workspace and runJson), and writes
// each result as a normalised JSON document, <out>/<corpus>/<operation>.json.
// `cargo xtask conformance` runs it next to the Rust runner
// (crates/opentide/tests/conformance.rs) and the Python runner
// (tests/conformance/test_python_runner.py) and requires the three trees to be
// byte-identical; tests/conformance/README.md says how a document is built,
// the same way in each runner.
//
// Driven by xtask, OPENTIDE_CONFORMANCE_PLAN names the plan (with the URLs of
// the stand-in tenants xtask started, which every runner talks to) and
// OPENTIDE_CONFORMANCE_OUT the folder to write; OPENTIDE_CONFORMANCE_DIVERGE
// (test-only) makes this runner diverge on purpose. Without them, as part of
// `npm test`, it starts the stand-ins itself and runs every operation on the
// tide corpus under a temporary folder.
import assert from 'node:assert/strict'
import { mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import { join, relative, sep } from 'node:path'
import { test } from 'node:test'
import { PACKAGE, REPO, tempDir, tideCorpus } from './corpus.mjs'
import { standIn } from './stand_in.mjs'

const require = createRequire(import.meta.url)
const opentide = require(PACKAGE)

const MANIFEST = join(REPO, 'tests/conformance/manifest.json')

/** `document` as every runner writes it: two-space indentation, keys in their order, a final newline. */
export function canonical(document) {
  return `${JSON.stringify(document, null, 2)}\n`
}

// The members that hold a run's own clock, by their path from the document's
// root: its wall time and the time it ran, the values two runs of one operation
// differ in. Every runner writes them as null, and changes nothing else.
const VOLATILE = [['duration_ms'], ['evaluated_at'], ['report', 'stats', 'wall_ms']]

const isObject = (value) => value !== null && typeof value === 'object' && !Array.isArray(value)

/** `document` with each member of VOLATILE it has set to null. */
export function normalise(document) {
  for (const path of VOLATILE) {
    let parent = document
    for (const key of path.slice(0, -1)) parent = isObject(parent) ? parent[key] : undefined
    const last = path[path.length - 1]
    if (isObject(parent) && Object.hasOwn(parent, last)) parent[last] = null
  }
  return document
}

function error(e) {
  if (typeof e?.code !== 'string') throw e
  return { error: { code: e.code, message: e.message } }
}

/** A tenant operation's error: its code, its message and the vendor's words. */
function tenantError(e) {
  if (typeof e?.code !== 'string') throw e
  return { error: { code: e.code, message: e.message, detail: e.detail } }
}

/** Every file under `root`, by its path from `root` with `/`, as text. */
function files(root) {
  const out = {}
  for (const entry of readdirSync(root, { recursive: true, withFileTypes: true })) {
    if (!entry.isFile()) continue
    const path = join(entry.parentPath ?? entry.path, entry.name)
    out[relative(root, path).split(sep).join('/')] = readFileSync(path, 'utf8')
  }
  return out
}

function open(root, mode) {
  try {
    return mode === 'files' ? opentide.Workspace.fromFiles(root, files(root)) : opentide.Workspace.open(root)
  } catch (e) {
    return error(e)
  }
}

// The manifest's options are the facade's names; the Node API's are camelCase.
function call(ws, operation) {
  const o = operation.options ?? {}
  switch (operation.call) {
    case 'validate': {
      const v = ws.validate({
        check: o.check,
        files: o.files,
        uuids: o.uuids,
        types: o.types,
        strict: o.strict,
        queries: o.queries,
      })
      return {
        checks: v.checks,
        report: v.report,
        summary: v.summary,
        failed: v.failed,
        warned: v.warned,
        exit_code: v.exitCode,
      }
    }
    case 'lint': {
      const r = ws.lint({ checks: o.checks, files: o.files, strict: o.strict })
      return {
        path: r.path,
        checks: r.checks,
        findings: r.findings,
        status: r.status,
        message: r.message,
        exit_code: r.exitCode,
        failure_code: r.failureCode,
        summary: r.summary,
        outcome: r.outcome,
        unmatched: r.unmatched,
        warnings: r.warnings,
        next_actions: r.nextActions,
      }
    }
    case 'info':
      return ws.info()
    case 'catalog':
      return ws.catalog()
    case 'rules':
      return ws.rules()
    case 'objectives':
      return ws.objectives()
    case 'threats':
      return ws.threats()
    case 'coverage':
      return ws.coverage(operation.technique)
    case 'tenants':
      return ws
        .tenants(operation.platform)
        .map((tenant) => ({ platform: tenant.platform, name: tenant.name, setup_keys: tenant.setupKeys }))
    case 'deploy_plan': {
      const plan = ws.deployPlan({
        strategies: o.strategies,
        uuids: o.uuids,
        files: o.files,
        platform: o.platform,
        keepDeprecated: o.keep_deprecated,
      })
      return { document: plan.document, summary: plan.summary, ok: plan.ok }
    }
    default:
      throw new Error(`unknown call ${operation.call}`)
  }
}

// The calls on a tenant (Connection), not on a workspace.
const TENANT_CALLS = new Set(['query', 'validate_query', 'deploy'])

/** `tenant`'s setup, each `{<stand-in>}` the URL that stand-in listens on. */
function setup(tenant, urls) {
  const out = {}
  for (const [key, value] of Object.entries(tenant.setup)) {
    out[key] = Object.entries(urls).reduce((text, [name, url]) => text.replaceAll(`{${name}}`, url), value)
  }
  return out
}

function connect(tenant, urls) {
  try {
    const config = new opentide.TenantConfig(tenant.platform, tenant.name, setup(tenant, urls))
    return opentide.Connection.open(config, { environment: tenant.environment })
  } catch (e) {
    return tenantError(e)
  }
}

/** A query's document, by the facade's names (`vendorQueryId` as `vendor_query_id`). */
function queryDocument(result) {
  return {
    columns: result.columns,
    rows: result.rows,
    truncated: result.truncated,
    partial: result.partial,
    warnings: result.warnings,
    vendor_query_id: result.vendorQueryId,
    sent: result.sent,
    language: result.language,
  }
}

async function tenantCall(connection, operation) {
  if (operation.call === 'deploy') {
    const outcome = await connection.deploy(operation.rule_id, operation.operation, Buffer.from(operation.body, 'utf8'))
    return { remote_id: outcome.remoteId, operation: outcome.operation }
  }
  const o = operation.options ?? {}
  // The window's instants as Dates, as the Python runner passes datetimes.
  const at = (text) => (text === undefined ? undefined : new Date(text))
  const options = {
    language: o.language,
    start: at(o.start),
    end: at(o.end),
    limit: o.limit,
    index: o.index,
    dataView: o.data_view,
    timeout: o.timeout,
  }
  if (operation.call === 'query') return queryDocument(await connection.query(operation.text, options))
  const check = await connection.validateQuery(operation.text, options)
  return {
    result: check.result === null ? null : queryDocument(check.result),
    errors: check.errors,
    warnings: check.warnings,
  }
}

async function tenant(connection, operation) {
  if (!(connection instanceof opentide.Connection)) return connection
  try {
    return await tenantCall(connection, operation)
  } catch (e) {
    return tenantError(e)
  }
}

function connectors() {
  const platforms = opentide.platforms()
  const capabilities = {}
  for (const platform of platforms) {
    const found = opentide.capabilities(platform)
    if (found !== null) {
      capabilities[platform] = { deploy: found.deploy, live_validation: found.liveValidation, query: found.query }
    }
  }
  return { platforms, capabilities }
}

function guarded(ws, operation) {
  try {
    return call(ws, operation)
  } catch (e) {
    return error(e)
  }
}

function runJson(root, operation) {
  const argv = operation.repo === false ? [...operation.argv] : ['--repo', root, ...operation.argv]
  const cwd = process.cwd()
  process.chdir(root)
  let document
  try {
    document = opentide.runJson(argv)
  } catch (e) {
    return error(e)
  } finally {
    process.chdir(cwd)
  }
  return document
}

/** Sorts every object's keys: the test-only divergence. */
function sorted(value) {
  if (Array.isArray(value)) return value.map(sorted)
  if (value === null || typeof value !== 'object') return value
  return Object.fromEntries(
    Object.keys(value)
      .sort()
      .map((key) => [key, sorted(value[key])]),
  )
}

/** Writes the document of every operation on every corpus of `plan` under `out`. */
export async function runPlan(plan, out, { diverge = false } = {}) {
  const written = []
  const tenants = new Map((plan.tenants ?? []).map((t) => [t.name, t]))
  const urls = plan.urls ?? {}
  for (const corpus of plan.corpora) {
    const opened = new Map()
    const connected = new Map()
    for (const operation of plan.operations) {
      if (operation.corpora && !operation.corpora.includes(corpus.name.split('/')[0])) continue
      let document
      if (operation.call === 'run_json') {
        document = runJson(corpus.root, operation)
      } else if (operation.call === 'connectors') {
        document = connectors()
      } else if (TENANT_CALLS.has(operation.call)) {
        if (!connected.has(operation.tenant)) connected.set(operation.tenant, connect(tenants.get(operation.tenant), urls))
        document = await tenant(connected.get(operation.tenant), operation)
      } else {
        const mode = operation.open ?? 'disk'
        if (!opened.has(mode)) opened.set(mode, open(corpus.root, mode))
        const ws = opened.get(mode)
        document = ws instanceof opentide.Workspace ? guarded(ws, operation) : ws
        if (diverge && operation.call === 'validate' && ws instanceof opentide.Workspace) {
          // The document as a binding that went through a sorted map would hand it back.
          document = sorted(document)
        }
      }
      const path = join(out, ...corpus.name.split('/'), `${operation.name}.json`)
      mkdirSync(join(path, '..'), { recursive: true })
      writeFileSync(path, canonical(normalise(document)))
      written.push(path)
    }
  }
  return written
}

/** Every operation of the manifest on the tide corpus; its `urls` are the stand-ins' once `startStandIns` started them. */
function standalonePlan() {
  const manifest = JSON.parse(readFileSync(MANIFEST, 'utf8'))
  return {
    corpora: [{ name: 'tide_corpus', root: tideCorpus() }],
    operations: manifest.operations,
    tenants: manifest.tenants,
    stand_ins: manifest.stand_ins,
    urls: {},
  }
}

/** Starts each stand-in tenant of `plan` for a run of this runner alone; resolves to their `stop()`. */
async function startStandIns(plan) {
  const started = []
  for (const spec of plan.stand_ins) {
    const tenant = await standIn(spec.name, spec.environment)
    started.push(tenant)
    plan.urls[spec.name] = tenant.url
  }
  return () => {
    for (const tenant of started) tenant.stop()
  }
}

const read = (out, name) => JSON.parse(readFileSync(join(out, 'tide_corpus', `${name}.json`), 'utf8'))

test('the Node runner writes every document', async () => {
  const driven = process.env.OPENTIDE_CONFORMANCE_PLAN
  const plan = driven ? JSON.parse(readFileSync(driven, 'utf8')) : standalonePlan()
  const out = driven ? process.env.OPENTIDE_CONFORMANCE_OUT : tempDir()
  const stop = driven ? () => {} : await startStandIns(plan)
  let written
  try {
    written = await runPlan(plan, out, { diverge: Boolean(process.env.OPENTIDE_CONFORMANCE_DIVERGE) })
  } finally {
    stop()
  }
  assert.ok(written.length > 0, 'the plan names no operation')
  for (const path of written) JSON.parse(readFileSync(path, 'utf8'))
  if (!driven) {
    assert.equal(written.length, plan.operations.length)
    const validate = read(out, 'validate')
    assert.equal(validate.failed, false)
    assert.equal(validate.exit_code, 0)
    // The tenant operations reached the stand-ins.
    assert.deepEqual(read(out, 'query-soc').rows[0], { 'src.process.name': 'cmd.exe', 'endpoint.name': 'ws-1' })
    assert.deepEqual(read(out, 'deploy-soc-create'), { remote_id: '1900000000000000001', operation: 'create' })
  }
})

test('the divergence flag changes the bytes and not the data', async () => {
  const plan = standalonePlan()
  plan.operations = plan.operations.filter((operation) => operation.name === 'validate')
  const [same] = await runPlan(plan, tempDir())
  const [diverged] = await runPlan(plan, tempDir(), { diverge: true })
  const before = readFileSync(same, 'utf8')
  const after = readFileSync(diverged, 'utf8')
  assert.notEqual(before, after)
  assert.deepEqual(JSON.parse(before), JSON.parse(after))
  assert.equal(Object.keys(JSON.parse(after))[1], 'exit_code')
})
