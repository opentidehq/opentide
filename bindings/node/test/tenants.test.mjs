// The tenant operations (UC-5.3b, #838): Workspace.tenants and Connection,
// against the SentinelOne stand-in of tests/cassettes on loopback (the Python
// SDK's, tests/test_sdk/test_tenants.py). Each connection is given an
// environment of its own, so that no proxy of the process applies; nothing
// reaches a real host.
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { createRequire } from 'node:module'
import { after, before, test } from 'node:test'
import { PACKAGE } from './corpus.mjs'
import { S1_TOKEN, sentinelOne } from './stand_in.mjs'

const require = createRequire(import.meta.url)
const { Connection, TenantConfig, Workspace, capabilities, platforms } = require(PACKAGE)

const ENVIRONMENT = { environment: { S1_API_TOKEN: S1_TOKEN } }

let s1
before(async () => {
  s1 = await sentinelOne()
})
after(() => s1.stop())

function soc(url = s1.url) {
  return new TenantConfig('sentinel_one', 'soc', { url, api_token: '$S1_API_TOKEN', account_id: '42' })
}

function connect() {
  return Connection.open(soc(), ENVIRONMENT)
}

/** Asserts that `promise` rejects with an `Error` whose `code` is `code`; returns the error. */
async function rejects(promise, code) {
  let caught
  await assert.rejects(promise, (error) => {
    assert.ok(error instanceof Error, String(error))
    assert.equal(error.code, code, error.message)
    caught = error
    return true
  })
  return caught
}

// --------------------------------------------------------------------------
// Tenants and connections
// --------------------------------------------------------------------------

test('a workspace lists its tenants in file order', () => {
  const ws = Workspace.fromFiles('/ws', {
    '.opentide/configurations/platforms/splunk.toml':
      '[platform]\nenabled = true\n\n[[tenants]]\nname = "prod"\n[tenants.setup]\n' +
      'url = "$SPLUNK_URL"\nport = 8089\ntoken = "$SPLUNK_TOKEN"\n\n' +
      '[[tenants]]\nname = "lab"\n[tenants.setup]\nurl = "https://lab.example"\n',
  })
  const tenants = ws.tenants('splunk')
  assert.deepEqual(tenants.map((tenant) => tenant.name), ['prod', 'lab'])
  assert.ok(tenants[0] instanceof TenantConfig)
  assert.equal(tenants[0].platform, 'splunk')
  assert.deepEqual(tenants[0].setupKeys, ['port', 'token', 'url'])
  assert.deepEqual(ws.tenants('elastic'), [])
})

test('the platforms and what each can do', () => {
  assert.equal(platforms().length, 9)
  assert.deepEqual(capabilities('sysdig'), { deploy: true, liveValidation: false, query: false })
  assert.equal(capabilities('nowhere'), null)
})

test('a connection names its tenant and never its secret', () => {
  const connection = connect()
  assert.equal(connection.platform, 'sentinel_one')
  assert.equal(connection.tenant, 'soc')
  assert.deepEqual(connection.capabilities, { deploy: true, liveValidation: true, query: true })
  assert.ok(!JSON.stringify(connection).includes(S1_TOKEN))
})

test('opening refuses what cannot connect, synchronously', () => {
  for (const [tenant, code] of [
    [new TenantConfig('nowhere', 'x', { url: 'https://x' }), 'operation_unsupported'],
    [new TenantConfig('harfanglab', 'lab', { url: 'https://hl', api_token: '$UNSET_TOKEN' }), 'credential_unset'],
    [new TenantConfig('splunk', 'prod', { ssl: 'maybe' }), 'tenant_setup_invalid'],
  ]) {
    assert.throws(() => Connection.open(tenant, { environment: {} }), (error) => {
      assert.equal(error.code, code, error.message)
      assert.equal(error.detail, null)
      return true
    })
  }
  assert.throws(() => Connection.open(soc(), { environment: {} }), {
    code: 'credential_unset',
    message: /S1_API_TOKEN/,
  })
  for (const timeout of [-1, Number.NaN]) {
    assert.throws(() => Connection.open(soc(), { ...ENVIRONMENT, timeout }), { code: 'usage_invalid_value' })
  }
})

// --------------------------------------------------------------------------
// The operations
// --------------------------------------------------------------------------

test('a query resolves to its rows', async () => {
  const result = await connect().query("event.type = 'Process Creation'")
  assert.deepEqual(Object.keys(result), [
    'columns', 'rows', 'truncated', 'partial', 'warnings', 'vendorQueryId', 'sent', 'language',
  ])
  // The SentinelOne connector names no column types.
  assert.deepEqual(result.columns, [
    { name: 'src.process.name', type: null },
    { name: 'endpoint.name', type: null },
  ])
  assert.deepEqual(result.rows, [
    { 'src.process.name': 'cmd.exe', 'endpoint.name': 'ws-1' },
    { 'src.process.name': 'powershell.exe', 'endpoint.name': 'ws-2' },
  ])
  assert.equal(result.truncated, false)
  assert.equal(result.partial, false)
  assert.deepEqual(result.warnings, ['Add a filter on event.type to speed up the query'])
})

test('a query stops at its limit, over the window it is given', async () => {
  const end = new Date(Date.UTC(2026, 10, 12, 10))
  const start = new Date(end.getTime() - 3_600_000)
  const result = await connect().query('x', { limit: 1, start: start.toISOString(), end: end.toISOString() })
  assert.equal(result.rows.length, 1)
  assert.equal(result.truncated, true)
})

test('a refused query rejects with its code and the vendor\'s words', async () => {
  const error = await rejects(connect().query('x | syntax'), 'tenant_refused')
  assert.match(error.detail, /Syntax error at 3/)
})

test('an option that does not read rejects the promise', async () => {
  const connection = connect()
  await rejects(
    connection.query('x', { start: '2026-11-12T10:00:01Z', end: '2026-11-12T10:00:00Z' }),
    'usage_invalid_value',
  )
  await rejects(connection.query('x', { end: 'soon' }), 'usage_invalid_value')
  await rejects(connection.query('x', { timeout: -1 }), 'usage_invalid_value')
  await rejects(connection.deploy('x', 'upsert', '{}'), 'usage_invalid_choice')
})

test('a live check accepts and refuses', async () => {
  const connection = connect()
  const check = await connection.validateQuery("event.type = 'Process Creation'", { language: 's1ql' })
  assert.deepEqual(check.errors, [])
  assert.equal(check.result.rows[0]['endpoint.name'], 'ws-1')
  await rejects(connection.validateQuery('x | syntax'), 'tenant_refused')
})

test('a platform that cannot check live says so', async () => {
  const lab = new TenantConfig('harfanglab', 'lab', { url: 'http://127.0.0.1:9', api_token: 't' })
  const connection = Connection.open(lab, { environment: {} })
  assert.equal(connection.capabilities.liveValidation, false)
  await rejects(connection.validateQuery('process.name:cmd.exe'), 'operation_unsupported')
})

test('a deploy creates the rule', async () => {
  const connection = connect()
  const body = JSON.stringify({ data: { name: 'Example', queryType: 'events' } })
  const created = await connection.deploy('11111111-1111-4111-8111-111111111111', 'create', Buffer.from(body))
  assert.deepEqual(Object.keys(created), ['remoteId', 'operation'])
  assert.equal(created.operation, 'create')
  assert.match(created.remoteId, /^19000000000000000/)
  // A string body is sent as its UTF-8 bytes; an update of that rule.
  const updated = await connection.deploy(created.remoteId, 'update', body)
  assert.deepEqual(updated, { remoteId: created.remoteId, operation: 'update' })
})

test('an unreachable tenant is reported without its secret', async () => {
  const closed = Connection.open(soc('http://127.0.0.1:9'), ENVIRONMENT)
  const error = await rejects(closed.query('x'), 'tenant_unreachable')
  assert.ok(!error.message.includes(S1_TOKEN), error.message)
})

// --------------------------------------------------------------------------
// The event loop and cancellation
// --------------------------------------------------------------------------

test('operations leave the event loop free', async () => {
  const connection = connect()
  let ticks = 0
  const timer = setInterval(() => {
    ticks += 1
  }, 10)
  try {
    // A slow search is polled twice, at least one poll delay (0.5 s) apart.
    const [slow, fast] = await Promise.all([connection.query('slow'), connection.query('fast')])
    assert.equal(slow.rows.length, 2)
    assert.equal(fast.rows.length, 2)
  } finally {
    clearInterval(timer)
  }
  assert.ok(ticks >= 20, `${ticks} ticks`)
})

test('a canceller interrupts the running operation and every later one', async () => {
  const connection = connect()
  const canceller = connection.canceller()
  assert.equal(canceller.isCancelled, false)
  const running = connection.query('slow')
  setTimeout(() => canceller.cancel(), 100)
  const started = Date.now()
  await rejects(running, 'interrupted')
  assert.ok(Date.now() - started < 1000, 'stopped before the search finished')
  assert.equal(canceller.isCancelled, true)
  await rejects(connection.query('x'), 'interrupted')
})

test('the runtime starts on the first operation, not when the package loads', { skip: process.platform !== 'linux' }, () => {
  // Counts the process's threads through /proc before and after an operation.
  const script = `
    const { readdirSync } = require('node:fs')
    const { Connection, TenantConfig } = require(${JSON.stringify(PACKAGE)})
    const threads = () => readdirSync('/proc/self/task').length
    const lab = new TenantConfig('harfanglab', 'lab', { url: 'http://127.0.0.1:9', api_token: 't' })
    const connection = Connection.open(lab, { environment: {} })
    const before = threads()
    connection.validateQuery('x').catch((error) => {
      console.log(JSON.stringify({ before, after: threads(), code: error.code }))
    })
  `
  const run = spawnSync(process.execPath, ['-e', script], { encoding: 'utf8', timeout: 60_000 })
  assert.equal(run.status, 0, run.stderr)
  const seen = JSON.parse(run.stdout)
  assert.equal(seen.code, 'operation_unsupported')
  assert.ok(seen.after > seen.before, `${seen.before} threads, then ${seen.after}`)
})
