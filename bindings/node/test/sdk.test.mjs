// The SDK: Workspace and runJson, against the command line's own documents.
import assert from 'node:assert/strict'
import { createRequire } from 'node:module'
import { test } from 'node:test'
import { MANIFEST, PACKAGE, tideCorpus } from './corpus.mjs'

const require = createRequire(import.meta.url)
const opentide = require(PACKAGE)

test('VERSION is the version the build was given, the package\'s by default', () => {
  assert.equal(opentide.VERSION, process.env.OPENTIDE_VERSION || MANIFEST.version)
})

test('runJson returns the document in the command line\'s key order', async () => {
  const tree = await opentide.runJson(['commands'])
  assert.deepEqual(Object.keys(tree).slice(0, 2), ['program', 'version'])
  assert.equal(tree.program, 'opentide')
  assert.equal(tree.version, opentide.VERSION)

  const ws = tideCorpus()
  const info = await opentide.runJson(['--repo', ws, 'info'])
  assert.equal(info.ok, true)
  assert.equal(info.counts.rules, 10)

  // A failure still returns its document.
  const typo = await opentide.runJson(['valdiate'])
  assert.equal(typo.ok, false)
  assert.equal(typo.failure.code, 'usage_unknown_command')
})

test('runJson rejects with no_json_document when the command writes none', async () => {
  await assert.rejects(opentide.runJson(['--version']), (error) => {
    assert.ok(error instanceof Error)
    assert.equal(error.code, 'no_json_document')
    return true
  })
})

test('a workspace on disk reports what the command line reports', async (t) => {
  const dir = tideCorpus()
  const cwd = process.cwd()
  process.chdir(dir)
  t.after(() => process.chdir(cwd))
  const ws = await opentide.Workspace.open('.')
  assert.equal(ws.root, dir)

  const info = ws.info()
  assert.deepEqual(info.counts, { rules: 10, threats: 1, objectives: 1 })
  assert.deepEqual(info.counts, (await opentide.runJson(['info'])).counts)

  const validation = ws.validate()
  const validate = await opentide.runJson(['validate'])
  assert.equal(validation.failed, false)
  assert.equal(validation.exitCode, 0)
  assert.equal(validation.summary.objects, 12)
  assert.equal(JSON.stringify(validation.checks), JSON.stringify(validate.checks))
  assert.equal(JSON.stringify(validation.summary), JSON.stringify(validate.summary))
  assert.deepEqual(validation.report.issues, validate.report.issues)
  assert.deepEqual(Object.keys(validation.report), Object.keys(validate.report))

  const lint = ws.lint()
  const linted = await opentide.runJson(['lint'])
  assert.equal(lint.status, linted.status)
  assert.equal(JSON.stringify(lint.findings), JSON.stringify(linted.findings))
  assert.equal(JSON.stringify(lint.summary), JSON.stringify(linted.summary))

  const coverage = ws.coverage('T1059')
  assert.equal(coverage.count, 10)
  assert.deepEqual(coverage.matched_techniques, ['T1059', 'T1059.004'])

  const catalogue = ws.catalog()
  assert.deepEqual(Object.keys(catalogue), ['objects', 'edges', 'signals', 'attack'])
  assert.deepEqual(catalogue.objects, (await opentide.runJson(['info', 'catalog'])).objects)

  const plan = await ws.deployPlan({ strategies: ['PREVIEW'] })
  assert.equal(typeof plan.ok, 'boolean')
  assert.deepEqual(plan.document.strategies, ['PREVIEW'])
  assert.equal(plan.document.dry_run, true)
})

test('a workspace in memory reads nothing from the disk', () => {
  const ws = opentide.Workspace.fromFiles('/ws', {
    'objects/rules/a.yaml': 'name: A\nmetadata:\n  uuid: not-a-uuid\n',
  })
  assert.equal(ws.info().counts.rules, 1)
  const validation = ws.validate({ queries: 'off', check: 'uuid-format' })
  assert.equal(validation.failed, true)
  assert.equal(validation.exitCode, 1)
  assert.deepEqual(Object.keys(validation.checks), ['uuid-format'])
  assert.ok(validation.report.issues.some((issue) => issue.code === 'invalid_uuid'))
  const lint = ws.lint({ checks: ['metadata'] })
  assert.deepEqual(lint.checks, ['metadata'])
})

test('an option the command line would refuse throws usage_invalid_choice', async () => {
  const ws = opentide.Workspace.fromFiles('/ws', {})
  for (const call of [
    () => ws.validate({ queries: 'loud' }),
    () => ws.validate({ check: 'everything' }),
    () => ws.lint({ checks: ['spelling'] }),
  ]) {
    assert.throws(call, { code: 'usage_invalid_choice' })
  }
  // deployPlan returns a promise, which rejects.
  await assert.rejects(ws.deployPlan({ strategies: ['LATER'] }), { code: 'usage_invalid_choice' })
})

test('a configuration that does not resolve throws its code', () => {
  const dir = tideCorpus()
  const broken = { '.opentide/configurations/paths.toml': 'not = [toml' }
  assert.throws(() => opentide.Workspace.fromFiles(dir, broken), (error) => {
    assert.match(error.code, /^config/)
    return true
  })
})

test('main, runJson, Workspace.open and deployPlan return promises, off the event loop', async () => {
  // #1142: each returns at once; the work runs on the Rust core's threads.
  const tree = opentide.runJson(['commands'])
  const opened = opentide.Workspace.open(tideCorpus())
  const code = opentide.main(['--version'])
  for (const pending of [tree, opened, code]) assert.ok(pending instanceof Promise)
  // The event loop runs while they do: a timer set now fires before all settle.
  let ticked = false
  setImmediate(() => {
    ticked = true
  })
  const [document, ws, exit] = await Promise.all([tree, opened, code])
  assert.equal(document.program, 'opentide')
  assert.equal(exit, 0)
  const plan = ws.deployPlan({ strategies: ['PREVIEW'] })
  assert.ok(plan instanceof Promise)
  assert.equal(typeof (await plan).ok, 'boolean')
  assert.ok(ticked)
})

test('info and a plan look a tenant\'s credentials up in the environment given', async () => {
  const variable = 'OPENTIDE_SWEEP_NODE_TOKEN'
  const reference = '$' + variable
  assert.equal(process.env[variable], undefined)
  const ws = opentide.Workspace.fromFiles('/ws', {
    '.opentide/configurations/platforms/sentinel_one.toml':
      '[platform]\nenabled = true\n\n[[tenants]]\nname = "lab"\nstrategies = ["PREVIEW", "RELEASE"]\n' +
      '[tenants.setup]\nurl = "https://s1.invalid"\naccount_id = 1001\napi_token = "' + reference + '"\n',
    'objects/rules/s1.yaml':
      'name: S1 rule\nmetadata:\n  uuid: 00000000-0000-4000-8099-000000000202\n  schema: rule::1.0\n' +
      '  version: 1\n  created: 2026-01-01\n  modified: 2026-01-02\n  tlp: clear\ndescription: S1.\n' +
      'response:\n  alert_severity: High\nconfigurations:\n  sentinel_one:\n    status: STAGING\n' +
      '    condition:\n      type: Single Event\n      single_event:\n        query: src.process.name = \'cmd.exe\'\n' +
      '    response:\n      treat_as_threat: Malicious\n      network_quarantine: false\n',
  })
  const set = (info) => info.platforms
    .flatMap((platform) => platform.tenants)
    .flatMap((tenant) => tenant.variables)
    .find((v) => v.name === variable).set
  assert.equal(set(ws.info()), false)
  assert.equal(set(ws.info({ [variable]: 'token' })), true)
  const named = async (options) => JSON.stringify((await ws.deployPlan(options)).document).includes(reference)
  const plan = { strategies: ['PREVIEW'], platform: 'sentinel_one' }
  assert.equal(await named(plan), true)
  assert.equal(await named({ ...plan, environment: { [variable]: 'token' } }), false)
})
