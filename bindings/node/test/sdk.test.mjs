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

test('runJson returns the document in the command line\'s key order', () => {
  const tree = opentide.runJson(['commands'])
  assert.deepEqual(Object.keys(tree).slice(0, 2), ['program', 'version'])
  assert.equal(tree.program, 'opentide')
  assert.equal(tree.version, opentide.VERSION)

  const ws = tideCorpus()
  const info = opentide.runJson(['--repo', ws, 'info'])
  assert.equal(info.ok, true)
  assert.equal(info.counts.rules, 10)

  // A failure still returns its document.
  const typo = opentide.runJson(['valdiate'])
  assert.equal(typo.ok, false)
  assert.equal(typo.failure.code, 'usage_unknown_command')
})

test('runJson throws no_json_document when the command writes none', () => {
  assert.throws(() => opentide.runJson(['--version']), (error) => {
    assert.ok(error instanceof Error)
    assert.equal(error.code, 'no_json_document')
    return true
  })
})

test('a workspace on disk reports what the command line reports', (t) => {
  const dir = tideCorpus()
  const cwd = process.cwd()
  process.chdir(dir)
  t.after(() => process.chdir(cwd))
  const ws = opentide.Workspace.open('.')
  assert.equal(ws.root, dir)

  const info = ws.info()
  assert.deepEqual(info.counts, { rules: 10, threats: 1, objectives: 1 })
  assert.deepEqual(info.counts, opentide.runJson(['info']).counts)

  const validation = ws.validate()
  const validate = opentide.runJson(['validate'])
  assert.equal(validation.failed, false)
  assert.equal(validation.exitCode, 0)
  assert.equal(validation.summary.objects, 12)
  assert.equal(JSON.stringify(validation.checks), JSON.stringify(validate.checks))
  assert.equal(JSON.stringify(validation.summary), JSON.stringify(validate.summary))
  assert.deepEqual(validation.report.issues, validate.report.issues)
  assert.deepEqual(Object.keys(validation.report), Object.keys(validate.report))

  const lint = ws.lint()
  const linted = opentide.runJson(['lint'])
  assert.equal(lint.status, linted.status)
  assert.equal(JSON.stringify(lint.findings), JSON.stringify(linted.findings))
  assert.equal(JSON.stringify(lint.summary), JSON.stringify(linted.summary))

  const coverage = ws.coverage('T1059')
  assert.equal(coverage.count, 10)
  assert.deepEqual(coverage.matched_techniques, ['T1059', 'T1059.004'])

  const catalogue = ws.catalog()
  assert.deepEqual(Object.keys(catalogue), ['objects', 'edges', 'signals', 'attack'])
  assert.deepEqual(catalogue.objects, opentide.runJson(['info', 'catalog']).objects)

  const plan = ws.deployPlan({ strategies: ['PREVIEW'] })
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

test('an option the command line would refuse throws usage_invalid_choice', () => {
  const ws = opentide.Workspace.fromFiles('/ws', {})
  for (const call of [
    () => ws.validate({ queries: 'loud' }),
    () => ws.validate({ check: 'everything' }),
    () => ws.lint({ checks: ['spelling'] }),
    () => ws.deployPlan({ strategies: ['LATER'] }),
  ]) {
    assert.throws(call, { code: 'usage_invalid_choice' })
  }
})

test('a configuration that does not resolve throws its code', () => {
  const dir = tideCorpus()
  const broken = { '.opentide/configurations/paths.toml': 'not = [toml' }
  assert.throws(() => opentide.Workspace.fromFiles(dir, broken), (error) => {
    assert.match(error.code, /^config/)
    return true
  })
})
