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
// Driven by xtask, OPENTIDE_CONFORMANCE_PLAN names the plan and
// OPENTIDE_CONFORMANCE_OUT the folder to write; OPENTIDE_CONFORMANCE_DIVERGE
// (test-only) makes this runner diverge on purpose. Without them, as part of
// `npm test`, it runs every operation on the tide corpus under a temporary
// folder.
import assert from 'node:assert/strict'
import { mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import { join, relative, sep } from 'node:path'
import { test } from 'node:test'
import { PACKAGE, REPO, tempDir, tideCorpus } from './corpus.mjs'

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
export function runPlan(plan, out, { diverge = false } = {}) {
  const written = []
  for (const corpus of plan.corpora) {
    const opened = new Map()
    for (const operation of plan.operations) {
      if (operation.corpora && !operation.corpora.includes(corpus.name.split('/')[0])) continue
      let document
      if (operation.call === 'run_json') {
        document = runJson(corpus.root, operation)
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

function standalonePlan() {
  const manifest = JSON.parse(readFileSync(MANIFEST, 'utf8'))
  return { corpora: [{ name: 'tide_corpus', root: tideCorpus() }], operations: manifest.operations }
}

test('the Node runner writes every document', () => {
  const driven = process.env.OPENTIDE_CONFORMANCE_PLAN
  const plan = driven ? JSON.parse(readFileSync(driven, 'utf8')) : standalonePlan()
  const out = driven ? process.env.OPENTIDE_CONFORMANCE_OUT : tempDir()
  const written = runPlan(plan, out, { diverge: Boolean(process.env.OPENTIDE_CONFORMANCE_DIVERGE) })
  assert.ok(written.length > 0, 'the plan names no operation')
  for (const path of written) JSON.parse(readFileSync(path, 'utf8'))
  if (!driven) {
    assert.equal(written.length, plan.operations.length)
    const validate = JSON.parse(readFileSync(join(out, 'tide_corpus', 'validate.json'), 'utf8'))
    assert.equal(validate.failed, false)
    assert.equal(validate.exit_code, 0)
  }
})

test('the divergence flag changes the bytes and not the data', () => {
  const plan = standalonePlan()
  plan.operations = plan.operations.filter((operation) => operation.name === 'validate')
  const [same] = runPlan(plan, tempDir())
  const [diverged] = runPlan(plan, tempDir(), { diverge: true })
  const before = readFileSync(same, 'utf8')
  const after = readFileSync(diverged, 'utf8')
  assert.notEqual(before, after)
  assert.deepEqual(JSON.parse(before), JSON.parse(after))
  assert.equal(Object.keys(JSON.parse(after))[1], 'exit_code')
})
