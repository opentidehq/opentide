// The `opentide` bin: main(argv) in Node's process, its streams and exit
// codes, Ctrl-C, and `npx opentide` through the alias package.
import assert from 'node:assert/strict'
import { spawn, spawnSync } from 'node:child_process'
import { cpSync, mkdirSync, symlinkSync } from 'node:fs'
import { createRequire } from 'node:module'
import { join } from 'node:path'
import { test } from 'node:test'
import { PACKAGE, tempDir, tideCorpus } from './corpus.mjs'

const CLI = join(PACKAGE, 'cli.js')
const require = createRequire(import.meta.url)
const opentide = require(PACKAGE)

/** Runs the bin as npm's shim does: `node cli.js <argv>`. */
function run(argv, options = {}) {
  return spawnSync(process.execPath, [CLI, ...argv], { encoding: 'utf8', ...options })
}

test('--json commands prints the command tree runJson returns', () => {
  const printed = run(['--json', 'commands'])
  assert.equal(printed.status, 0, printed.stderr)
  assert.equal(printed.stderr, '')
  assert.ok(printed.stdout.endsWith('\n'))
  // The same document but for the time each run took.
  const tree = JSON.parse(printed.stdout)
  const returned = opentide.runJson(['commands'])
  delete tree.duration_ms
  delete returned.duration_ms
  assert.equal(JSON.stringify(tree), JSON.stringify(returned))
})

test('the bin exits with the command line\'s code', () => {
  const version = run(['--version'])
  assert.equal(version.status, 0)
  assert.equal(version.stdout, `opentide ${opentide.VERSION}\n`)

  const typo = run(['valdiate'], { env: { ...process.env, OPENTIDE_OUTPUT: 'plain' } })
  assert.equal(typo.status, 2)
  assert.ok(typo.stderr.startsWith("error: No such command 'valdiate'."), typo.stderr)

  const ws = tideCorpus()
  const validate = run(['--json', 'validate'], { cwd: ws })
  assert.equal(validate.status, 0, validate.stderr)
  assert.equal(JSON.parse(validate.stdout).ok, true)
})

test('a large document reaches a pipe whole', () => {
  // `info catalog` writes more than a pipe's buffer holds: the bin writes
  // all of it before Node exits.
  const ws = tideCorpus()
  const catalog = run(['--json', 'info', 'catalog'], { cwd: ws, maxBuffer: 1 << 26 })
  assert.equal(catalog.status, 0, catalog.stderr)
  assert.equal(JSON.parse(catalog.stdout).counts.rules, 10)
})

test('Ctrl-C ends a run with 130', { skip: process.platform === 'win32' && 'POSIX signals' }, async () => {
  // `lsp start` serves on stdin until it closes; the first Ctrl-C stops it.
  const child = spawn(process.execPath, [CLI, 'lsp', 'start'], { stdio: ['pipe', 'ignore', 'pipe'] })
  let stderr = ''
  child.stderr.on('data', (chunk) => {
    stderr += chunk
  })
  // Once the server runs, its handler (installed by main) is in place.
  await new Promise((resolve) => setTimeout(resolve, 1000))
  child.kill('SIGINT')
  const [code, signal] = await new Promise((resolve) => child.on('exit', (...args) => resolve(args)))
  assert.deepEqual([code, signal], [130, null])
  assert.equal(stderr, 'error: interrupted\n')
})

test('`npx opentide` runs the alias package\'s bin, which is this package\'s', () => {
  // node_modules as npm lays it out: the alias, and the package it depends on.
  const root = tempDir()
  const modules = join(root, 'node_modules')
  mkdirSync(join(modules, '@opentide'), { recursive: true })
  symlinkSync(PACKAGE, join(modules, '@opentide', 'opentide'), 'junction')
  cpSync(join(PACKAGE, 'alias'), join(modules, 'opentide'), { recursive: true })

  const printed = spawnSync(process.execPath, [join(modules, 'opentide', 'cli.js'), '--version'], {
    encoding: 'utf8',
  })
  assert.equal(printed.status, 0, printed.stderr)
  assert.equal(printed.stdout, `opentide ${opentide.VERSION}\n`)

  const alias = createRequire(join(root, 'index.js'))('opentide')
  assert.equal(alias.runJson, opentide.runJson)
  assert.equal(alias.Workspace, opentide.Workspace)
})
