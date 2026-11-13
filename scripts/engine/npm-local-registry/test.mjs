#!/usr/bin/env node
// The npm install test: publish the release's npm tarballs to a throwaway
// local registry (Verdaccio, no uplink: nothing reaches npmjs.com), then
// install `@opentide/opentide` into a clean project the way a user does and
// check what npm chose and what runs.
//
//   node scripts/engine/npm-local-registry/test.mjs --version X.Y.Z --tarballs DIR
//   node scripts/engine/npm-local-registry/test.mjs --version X.Y.Z --pack DIR
//
// --tarballs DIR  publish every *.tgz under DIR (publish.yml's npm-pack layout:
//                 1-native, 2-package, 3-alias, 4-lsp).
// --pack DIR      first pack the tree's packages into DIR (bindings/node, its
//                 alias and every native package), at the version
//                 `release.py npm-version` wrote. The host's native package
//                 gets the addon `node build.mjs` built; a target without one
//                 is packed as a stand-in (its manifest, no addon), so that
//                 npm still sees all six and has to choose by os/cpu/libc.
// --keep          leave the work folder (registry storage, projects) in place.
// --work DIR      the work folder (default: a new one under the OS temp folder).
//
// It asserts that npm installed exactly the host's native package; that
// `npx opentide --version` prints the version (from @opentide/opentide, and
// from the `opentide` alias); that the SDK loads from CommonJS and ESM, with
// the loader's version check on; that `runJson(['commands'])` returns the
// command tree; and that `tsc --noEmit` resolves the package's types. The
// registry and the TypeScript compiler come from ./package-lock.json
// (`npm ci` from the default registry, into the work folder).
import assert from 'node:assert/strict'
import { spawn, spawnSync } from 'node:child_process'
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs'
import { createServer } from 'node:net'
import { tmpdir } from 'node:os'
import { dirname, join, relative, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { gunzipSync } from 'node:zlib'

const HERE = dirname(fileURLToPath(import.meta.url))
const ROOT = resolve(HERE, '..', '..', '..')
const NODE_PACKAGE = join(ROOT, 'bindings', 'node')
const MAIN = '@opentide/opentide'
const ALIAS = 'opentide'

// --- Arguments ---------------------------------------------------------------

function parseArgs(argv) {
  const args = { keep: false }
  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i]
    const value = () => {
      const next = argv[++i]
      if (next === undefined) fail(`${flag} needs a value`)
      return next
    }
    if (flag === '--version') args.version = value()
    else if (flag === '--tarballs') args.tarballs = resolve(value())
    else if (flag === '--pack') args.pack = resolve(value())
    else if (flag === '--work') args.work = resolve(value())
    else if (flag === '--keep') args.keep = true
    else fail(`unknown argument: ${flag}`)
  }
  if (!args.version) fail('--version is required')
  if (!/^\d+\.\d+\.\d+(?:-rc\.[1-9]\d*)?$/.test(args.version)) fail(`not a release version: ${args.version}`)
  if (Boolean(args.tarballs) === Boolean(args.pack)) fail('give one of --tarballs DIR and --pack DIR')
  return args
}

function fail(message) {
  console.error(`npm-local-registry: ${message}`)
  process.exit(2)
}

function step(message) {
  console.log(`\n== ${message}`)
}

function ok(message) {
  console.log(`ok   ${message}`)
}

// --- Processes ---------------------------------------------------------------

/** npm's own scripts next to this Node, so that no shell is needed on Windows
 * (npm.cmd and npx.cmd cannot be spawned without one). */
function npmScript(name) {
  const bin = dirname(process.execPath)
  for (const candidate of [
    join(bin, 'node_modules', 'npm', 'bin', name),
    join(bin, '..', 'lib', 'node_modules', 'npm', 'bin', name),
  ]) {
    if (existsSync(candidate)) return candidate
  }
  fail(`cannot find npm's ${name} next to ${process.execPath}`)
}

const NPM = npmScript('npm-cli.js')
const NPX = npmScript('npx-cli.js')

/** Runs a command, echoes it, and returns its stdout; a non-zero exit fails. */
function run(command, args, options = {}) {
  const words = [command === process.execPath ? 'node' : command, ...args]
  if (words[0] === 'node' && (words[1] === NPM || words[1] === NPX)) words.splice(0, 2, words[1] === NPM ? 'npm' : 'npx')
  const shown = words.join(' ')
  console.log(`$ ${shown}${options.cwd ? `    (in ${options.cwd})` : ''}`)
  const result = spawnSync(command, args, {
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
    ...options,
    env: { ...process.env, ...options.env },
  })
  if (result.error) throw result.error
  if (result.status !== 0) {
    process.stdout.write(result.stdout ?? '')
    process.stderr.write(result.stderr ?? '')
    throw new Error(`${shown} exited ${result.status}`)
  }
  return result.stdout
}

const npm = (args, options) => run(process.execPath, [NPM, ...args], options)
const npx = (args, options) => run(process.execPath, [NPX, ...args], options)

// --- Tarballs ----------------------------------------------------------------

/** The files of a gzipped tar (npm pack's format), each name with its bytes. */
function readTarball(path) {
  const tar = gunzipSync(readFileSync(path))
  const files = new Map()
  let longName = null
  for (let offset = 0; offset + 512 <= tar.length; ) {
    const header = tar.subarray(offset, offset + 512)
    if (header.every((byte) => byte === 0)) break
    const field = (start, length) => header.subarray(start, start + length).toString('utf8').replace(/\0.*$/s, '')
    const size = parseInt(field(124, 12).trim() || '0', 8)
    const type = field(156, 1)
    const prefix = field(345, 155)
    let name = longName ?? (prefix ? `${prefix}/${field(0, 100)}` : field(0, 100))
    longName = null
    const body = tar.subarray(offset + 512, offset + 512 + size)
    if (type === 'L') longName = body.toString('utf8').replace(/\0.*$/s, '')
    else if (type === '0' || type === '') files.set(name, body)
    offset += 512 + Math.ceil(size / 512) * 512
  }
  return files
}

function describeTarball(path) {
  const files = readTarball(path)
  const manifest = files.get('package/package.json')
  assert.ok(manifest, `${path} has no package/package.json`)
  return { path, manifest: JSON.parse(manifest.toString('utf8')), files: [...files.keys()] }
}

function findTarballs(dir) {
  const found = []
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name)
    if (entry.isDirectory()) found.push(...findTarballs(path))
    else if (entry.name.endsWith('.tgz')) found.push(path)
  }
  return found.sort()
}

/** napi-rs's platform name for this machine (`linux-x64-gnu`, `darwin-arm64`,
 * `win32-x64-msvc`). There is no musl package (the maintainer's decision). */
function hostPlatform() {
  const { platform, arch } = process
  if (platform === 'linux') {
    const glibc = process.report?.getReport()?.header?.glibcVersionRuntime
    if (!glibc) fail('this Linux has no glibc: opentide ships no musl package (docs/internal/publishing.md)')
    return `linux-${arch}-gnu`
  }
  if (platform === 'win32') return `win32-${arch}-msvc`
  return `${platform}-${arch}`
}

/** Packs the tree's packages into `out` (see --pack), without changing the tree. */
function packTree(out, version, platform, work) {
  step(`Pack the tree's npm packages at ${version}`)
  const layout = { native: join(out, '1-native'), main: join(out, '2-package'), alias: join(out, '3-alias') }
  for (const dir of Object.values(layout)) mkdirSync(dir, { recursive: true })
  const stage = join(work, 'stage')
  for (const name of readdirSync(join(NODE_PACKAGE, 'npm')).sort()) {
    const source = join(NODE_PACKAGE, 'npm', name)
    const target = join(stage, name)
    mkdirSync(target, { recursive: true })
    for (const file of readdirSync(source)) copyFileSync(join(source, file), join(target, file))
    // The licence ships with every package, as publish.yml packs them.
    copyFileSync(join(NODE_PACKAGE, 'LICENSE'), join(target, 'LICENSE'))
    const addon = `opentide.${name}.node`
    if (existsSync(join(NODE_PACKAGE, addon))) {
      copyFileSync(join(NODE_PACKAGE, addon), join(target, addon))
      ok(`${name}: the addon ${addon}`)
    } else {
      assert.notEqual(name, platform, `no addon for this machine: run \`node build.mjs\` in bindings/node first`)
      ok(`${name}: a stand-in (no addon built for it here; npm must not choose it)`)
    }
    npm(['pack', '--pack-destination', layout.native], { cwd: target })
  }
  npm(['pack', '--pack-destination', layout.main], { cwd: NODE_PACKAGE })
  npm(['pack', '--pack-destination', layout.alias], { cwd: join(NODE_PACKAGE, 'alias') })
}

// --- The registry ------------------------------------------------------------

function freePort() {
  return new Promise((resolvePort, reject) => {
    const server = createServer()
    server.once('error', reject)
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address()
      server.close(() => resolvePort(port))
    })
  })
}

async function startRegistry(work, tools) {
  const port = await freePort()
  const url = `http://127.0.0.1:${port}/`
  const storage = join(work, 'registry', 'storage')
  mkdirSync(storage, { recursive: true })
  const config = join(work, 'registry', 'config.yaml')
  // No `uplinks` and no `proxy`: a name the registry does not hold is a 404,
  // never a fetch from npmjs.com. Anyone may publish: the registry lives as
  // long as this script and listens on the loopback interface only.
  writeFileSync(
    config,
    [
      `storage: ${JSON.stringify(storage)}`,
      'auth:',
      '  htpasswd:',
      `    file: ${JSON.stringify(join(work, 'registry', 'htpasswd'))}`,
      'uplinks: {}',
      // An addon is tens of megabytes; Verdaccio refuses bodies over 10 MB by default.
      'max_body_size: 1gb',
      'packages:',
      "  '**':",
      '    access: $all',
      '    publish: $all',
      'log: { type: stdout, format: pretty, level: warn }',
      '',
    ].join('\n'),
  )
  const verdaccio = join(tools, 'node_modules', 'verdaccio', 'bin', 'verdaccio')
  console.log(`$ node ${relative(work, verdaccio)} --config ${relative(work, config)} --listen 127.0.0.1:${port}`)
  const child = spawn(process.execPath, [verdaccio, '--config', config, '--listen', `127.0.0.1:${port}`], {
    stdio: ['ignore', 'pipe', 'pipe'],
  })
  let log = ''
  child.stdout.on('data', (chunk) => (log += chunk))
  child.stderr.on('data', (chunk) => (log += chunk))
  const deadline = Date.now() + 60_000
  for (;;) {
    if (child.exitCode !== null) throw new Error(`the registry exited ${child.exitCode}:\n${log}`)
    try {
      const response = await fetch(`${url}-/ping`)
      if (response.ok) break
    } catch {
      // Not listening yet.
    }
    if (Date.now() > deadline) {
      child.kill()
      throw new Error(`the registry did not answer within 60 s:\n${log}`)
    }
    await new Promise((r) => setTimeout(r, 250))
  }
  ok(`Verdaccio at ${url} (no uplink)`)
  return { url, child, log: () => log }
}

async function packument(url, name) {
  const response = await fetch(`${url}${name.replace('/', '%2f')}`)
  assert.equal(response.status, 200, `the registry has no ${name}`)
  return response.json()
}

// --- The checks --------------------------------------------------------------

function installedPackages(project) {
  const modules = join(project, 'node_modules')
  const names = []
  for (const entry of readdirSync(modules)) {
    if (entry.startsWith('.')) continue
    if (entry.startsWith('@')) {
      for (const scoped of readdirSync(join(modules, entry))) names.push(`${entry}/${scoped}`)
    } else names.push(entry)
  }
  return names.sort()
}

function newProject(work, name, npmrc) {
  const project = join(work, name)
  mkdirSync(project, { recursive: true })
  writeFileSync(join(project, 'package.json'), JSON.stringify({ name, version: '1.0.0', private: true }, null, 2) + '\n')
  writeFileSync(join(project, '.npmrc'), readFileSync(npmrc))
  return project
}

function checkVersionCommand(project, version, label) {
  const out = npx(['opentide', '--version'], { cwd: project }).trim()
  console.log(out)
  assert.ok(out.split(/\s+/).includes(version), `${label}: \`npx opentide --version\` printed ${JSON.stringify(out)}, not ${version}`)
  ok(`${label}: npx opentide --version prints ${version}`)
}

function checkSdk(project, version, specifier) {
  writeFileSync(
    join(project, 'sdk.cjs'),
    `'use strict'
const assert = require('node:assert/strict')
const opentide = require(${JSON.stringify(specifier)})
assert.equal(typeof opentide.Workspace, 'function', 'Workspace')
assert.equal(typeof opentide.Workspace.open, 'function', 'Workspace.open')
assert.equal(typeof opentide.Workspace.fromFiles, 'function', 'Workspace.fromFiles')
assert.equal(opentide.__napiBindingTarget, 'native', 'the native addon, not a fallback')
assert.equal(opentide.VERSION, ${JSON.stringify(version)}, 'VERSION')
const tree = opentide.runJson(['commands'])
assert.equal(typeof tree, 'object')
assert.equal(tree.program, 'opentide')
assert.equal(tree.version, ${JSON.stringify(version)})
assert.ok(Array.isArray(tree.commands) && tree.commands.length > 0, 'commands')
const ws = opentide.Workspace.fromFiles(process.cwd(), {})
assert.equal(typeof ws.root, 'string')
console.log(JSON.stringify({ program: tree.program, version: tree.version, commands: tree.commands.length, root: typeof ws.root }))
`,
  )
  writeFileSync(
    join(project, 'sdk.mjs'),
    `import assert from 'node:assert/strict'
import { Workspace, runJson, VERSION } from ${JSON.stringify(specifier)}
assert.equal(typeof Workspace, 'function')
assert.equal(VERSION, ${JSON.stringify(version)})
assert.equal(runJson(['commands']).program, 'opentide')
console.log('esm import ok')
`,
  )
  // The loader's own check that the native package is the loader's version.
  const env = { NAPI_RS_ENFORCE_VERSION_CHECK: '1' }
  console.log(run(process.execPath, ['sdk.cjs'], { cwd: project, env }).trim())
  console.log(run(process.execPath, ['sdk.mjs'], { cwd: project, env }).trim())
  ok(`${specifier}: require() and import load the SDK; runJson(['commands']) returns the command tree`)
}

function checkTypes(project, tools, specifier) {
  writeFileSync(
    join(project, 'tsconfig.json'),
    JSON.stringify(
      {
        compilerOptions: {
          strict: true,
          noEmit: true,
          module: 'nodenext',
          moduleResolution: 'nodenext',
          target: 'es2022',
          types: [],
          skipLibCheck: false,
        },
        files: ['types.ts'],
      },
      null,
      2,
    ) + '\n',
  )
  writeFileSync(
    join(project, 'types.ts'),
    `import { main, runJson, VERSION, Workspace } from ${JSON.stringify(specifier)}
import type { LintOptions, ValidateOptions } from ${JSON.stringify(specifier)}

const options: ValidateOptions = { strict: true }
const lintOptions: LintOptions = { strict: false }
const ws: Workspace = Workspace.fromFiles('/ws', { 'objects/rules/a.yaml': 'name: A\\n' })
const failed: boolean = ws.validate(options).failed
const status: 'completed' | 'issues' | 'failed' = ws.lint(lintOptions).status
const code: number = main(['--version'])
const version: string = VERSION
const tree = runJson(['commands'])
// The declarations, not \`any\`: this line must be an error.
// @ts-expect-error Workspace.open takes a path
Workspace.open(42)
export { failed, status, code, version, tree }
`,
  )
  const tsc = join(tools, 'node_modules', 'typescript', 'bin', 'tsc')
  run(process.execPath, [tsc, '-p', 'tsconfig.json'], { cwd: project })
  ok(`${specifier}: tsc --noEmit resolves its types (index.d.ts)`)
}

function checkNatives(project, version, platform, expected) {
  const installed = installedPackages(project)
  console.log(`installed: ${installed.join(', ')}`)
  assert.deepEqual(installed, [...expected, `${MAIN}-${platform}`].sort(), 'npm installed another set of packages')
  for (const name of installed) {
    const manifest = JSON.parse(readFileSync(join(project, 'node_modules', name, 'package.json'), 'utf8'))
    assert.equal(manifest.version, version, `${name} is at ${manifest.version}`)
  }
  const native = join(project, 'node_modules', '@opentide', `opentide-${platform}`)
  const addon = `opentide.${platform}.node`
  assert.ok(statSync(join(native, addon)).size > 0, `${addon} is missing or empty`)
  assert.ok(existsSync(join(native, 'LICENSE')), `${MAIN}-${platform} carries no LICENSE`)
  ok(`npm installed exactly the host's native package, ${MAIN}-${platform}, with ${addon} and LICENSE`)
}

// --- Main --------------------------------------------------------------------

async function main() {
  const args = parseArgs(process.argv.slice(2))
  const platform = hostPlatform()
  const work = args.work ?? mkdtempSync(join(tmpdir(), 'opentide-npm-registry-'))
  mkdirSync(work, { recursive: true })
  console.log(`node ${process.version}, npm ${npm(['--version']).trim()}, host ${platform}, work folder ${work}`)
  let registry = null
  try {
    step('The tools: Verdaccio and TypeScript, from package-lock.json')
    const tools = join(work, 'tools')
    mkdirSync(tools, { recursive: true })
    for (const file of ['package.json', 'package-lock.json']) copyFileSync(join(HERE, file), join(tools, file))
    npm(['ci', '--ignore-scripts', '--no-audit', '--no-fund', '--loglevel', 'error'], { cwd: tools })

    const tarballDir = args.tarballs ?? args.pack
    if (args.pack) packTree(args.pack, args.version, platform, work)

    step('The tarballs')
    const tarballs = findTarballs(tarballDir).map(describeTarball)
    assert.ok(tarballs.length > 0, `no .tgz under ${tarballDir}`)
    for (const { manifest, path } of tarballs) {
      assert.equal(manifest.version, args.version, `${relative(tarballDir, path)} is ${manifest.name}@${manifest.version}`)
      console.log(`${manifest.name}@${manifest.version}  ${relative(tarballDir, path)}`)
    }
    const byName = new Map(tarballs.map((t) => [t.manifest.name, t]))
    const main = byName.get(MAIN)
    assert.ok(main, `no ${MAIN} tarball`)
    assert.ok(byName.has(ALIAS), `no ${ALIAS} tarball`)
    const optional = main.manifest.optionalDependencies ?? {}
    const natives = Object.keys(optional).sort()
    assert.ok(natives.length > 0, `${MAIN} lists no native package`)
    for (const name of natives) {
      assert.equal(optional[name], args.version, `${MAIN} depends on ${name}@${optional[name]}`)
      const native = byName.get(name)
      assert.ok(native, `${MAIN} depends on ${name}, which has no tarball`)
      const suffix = name.slice(`${MAIN}-`.length)
      assert.ok(!/musl|wasm|wasi/.test(suffix), `${name}: no musl or WebAssembly package ships`)
      const { os, cpu, libc } = native.manifest
      assert.ok(Array.isArray(os) && os.length === 1 && Array.isArray(cpu) && cpu.length === 1, `${name}: one os, one cpu`)
      assert.equal(suffix.split('-').slice(0, 2).join('-'), `${os[0]}-${cpu[0]}`, `${name}: its os and cpu`)
      assert.deepEqual(libc, os[0] === 'linux' ? ['glibc'] : undefined, `${name}: its libc`)
      assert.equal(native.manifest.main, `opentide.${suffix}.node`, `${name}: its main`)
    }
    const host = byName.get(`${MAIN}-${platform}`)
    assert.ok(host, `no native package for this machine (${platform})`)
    assert.ok(host.files.includes(`package/opentide.${platform}.node`), `${host.manifest.name} holds no addon`)
    ok(`${tarballs.length} tarballs at ${args.version}; ${MAIN} lists ${natives.length} native packages: ${natives.join(', ')}`)

    step('Publish them to the local registry')
    registry = await startRegistry(work, tools)
    const npmrc = join(work, 'npmrc')
    // Any token: the registry lets anyone publish. Every npm command here
    // reads only this file and its own cache, never the user's ~/.npmrc.
    const authority = registry.url.replace(/^http:/, '')
    writeFileSync(
      npmrc,
      [`registry=${registry.url}`, `${authority}:_authToken=local-test-only`, `cache=${join(work, 'npm-cache')}`, 'audit=false', 'fund=false', 'update-notifier=false', ''].join('\n'),
    )
    process.env.npm_config_userconfig = npmrc
    process.env.npm_config_globalconfig = join(work, 'npmrc-global')
    writeFileSync(process.env.npm_config_globalconfig, '')
    // Native packages first, as publish.yml publishes them: the package depends on them.
    const order = [
      ...tarballs.filter((t) => natives.includes(t.manifest.name)),
      main,
      ...tarballs.filter((t) => !natives.includes(t.manifest.name) && t !== main),
    ]
    for (const { path } of order) {
      // --provenance=false: the package's publishConfig asks for provenance,
      // which only a CI publish with an OIDC token can sign. --tag latest: a
      // candidate's prerelease version needs a tag named.
      npm(['publish', path, '--registry', registry.url, '--provenance=false', '--access', 'public', '--tag', 'latest', '--loglevel', 'warn'])
    }
    for (const name of natives) {
      const doc = await packument(registry.url, name)
      const published = doc.versions?.[args.version]
      const { os, cpu, libc } = byName.get(name).manifest
      assert.deepEqual([published?.os, published?.cpu, published?.libc], [os, cpu, libc], `${name}: the registry's os/cpu/libc`)
    }
    const mainDoc = await packument(registry.url, MAIN)
    assert.equal(mainDoc['dist-tags']?.latest, args.version)
    ok(`published ${order.length} packages; the registry serves each native package's os, cpu and libc`)

    step(`A clean project: npm install ${MAIN}`)
    const project = newProject(work, 'project', npmrc)
    npm(['install', MAIN, '--registry', registry.url], { cwd: project })
    checkNatives(project, args.version, platform, [MAIN])
    checkVersionCommand(project, args.version, MAIN)
    checkSdk(project, args.version, MAIN)
    checkTypes(project, tools, MAIN)

    step(`Another clean project: npm install ${ALIAS} (the alias)`)
    const aliasProject = newProject(work, 'alias-project', npmrc)
    npm(['install', ALIAS, '--registry', registry.url], { cwd: aliasProject })
    checkNatives(aliasProject, args.version, platform, [MAIN, ALIAS])
    checkVersionCommand(aliasProject, args.version, ALIAS)
    checkSdk(aliasProject, args.version, ALIAS)

    console.log(`\nPASS: ${MAIN}@${args.version} installs from a local registry and runs on ${platform}`)
  } finally {
    if (registry) registry.child.kill()
    if (!args.keep) rmSync(work, { recursive: true, force: true, maxRetries: 5, retryDelay: 500 })
    else console.log(`kept ${work}`)
  }
}

main().catch((error) => {
  console.error(`\nFAIL: ${error.message}`)
  process.exitCode = 1
})
