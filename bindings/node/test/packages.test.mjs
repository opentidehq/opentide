// The npm packages: @opentide/opentide, one native package per target as an
// optional dependency, and the `opentide` alias, all at one version.
import assert from 'node:assert/strict'
import { readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { test } from 'node:test'
import { MANIFEST, PACKAGE } from './corpus.mjs'

const read = (path) => JSON.parse(readFileSync(join(PACKAGE, path), 'utf8'))

/** The npm platform name of each Rust target, as napi-rs names them. */
const PLATFORMS = {
  'x86_64-unknown-linux-gnu': 'linux-x64-gnu',
  'aarch64-unknown-linux-gnu': 'linux-arm64-gnu',
  'x86_64-unknown-linux-musl': 'linux-x64-musl',
  'aarch64-unknown-linux-musl': 'linux-arm64-musl',
  'x86_64-apple-darwin': 'darwin-x64',
  'aarch64-apple-darwin': 'darwin-arm64',
  'x86_64-pc-windows-msvc': 'win32-x64-msvc',
  'aarch64-pc-windows-msvc': 'win32-arm64-msvc',
}

test('the eight targets each have a native package, an optional dependency', () => {
  assert.deepEqual(MANIFEST.napi.targets, Object.keys(PLATFORMS))
  const dirs = readdirSync(join(PACKAGE, 'npm')).sort()
  assert.deepEqual(dirs, Object.values(PLATFORMS).sort())
  const optional = {}
  for (const platform of Object.values(PLATFORMS)) {
    const native = read(`npm/${platform}/package.json`)
    const name = `@opentide/opentide-${platform}`
    assert.equal(native.name, name)
    assert.equal(native.version, MANIFEST.version)
    assert.equal(native.main, `opentide.${platform}.node`)
    assert.deepEqual(native.files, [native.main])
    assert.equal(native.license, MANIFEST.license)
    optional[name] = MANIFEST.version
  }
  assert.deepEqual(MANIFEST.optionalDependencies, optional)
})

test('the alias depends on the package at its own version and has its bin', () => {
  const alias = read('alias/package.json')
  assert.equal(alias.name, 'opentide')
  assert.equal(alias.version, MANIFEST.version)
  assert.deepEqual(alias.dependencies, { [MANIFEST.name]: MANIFEST.version })
  assert.deepEqual(alias.bin, { opentide: 'cli.js' })
  assert.deepEqual(MANIFEST.bin, { opentide: 'cli.js' })
  assert.equal(alias.license, MANIFEST.license)
})

test('the packages ship only what they need', () => {
  assert.deepEqual(MANIFEST.files.sort(), ['LICENSE', 'README.md', 'cli.js', 'index.d.ts', 'index.js'])
  assert.equal(MANIFEST.private, undefined)
  assert.deepEqual(MANIFEST.publishConfig, { access: 'public', provenance: true })
})
