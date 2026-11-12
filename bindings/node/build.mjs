// Builds the addon for this machine (opentide.<target>.node) and writes the
// loader (index.js) and the TypeScript declarations (index.d.ts) napi-rs
// generates from the Rust items; both are committed, and CI fails when a
// build changes them. The command line reports this package's version
// (OPENTIDE_VERSION, which a caller may set to another).
// Arguments go to `napi build` (`--release`, `--profile develop`, `--target <triple>`).
import { spawnSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import { dirname, join } from 'node:path'

const require = createRequire(import.meta.url)
const { version } = require('./package.json')
const cli = require.resolve('@napi-rs/cli/package.json')
const napi = join(dirname(cli), JSON.parse(readFileSync(cli, 'utf8')).bin.napi)
const env = { ...process.env, OPENTIDE_VERSION: process.env.OPENTIDE_VERSION || version }
const args = ['build', '--platform', '--js', 'index.js', '--dts', 'index.d.ts', ...process.argv.slice(2)]
const build = spawnSync(process.execPath, [napi, ...args], { stdio: 'inherit', env })
if (build.error) throw build.error
process.exit(build.status ?? 1)
