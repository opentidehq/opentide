// The workspaces the tests open, laid out under a temporary folder: a test
// never writes into the checkout.
import { cpSync, mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

/** The npm package's folder (bindings/node). */
export const PACKAGE = dirname(dirname(fileURLToPath(import.meta.url)))
/** The repository's root. */
export const REPO = dirname(dirname(PACKAGE))
/** The package's manifest. */
export const MANIFEST = JSON.parse(readFileSync(join(PACKAGE, 'package.json'), 'utf8'))

/** A fresh temporary folder, removed when the process exits. */
export function tempDir() {
  const dir = mkdtempSync(join(tmpdir(), 'opentide-node-'))
  process.on('exit', () => rmSync(dir, { recursive: true, force: true }))
  return dir
}

/**
 * tests/fixtures/tide_corpus/current (one threat, one objective, ten rules on
 * the nine platforms, every platform enabled) in today's layout,
 * `objects/<family>/` and `.opentide/configurations/`, as the facade's tests
 * lay it out (crates/opentide/tests/common).
 */
export function tideCorpus() {
  const dir = tempDir()
  const source = join(REPO, 'tests/fixtures/tide_corpus/current')
  cpSync(join(source, 'Configurations'), join(dir, '.opentide/configurations'), { recursive: true })
  for (const [family, legacy] of [
    ['threats', 'Objects/Threat Vectors'],
    ['objectives', 'Objects/Detection Objectives'],
    ['rules', 'Objects/Detection Rules'],
  ]) {
    cpSync(join(source, legacy), join(dir, 'objects', family), { recursive: true })
  }
  return dir
}
