// The snippets of docs/sdk/typescript.md, run: each `js` fence as a script
// that requires the package, and each `npx` line of a `bash` fence with the
// package's bin in place of the copy npx would download, on the tide corpus.
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { mkdirSync, readFileSync, symlinkSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { test } from 'node:test'
import { PACKAGE, REPO, tempDir, tideCorpus } from './corpus.mjs'

const PAGE = 'docs/sdk/typescript.md'

/** Each fenced block of `page`: its language, first line and text. */
function fences(page) {
  const blocks = []
  let open = null
  readFileSync(join(REPO, page), 'utf8')
    .split('\n')
    .forEach((line, index) => {
      const fence = line.match(/^```(\S*)/)
      if (fence && open === null) {
        open = { language: fence[1], line: index + 2, lines: [] }
      } else if (fence) {
        blocks.push({ ...open, text: open.lines.join('\n') })
        open = null
      } else if (open !== null) {
        open.lines.push(line)
      }
    })
  return blocks
}

/** A corpus copy where `require('@opentide/opentide')` finds this package. */
function workspace() {
  const ws = tideCorpus()
  const modules = tempDir()
  mkdirSync(join(modules, 'node_modules', '@opentide'), { recursive: true })
  symlinkSync(PACKAGE, join(modules, 'node_modules', '@opentide', 'opentide'), 'junction')
  return { ws, modules }
}

const blocks = fences(PAGE)
const scripts = blocks.filter((block) => block.language === 'js')
const commands = blocks
  .filter((block) => block.language === 'bash')
  .flatMap((block) => block.text.split('\n').map((line, i) => ({ line: block.line + i, text: line.trim() })))
  .filter(({ text }) => text.startsWith('npx '))

test('the page has samples to run', () => {
  assert.ok(scripts.length >= 6, `${scripts.length} js fences`)
  assert.ok(commands.length >= 3, `${commands.length} npx lines`)
})

for (const script of scripts) {
  test(`${PAGE}:${script.line} runs`, () => {
    const { ws, modules } = workspace()
    const file = join(modules, 'sample.cjs')
    writeFileSync(file, script.text)
    const run = spawnSync(process.execPath, [file], { cwd: ws, encoding: 'utf8' })
    assert.equal(run.status, 0, `${run.stdout}\n${run.stderr}`)
    // A trailing `// value` states what the line before it prints.
    const stated = [...script.text.matchAll(/console\.log\([^\n]*\) \/\/ (.+)$/gm)].map((m) => m[1])
    for (const value of stated) {
      assert.ok(run.stdout.split('\n').includes(value), `prints ${value}: ${run.stdout}`)
    }
  })
}

for (const command of commands) {
  test(`${PAGE}:${command.line} \`${command.text}\` exits 0`, () => {
    const words = command.text.split(/\s+/).slice(1)
    const name = words.shift()
    assert.ok(['@opentide/opentide', 'opentide'].includes(name), name)
    const { ws } = workspace()
    const run = spawnSync(process.execPath, [join(PACKAGE, 'cli.js'), ...words], {
      cwd: ws,
      encoding: 'utf8',
      maxBuffer: 1 << 26,
    })
    assert.equal(run.status, 0, `${run.stdout}\n${run.stderr}`)
  })
}
