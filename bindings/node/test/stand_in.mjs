// Stand-in tenants on loopback for the tenant operations (UC-5.3b, #838), as
// tests/stand_in_support.py starts them for the Python SDK: one of
// tests/cassettes/<name>/tenant.py (standard library only) in a child
// process, on a free loopback port it prints first. Nothing reaches a real host.
import { spawn } from 'node:child_process'
import { join } from 'node:path'
import { createInterface } from 'node:readline'
import { REPO } from './corpus.mjs'

/** The API token the SentinelOne stand-in accepts (`S1_API_TOKEN`). */
export const S1_TOKEN = 's1-stand-in-token'

/** The Python that runs the stand-ins: `$PYTHON`, else python3 (python on Windows). */
const PYTHON = process.env.PYTHON || (process.platform === 'win32' ? 'python' : 'python3')

/**
 * Starts the stand-in `name` with `env` added to its environment; resolves
 * to `{ url, stop }`. `stop()` kills it.
 */
export async function standIn(name, env) {
  const child = spawn(PYTHON, [join(REPO, 'tests/cassettes', name, 'tenant.py')], {
    env: { ...process.env, ...env },
    stdio: ['ignore', 'pipe', 'inherit'],
  })
  const stop = () => {
    child.kill()
  }
  const port = await new Promise((resolve, reject) => {
    const lines = createInterface({ input: child.stdout })
    lines.once('line', (line) => {
      lines.close()
      resolve(Number.parseInt(line.trim(), 10))
    })
    child.once('error', reject)
    child.once('exit', (code) => reject(new Error(`the ${name} stand-in exited (${code})`)))
  })
  // The port is read: a later exit is the test's stop().
  child.removeAllListeners('exit')
  return { url: `http://127.0.0.1:${port}`, stop }
}

/** The SentinelOne stand-in (tests/cassettes/sentinel_one/tenant.py). */
export function sentinelOne() {
  return standIn('sentinel_one', { S1_API_TOKEN: S1_TOKEN })
}
