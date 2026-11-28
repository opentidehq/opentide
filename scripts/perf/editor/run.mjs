#!/usr/bin/env node
// Runs scripts/perf/editor/suite.cjs in VS Code under Xvfb, N times (a fresh VS Code each), with the
// extension at --vsx loaded in development mode and `opentide.path` set to --server (empty: no setting,
// the extension's own fallbacks).
//
//   xvfb-run -a node scripts/perf/editor/run.mjs --vsx /tmp/vsx --code .../VSCode-linux-x64/code \
//        --workspace DIR --label L --runs 4 --out out.json [--server PATH] [--proc SUBSTRING]
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const args = Object.fromEntries(process.argv.slice(2).reduce((acc, a, i, all) => (a.startsWith('--') ? [...acc, [a.slice(2), all[i + 1]]] : acc), []));
const vsx = resolve(args.vsx);
const require = createRequire(join(vsx, 'package.json'));
const { runTests } = require('@vscode/test-electron');
const runs = Number(args.runs || 3);
const here = import.meta.dirname;
const work = mkdtempSync(join(tmpdir(), 'opentide-editor-perf-'));
const results = [];
for (let i = 0; i < runs; i += 1) {
  const ws = join(work, `ws-${i}`);
  cpSync(resolve(args.workspace), ws, { recursive: true });
  mkdirSync(join(ws, '.vscode'), { recursive: true });
  // `opentide.path` is a machine-scoped setting: user settings, not the workspace's.
  mkdirSync(join(work, `ud-${i}`, 'User'), { recursive: true });
  writeFileSync(join(work, `ud-${i}`, 'User', 'settings.json'), JSON.stringify({ ...(args.server ? { 'opentide.path': args.server } : {}), 'telemetry.telemetryLevel': 'off', 'update.mode': 'none', 'extensions.autoUpdate': false, 'workbench.startupEditor': 'none', 'chat.disableAIFeatures': true }));
  const out = join(work, `out-${i}.json`);
  const t = Date.now();
  try {
    await runTests({
      vscodeExecutablePath: resolve(args.code),
      extensionDevelopmentPath: vsx,
      extensionTestsPath: join(here, 'suite.cjs'),
      launchArgs: [ws, '--disable-workspace-trust', '--no-sandbox', '--disable-gpu', '--disable-extensions', '--skip-welcome', '--skip-release-notes', `--user-data-dir=${join(work, `ud-${i}`)}`, `--extensions-dir=${join(work, `ex-${i}`)}`],
      extensionTestsEnv: { OPENTIDE_PERF_OUT: out, OPENTIDE_PERF_WARM: String(args.warm || 10), OPENTIDE_PERF_PAUSE: String(args.pause || 100), OPENTIDE_PERF_PROC: args.proc || '' },
    });
  } catch (e) {
    console.error(`run ${i} failed: ${e.message}`);
  }
  try { results.push({ run: i, wall_ms: Date.now() - t, ...JSON.parse(readFileSync(out, 'utf8')) }); } catch { results.push({ run: i, error: 'no result' }); }
}
rmSync(work, { recursive: true, force: true });
writeFileSync(resolve(args.out), JSON.stringify({ label: args.label, server: args.server || null, workspace: args.workspace, runs, raw: results }, null, 1));
const ok = results.filter((r) => !r.error);
console.log(`${args.label}: ${ok.length}/${runs} runs`);
