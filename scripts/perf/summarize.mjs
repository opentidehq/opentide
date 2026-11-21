#!/usr/bin/env node
// Markdown tables from the matrix's raw JSON (scripts/perf/run-matrix.sh): one row per tier and
// workspace, every percentile computed from the pooled raw samples.
//   node scripts/perf/summarize.mjs docs/internal/perf/data [tier ...]
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

const dir = process.argv[2];
const order = process.argv.slice(3);
const q = (xs, p) => {
  if (!xs.length) return NaN;
  const s = [...xs].sort((a, b) => a - b);
  const i = (s.length - 1) * p;
  const lo = Math.floor(i), hi = Math.ceil(i);
  return s[lo] + (s[hi] - s[lo]) * (i - lo);
};
const f = (x) => (Number.isNaN(x) ? '-' : x >= 100 ? x.toFixed(0) : x >= 10 ? x.toFixed(1) : x.toFixed(2));
const files = readdirSync(dir).filter((n) => n.endsWith('.json'));
const reports = files.map((n) => JSON.parse(readFileSync(join(dir, n), 'utf8')));
const tiers = order.length ? order : [...new Set(reports.map((r) => r.label.replace(/-(small|large)$/, '')))];
const get = (tier, ws) => reports.find((r) => r.label === `${tier}-${ws}`);

const pool = (r, kind, pick = (n) => n.startsWith('completion:')) => {
  const out = [];
  for (const run of r.raw.filter((x) => !x.error))
    for (const [name, s] of Object.entries(run.scenarios)) if (pick(name)) out.push(...(kind === 'cold' ? [s.cold.ms] : s[kind]));
  return out;
};
const trio = (xs) => `${f(q(xs, 0.5))} / ${f(q(xs, 0.95))} / ${f(Math.max(...xs))}`;
const col = (r, fn) => r.raw.filter((x) => !x.error).map(fn);

for (const ws of ['small', 'large']) {
  console.log(`\n### ${ws} workspace\n`);
  console.log('| Tier | Start → `initialize` ms | First diagnostics ms | Edit → diagnostics ms | Completion cold ms | Completion warm ms | Completion typed ms | Hover warm ms | `semanticTokens/full` cold ms | `workspace/diagnostic` ms | RSS MiB |');
  console.log('|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|');
  for (const tier of tiers) {
    const r = get(tier, ws);
    if (!r) continue;
    const init = col(r, (x) => x.init_ms);
    const first = col(r, (x) => x.first_diag_ms);
    const edit = r.raw.filter((x) => !x.error).flatMap((x) => x.edit_diag_ms);
    const wsp = r.raw.filter((x) => !x.error).flatMap((x) => x.workspace_pull.ms);
    const tok = r.raw.filter((x) => !x.error).map((x) => x.scenarios['semanticTokens/full'].cold.ms);
    const rss = col(r, (x) => x.hwm_mib);
    console.log(
      `| ${tier} | ${trio(init)} | ${trio(first)} | ${trio(edit)} | ${trio(pool(r, 'cold'))} | ${trio(pool(r, 'warm'))} | ${trio(pool(r, 'typed'))} | ${trio(pool(r, 'warm', (n) => n.startsWith('hover:')))} | ${trio(tok)} | ${wsp.length ? trio(wsp) : '-'} | ${f(q(rss, 0.5))} |`,
    );
  }
}

console.log('\n### What a completion returns (items, bytes)\n');
console.log('| Tier | after `\\| ` | after `where ` | YAML key | platform key | ATT&CK technique |');
console.log('|---|---:|---:|---:|---:|---:|');
for (const tier of tiers) {
  const r = get(tier, 'small');
  if (!r) continue;
  const c = (n) => {
    const s = r.summary.scenarios[`completion:${n}`];
    return `${s.items} / ${(s.bytes / 1024).toFixed(1)} KiB`;
  };
  console.log(`| ${tier} | ${c('kql-after-pipe')} | ${c('kql-after-where')} | ${c('yaml-top-key')} | ${c('platform-block-key')} | ${c('attack-technique')} |`);
}
const m = reports[0].machine;
console.log(`\nMachine: ${m.cpus} vCPU (${m.model}), ${m.mem_gib} GiB, node ${m.node}, ${m.platform}. Runs per row: ${reports[0].runs}, warm samples per scenario and run: ${reports[0].warm}.`);
