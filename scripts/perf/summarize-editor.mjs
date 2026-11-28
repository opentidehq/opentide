#!/usr/bin/env node
// Markdown table of the in-editor runs (scripts/perf/editor/run-matrix.sh): percentiles over the pooled
// samples of every VS Code launch. node scripts/perf/summarize-editor.mjs docs/internal/perf/data [tier ...]
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
const dir = process.argv[2];
const order = process.argv.slice(3);
const q = (xs, p) => { if (!xs.length) return NaN; const s = [...xs].sort((a, b) => a - b); const i = (s.length - 1) * p; const lo = Math.floor(i), hi = Math.ceil(i); return s[lo] + (s[hi] - s[lo]) * (i - lo); };
const f = (x) => (Number.isNaN(x) ? '-' : x >= 100 ? x.toFixed(0) : x >= 10 ? x.toFixed(1) : x.toFixed(2));
const trio = (xs) => (xs.length ? `${f(q(xs, 0.5))} / ${f(q(xs, 0.95))} / ${f(Math.max(...xs))}` : '-');
const reports = readdirSync(dir).filter((n) => n.startsWith('ed-') && n.endsWith('.json')).map((n) => JSON.parse(readFileSync(join(dir, n), 'utf8')));
const tiers = order.length ? order : reports.map((r) => r.label.replace(/^ed-|-large$/g, ''));
console.log('| Runtime (in VS Code 1.147.0) | Launches ok | First diagnostics ms | Edit → diagnostics ms | Completion cold ms | Completion warm ms | Completion typed ms | Server RSS MiB |');
console.log('|---|---:|---:|---:|---:|---:|---:|---:|');
for (const tier of tiers) {
  const r = reports.find((x) => x.label === `ed-${tier}-large`);
  if (!r) continue;
  const ok = r.raw.filter((x) => !x.error && x.scenarios);
  const pool = (k) => ok.flatMap((x) => Object.values(x.scenarios).flatMap((s) => (k === 'cold' ? [s.cold] : s[k])));
  const edit = ok.flatMap((x) => (x.edit_diag_ms || []).filter((v) => v !== null));
  console.log(`| ${tier} | ${ok.length}/${r.runs} | ${trio(ok.map((x) => x.first_diag_ms))} | ${trio(edit)} | ${trio(pool('cold'))} | ${trio(pool('warm'))} | ${trio(pool('typed'))} | ${f(q(ok.map((x) => x.rss_mib).filter((v) => v != null), 0.5))} |`);
}
