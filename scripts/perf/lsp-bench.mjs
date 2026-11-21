#!/usr/bin/env node
// A scripted LSP client that measures a language server's latency from the outside: server start to
// the `initialize` result, the first diagnostics after `didOpen` and after an edit, and
// `textDocument/completion`, `hover` and `semanticTokens/full` at fixed positions of a rule, cold (the
// first request of its kind in a fresh server) and warm (the same request again), plus the payload
// (items, bytes) and the server's memory. Every sample is kept in the output: the summary (p50, p95,
// max) is computed from them.
//
//   node scripts/perf/lsp-bench.mjs --label tier1-native --workspace DIR --runs 15 --out out.json \
//        [--diag pull|push] [--watch on|off] [--doc objects/rules/rule-0001-sentinel-kql.yaml] \
//        [--warm 20] -- <server command> [args...]
//
// The server is the child process; its stdout speaks LSP frames. The client declares what VS Code's
// client records (pytest-lsp's `visual-studio-code`) plus pull diagnostics with refresh support
// (vscode-languageclient's), because the capabilities decide what the server does: a client that
// watches files lets the server keep its caches, one that does not has the disk read again for every
// message.
import { spawn } from 'node:child_process';
import { readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { cpus, totalmem } from 'node:os';
import { join, resolve } from 'node:path';
import { performance } from 'node:perf_hooks';
import { pathToFileURL } from 'node:url';
import { Worker } from 'node:worker_threads';

const argv = process.argv.slice(2);
const sep = argv.indexOf('--');
const opts = { runs: 10, warm: 10, pause: 0, wspull: 'auto', diag: 'pull', watch: 'on', doc: 'objects/rules/rule-0001-sentinel-kql.yaml', label: 'run', timeout: 120 };
const flags = sep < 0 ? argv : argv.slice(0, sep);
for (let i = 0; i < flags.length; i += 2) opts[flags[i].replace(/^--/, '')] = flags[i + 1];
const command = sep < 0 ? [] : argv.slice(sep + 1);
const worker = opts.worker; // a worker_threads transport (the browser engine's node build), instead of a process
if (!opts.workspace || (command.length === 0 && !worker)) {
  console.error('usage: lsp-bench.mjs --workspace DIR [--runs N --warm N --label L --out FILE --diag pull|push --watch on|off --doc REL] -- cmd args...');
  process.exit(2);
}
const workspace = resolve(opts.workspace);
const runs = Number(opts.runs);
const warmCount = Number(opts.warm);
const capsPath = process.env.LSP_BENCH_CAPS || join(import.meta.dirname, 'vscode-caps.json');
const baseCaps = JSON.parse(readFileSync(capsPath, 'utf8'));

function capabilities() {
  const caps = structuredClone(baseCaps);
  caps.workspace.didChangeWatchedFiles = opts.watch === 'on' ? { dynamicRegistration: true } : undefined;
  caps.workspace.workspaceFolders = true;
  caps.workspace.configuration = true;
  caps.workspace.semanticTokens = { refreshSupport: true };
  caps.workspace.inlayHint = { refreshSupport: true };
  caps.workspace.codeLens = { refreshSupport: true };
  if (opts.diag === 'pull') {
    caps.textDocument.diagnostic = { dynamicRegistration: true, relatedDocumentSupport: true };
    caps.workspace.diagnostics = { refreshSupport: true };
  }
  caps.textDocument.publishDiagnostics = { relatedInformation: true, versionSupport: false, codeDescriptionSupport: true, tagSupport: { valueSet: [1, 2] } };
  caps.textDocument.completion = {
    dynamicRegistration: true,
    contextSupport: true,
    completionItem: {
      snippetSupport: true,
      commitCharactersSupport: true,
      documentationFormat: ['markdown', 'plaintext'],
      deprecatedSupport: true,
      preselectSupport: true,
      insertReplaceSupport: true,
      resolveSupport: { properties: ['documentation', 'detail', 'additionalTextEdits'] },
    },
    completionList: { itemDefaults: ['commitCharacters', 'editRange', 'insertTextFormat', 'insertTextMode', 'data'] }, // vscode-languageclient 10.1: completion.js
  };
  caps.textDocument.hover = { dynamicRegistration: true, contentFormat: ['markdown', 'plaintext'] };
  caps.textDocument.semanticTokens = {
    dynamicRegistration: true,
    tokenTypes: [], tokenModifiers: [], formats: ['relative'],
    requests: { range: true, full: { delta: true } },
  };
  return caps;
}

// ---------------------------------------------------------------------------
// Transports: a child process speaking Content-Length frames, or a worker_threads Worker with one
// message per JSON-RPC message (what the extension's engine tier does).

function frameReader(onMessage) {
  let buf = Buffer.alloc(0);
  return (chunk) => {
    buf = buf.length === 0 ? chunk : Buffer.concat([buf, chunk]);
    for (;;) {
      const headerEnd = buf.indexOf('\r\n\r\n');
      if (headerEnd < 0) return;
      const header = buf.subarray(0, headerEnd).toString('ascii');
      const m = /content-length:\s*(\d+)/i.exec(header);
      if (!m) throw new Error(`bad LSP header: ${header}`);
      const len = Number(m[1]);
      if (buf.length < headerEnd + 4 + len) return;
      const body = buf.subarray(headerEnd + 4, headerEnd + 4 + len);
      buf = buf.subarray(headerEnd + 4 + len);
      onMessage(JSON.parse(body.toString('utf8')), len);
    }
  };
}

function startProcess(onMessage) {
  const child = spawn(command[0], command.slice(1), { cwd: workspace, stdio: ['pipe', 'pipe', 'pipe'], env: { ...process.env } });
  const stderr = [];
  child.stderr.on('data', (d) => stderr.push(d));
  child.stdout.on('data', frameReader(onMessage));
  child.on('error', (e) => { throw e; });
  return {
    pid: child.pid,
    send(msg) {
      const body = Buffer.from(JSON.stringify(msg), 'utf8');
      child.stdin.write(`Content-Length: ${body.length}\r\n\r\n`);
      child.stdin.write(body);
    },
    kill() { child.kill('SIGKILL'); },
    exited: new Promise((r) => child.on('exit', r)),
    stderr: () => Buffer.concat(stderr).toString('utf8'),
    pids: () => processTree(child.pid),
  };
}

function startWorker(onMessage) {
  // The engine's worker (scripts/perf/engine-worker.mjs): JSON text per message, as the extension posts it.
  const w = new Worker(resolve(worker), { workerData: { module: opts.module, glue: opts.glue } });
  w.on('message', (m) => {
    const text = typeof m === 'string' ? m : JSON.stringify(m);
    onMessage(JSON.parse(text), Buffer.byteLength(text));
  });
  w.on('error', (e) => { console.error('worker error', e); });
  return {
    pid: process.pid,
    send(msg) { w.postMessage(JSON.stringify(msg)); },
    kill() { w.terminate(); },
    exited: new Promise((r) => w.on('exit', r)),
    stderr: () => '',
    pids: () => [process.pid],
  };
}

// A host with no filesystem is given the workspace on `initialize` (the extension's feed:
// src/engine/feed.ts): the object files under objects/ and visibility.toml.
function suppliedWorkspace() {
  const documents = [];
  const walk = (dir) => {
    for (const e of readdirSync(dir, { withFileTypes: true })) {
      const p = join(dir, e.name);
      if (e.isDirectory()) walk(p);
      else if (/\.ya?ml$/i.test(e.name)) documents.push({ uri: pathToFileURL(p).href, text: readFileSync(p, 'utf8') });
    }
  };
  walk(join(workspace, 'objects'));
  documents.sort((a, b) => (a.uri < b.uri ? -1 : 1));
  let visibility;
  try { visibility = readFileSync(join(workspace, '.opentide/configurations/visibility.toml'), 'utf8'); } catch { /* none */ }
  return { documents, ...(visibility !== undefined ? { visibility } : {}) };
}

function processTree(root) {
  const out = [root];
  try {
    const all = readdirSync('/proc').filter((n) => /^\d+$/.test(n));
    const parent = new Map();
    for (const pid of all) {
      try {
        const stat = readFileSync(`/proc/${pid}/stat`, 'utf8');
        parent.set(Number(pid), Number(stat.slice(stat.lastIndexOf(')') + 2).split(' ')[1]));
      } catch { /* gone */ }
    }
    for (let grew = true; grew;) {
      grew = false;
      for (const [pid, ppid] of parent) if (out.includes(ppid) && !out.includes(pid)) { out.push(pid); grew = true; }
    }
  } catch { /* not Linux */ }
  return out;
}

function rssMiB(pids) {
  let rss = 0, hwm = 0;
  for (const pid of pids) {
    try {
      const s = readFileSync(`/proc/${pid}/status`, 'utf8');
      rss += Number(/VmRSS:\s+(\d+)/.exec(s)?.[1] ?? 0);
      hwm += Number(/VmHWM:\s+(\d+)/.exec(s)?.[1] ?? 0);
    } catch { /* gone */ }
  }
  return { rss: rss / 1024, hwm: hwm / 1024 };
}

// ---------------------------------------------------------------------------
// The scenarios: positions found in the opened rule by their text, so a fixture that changes a line
// moves them with it.

function at(text, anchor, delta = 0) {
  const i = text.indexOf(anchor);
  if (i < 0) throw new Error(`anchor not found in ${opts.doc}: ${JSON.stringify(anchor)}`);
  return position(text, i + delta);
}
function position(text, offset) {
  const before = text.slice(0, offset);
  const line = before.split('\n').length - 1;
  const character = offset - (before.lastIndexOf('\n') + 1); // ASCII fixtures: UTF-16 units = chars
  return { line, character };
}

// Each scenario may type into the rule first (`edit` replaces the text between two anchors), so the
// cursor sits where a user pressing Ctrl+Space is: at the end of `| ` or `where `, on a new key line.
function scenarios(text) {
  const swap = (from, to) => {
    if (!text.includes(from)) throw new Error(`anchor not found in ${opts.doc}: ${JSON.stringify(from)}`);
    return text.replace(from, to);
  };
  const pipe = swap('      | take 1\n', '      | \n');
  const where = swap('      | where EventID == 4688\n      | take 1\n', '      | where \n');
  const topKey = swap('status: STAGING\nseverity', 'status: STAGING\n\nseverity');
  const block = swap('    enabled: true\n', '    enabled: true\n    \n');
  const technique = swap('  - T1059\n', '  - T10\n');
  return [
    { name: 'completion:kql-after-pipe', method: 'textDocument/completion', text: pipe, pos: at(pipe, '      | \n', 8), trigger: ' ' },
    { name: 'completion:kql-after-where', method: 'textDocument/completion', text: where, pos: at(where, '      | where \n', 14), trigger: ' ' },
    { name: 'completion:yaml-top-key', method: 'textDocument/completion', text: topKey, pos: at(topKey, 'status: STAGING\n\n', 16) },
    { name: 'completion:platform-block-key', method: 'textDocument/completion', text: block, pos: at(block, '    enabled: true\n    \n', 18 + 4) },
    { name: 'completion:attack-technique', method: 'textDocument/completion', text: technique, pos: at(technique, '  - T10', 7) },
    { name: 'hover:kql-column', method: 'textDocument/hover', pos: at(text, 'EventID', 3) },
    { name: 'hover:yaml-key', method: 'textDocument/hover', pos: at(text, 'severity:', 3) },
    { name: 'semanticTokens/full', method: 'textDocument/semanticTokens/full', pos: null },
  ];
}

// ---------------------------------------------------------------------------

function quantile(xs, q) {
  if (xs.length === 0) return null;
  const s = [...xs].sort((a, b) => a - b);
  const i = (s.length - 1) * q;
  const lo = Math.floor(i), hi = Math.ceil(i);
  return s[lo] + (s[hi] - s[lo]) * (i - lo);
}
const stats = (xs) => ({ n: xs.length, p50: quantile(xs, 0.5), p95: quantile(xs, 0.95), max: xs.length ? Math.max(...xs) : null, min: xs.length ? Math.min(...xs) : null });
const round = (x) => (x === null || x === undefined ? x : Math.round(x * 100) / 100);

async function oneRun(runIndex) {
  const docPath = join(workspace, opts.doc);
  const text = readFileSync(docPath, 'utf8');
  const uri = pathToFileURL(docPath).href;
  const rootUri = pathToFileURL(workspace).href;
  const waiting = new Map(); // id -> { resolve, t0 }
  let nextId = 1;
  let publish = null; // resolver for the next publishDiagnostics of the document
  let lastBytes = 0;
  const logs = [];
  const handle = (msg, bytes) => {
    if (msg.id !== undefined && msg.method === undefined) {
      const w = waiting.get(msg.id);
      if (w) { waiting.delete(msg.id); w.resolve({ msg, t1: performance.now(), bytes }); }
      return;
    }
    if (msg.method === 'textDocument/publishDiagnostics' && msg.params.uri === uri && publish) {
      const p = publish; publish = null; p({ msg, t1: performance.now(), bytes });
      return;
    }
    if (msg.method === 'window/logMessage') logs.push(msg.params.message);
    if (msg.id !== undefined && msg.method !== undefined) {
      // A request from the server: answer as an editor would.
      let result = null;
      if (msg.method === 'workspace/configuration') result = (msg.params.items ?? []).map(() => null);
      if (msg.method === 'workspace/workspaceFolders') result = [{ uri: rootUri, name: 'ws' }];
      server.send({ jsonrpc: '2.0', id: msg.id, result });
    }
  };
  const server = worker ? startWorker(handle) : startProcess(handle);
  const request = (method, params) => {
    const id = nextId++;
    const t0 = performance.now();
    return new Promise((resolveP, reject) => {
      const timer = setTimeout(() => reject(new Error(`${method} timed out`)), Number(opts.timeout) * 1000);
      waiting.set(id, { resolve: (r) => { clearTimeout(timer); resolveP({ ...r, ms: r.t1 - t0 }); } });
      server.send({ jsonrpc: '2.0', id, method, params });
    });
  };
  const notify = (method, params) => server.send({ jsonrpc: '2.0', method, params });
  const nextPublish = () => new Promise((r) => { publish = r; });

  const out = { run: runIndex, scenarios: {} };
  const t0 = performance.now();
  const init = await request('initialize', {
    processId: process.pid,
    clientInfo: { name: 'lsp-bench', version: '1' },
    rootUri,
    workspaceFolders: [{ uri: rootUri, name: 'ws' }],
    capabilities: capabilities(),
    initializationOptions: worker ? { workspace: suppliedWorkspace() } : undefined,
  });
  // What the server does decides how its diagnostics are read: a client that pulls gets pull
  // diagnostics only from a server that advertises them, else the server pushes.
  const diagMode = opts.diag === 'pull' && init.msg.result?.capabilities?.diagnosticProvider ? 'pull' : 'push';
  out.diag_mode = diagMode;
  out.init_ms = init.ms;
  out.init_bytes = init.bytes;
  out.server = init.msg.result?.serverInfo;
  notify('initialized', {});

  // didOpen, then the first diagnostics: pulled as the extension does, or pushed.
  const tOpen = performance.now();
  const pushed = diagMode === 'push' ? nextPublish() : null;
  notify('textDocument/didOpen', { textDocument: { uri, languageId: 'yaml', version: 1, text } });
  let first;
  if (diagMode === 'pull') {
    first = await request('textDocument/diagnostic', { textDocument: { uri } });
    out.diag_count = first.msg.result?.items?.length ?? 0;
  } else {
    first = await pushed;
    out.diag_count = first.msg.params.diagnostics.length;
  }
  out.first_diag_ms = first.t1 - tOpen;
  out.start_to_first_diag_ms = first.t1 - t0;
  out.diag_bytes = first.bytes;

  // vscode-languageclient pulls workspace diagnostics for a server that advertises them: at start,
  // then 2 s after each answer, for as long as the client runs (diagnostic.js, pullWorkspace). The
  // loop feeds each answer's resultIds back, as the client does.
  const wsPull = { count: 0, ms: [], items: 0 };
  let wsStop = false;
  let wsLoop = Promise.resolve();
  const advertised = init.msg.result?.capabilities?.diagnosticProvider?.workspaceDiagnostics === true;
  if (opts.wspull === 'on' || (opts.wspull === 'auto' && diagMode === 'pull' && advertised)) {
    wsLoop = (async () => {
      let previous = [];
      while (!wsStop) {
        const r = await request('workspace/diagnostic', { previousResultIds: previous }).catch(() => null);
        if (!r) break;
        const items = r.msg.result?.items ?? [];
        wsPull.count += 1; wsPull.ms.push(r.ms); wsPull.items = items.length;
        previous = items.filter((i) => i.resultId).map((i) => ({ uri: i.uri, value: i.resultId }));
        await new Promise((res) => setTimeout(res, 2000));
      }
    })();
  }
  out.workspace_pull = wsPull;
  const sleep = (ms) => new Promise((res) => setTimeout(res, ms));

  let version = 1;
  const edit = async (kind) => {
    // Typing: append a space to the first description line, the way an editor sends one keystroke.
    version += 1;
    const pos = at(text, 'description: |', 'description: |'.length);
    const change = kind === 'del'
      ? { range: { start: { line: pos.line, character: pos.character }, end: { line: pos.line, character: pos.character + 1 } }, text: '' }
      : { range: { start: pos, end: pos }, text: ' ' };
    notify('textDocument/didChange', { textDocument: { uri, version }, contentChanges: [change] });
  };

  // Diagnostics after an edit: didChange, then the next diagnostics.
  out.edit_diag_ms = [];
  for (let i = 0; i < Math.min(warmCount, 5); i += 1) {
    const t = performance.now();
    const pushedNext = diagMode === 'push' ? nextPublish() : null;
    await edit(i % 2 === 0 ? 'add' : 'del');
    const r = diagMode === 'pull' ? await request('textDocument/diagnostic', { textDocument: { uri } }) : await pushedNext;
    out.edit_diag_ms.push(r.t1 - t);
  }
  if ((Math.min(warmCount, 5)) % 2 === 1) await edit('del'); // leave the text as it was

  // Cold: the first request of each kind; warm: the same again; typed: after a keystroke.
  const fullText = async (t) => {
    version += 1;
    notify('textDocument/didChange', { textDocument: { uri, version }, contentChanges: [{ text: t }] });
  };
  for (const sc of scenarios(text)) {
    if (sc.text) await fullText(sc.text);
    const params = sc.pos
      ? {
          textDocument: { uri }, position: sc.pos,
          ...(sc.method === 'textDocument/completion'
            ? { context: sc.trigger ? { triggerKind: 2, triggerCharacter: sc.trigger } : { triggerKind: 1 } }
            : {}),
        }
      : { textDocument: { uri } };
    const sample = async () => {
      const r = await request(sc.method, params);
      const res = r.msg.result;
      const items = Array.isArray(res) ? res.length : (res?.items?.length ?? (res?.data?.length ?? (res ? 1 : 0)));
      return { ms: r.ms, items, bytes: r.bytes, error: r.msg.error?.message };
    };
    const cold = await sample();
    const warm = [];
    for (let i = 0; i < warmCount; i += 1) { warm.push((await sample()).ms); if (Number(opts.pause)) await sleep(Number(opts.pause)); }
    const typed = [];
    if (sc.method === 'textDocument/completion') {
      for (let i = 0; i < Math.min(warmCount, 5); i += 1) {
        await edit(i % 2 === 0 ? 'add' : 'del');
        typed.push((await sample()).ms);
        if (Number(opts.pause)) await sleep(Number(opts.pause));
      }
      if (typed.length % 2 === 1) await edit('del');
    }
    out.scenarios[sc.name] = { cold, warm, typed };
    if (sc.text) await fullText(text);
  }

  // Resolve one completion item (documentation on demand), cold and warm.
  {
    const sc = scenarios(text)[0];
    const r = await request('textDocument/completion', { textDocument: { uri }, position: sc.pos, context: { triggerKind: 2, triggerCharacter: ' ' } });
    const items = Array.isArray(r.msg.result) ? r.msg.result : r.msg.result?.items ?? [];
    if (items.length > 0) {
      const it = await request('completionItem/resolve', items[0]);
      out.resolve_ms = it.ms;
    }
  }

  wsStop = true;
  const mem = rssMiB(server.pids());
  out.rss_mib = mem.rss;
  out.hwm_mib = mem.hwm;
  // Shut down like an editor.
  try {
    await request('shutdown', null);
    notify('exit', null);
    await Promise.race([server.exited, new Promise((r) => setTimeout(r, 3000))]);
  } catch { /* killed below */ }
  server.kill();
  out.stderr_tail = server.stderr().split('\n').slice(-3).join('\n');
  return out;
}

const results = [];
for (let i = 0; i < runs; i += 1) {
  try {
    results.push(await oneRun(i));
  } catch (e) {
    console.error(`run ${i} failed: ${e.message}`);
    results.push({ run: i, error: e.message });
  }
}

const ok = results.filter((r) => !r.error);
const summary = {
  init_ms: stats(ok.map((r) => r.init_ms)),
  first_diag_ms: stats(ok.map((r) => r.first_diag_ms)),
  start_to_first_diag_ms: stats(ok.map((r) => r.start_to_first_diag_ms)),
  edit_diag_ms: stats(ok.flatMap((r) => r.edit_diag_ms)),
  resolve_ms: stats(ok.map((r) => r.resolve_ms).filter((x) => x !== undefined)),
  workspace_pull_ms: stats(ok.flatMap((r) => r.workspace_pull.ms)),
  workspace_pull_items: ok[0]?.workspace_pull.items,
  rss_mib: stats(ok.map((r) => r.rss_mib)),
  hwm_mib: stats(ok.map((r) => r.hwm_mib)),
  diag_count: ok[0]?.diag_count,
  scenarios: {},
};
for (const name of Object.keys(ok[0]?.scenarios ?? {})) {
  const cold = ok.map((r) => r.scenarios[name].cold);
  summary.scenarios[name] = {
    cold: stats(cold.map((c) => c.ms)),
    warm: stats(ok.flatMap((r) => r.scenarios[name].warm)),
    typed: stats(ok.flatMap((r) => r.scenarios[name].typed)),
    items: cold[0]?.items,
    bytes: cold[0]?.bytes,
    error: cold.find((c) => c.error)?.error,
  };
}

const report = {
  label: opts.label,
  command: worker ? [`worker:${worker}`, ...command] : command,
  workspace,
  doc: opts.doc,
  diag: opts.diag,
  watch: opts.watch,
  runs,
  warm: warmCount,
  failed: results.length - ok.length,
  machine: { cpus: cpus().length, model: cpus()[0]?.model, mem_gib: Math.round(totalmem() / 2 ** 30), node: process.version, platform: process.platform },
  when: new Date().toISOString(),
  summary,
  raw: results,
};
if (opts.out) writeFileSync(opts.out, JSON.stringify(report, null, 1));

const f = (x) => (x === null || x === undefined ? '    -' : x.toFixed(1).padStart(7));
console.log(`\n== ${opts.label}  (${report.machine.cpus} cpus, ${runs} runs, ${results.length - ok.length} failed, diag=${ok[0]?.diag_mode ?? opts.diag} watch=${opts.watch})`);
console.log(`init ms           p50 ${f(summary.init_ms.p50)}  p95 ${f(summary.init_ms.p95)}  max ${f(summary.init_ms.max)}`);
console.log(`first diag ms     p50 ${f(summary.first_diag_ms.p50)}  p95 ${f(summary.first_diag_ms.p95)}  max ${f(summary.first_diag_ms.max)}   (${summary.diag_count} diagnostics)`);
console.log(`edit->diag ms     p50 ${f(summary.edit_diag_ms.p50)}  p95 ${f(summary.edit_diag_ms.p95)}  max ${f(summary.edit_diag_ms.max)}`);
console.log(`workspace/diag ms  p50 ${f(summary.workspace_pull_ms.p50)}  p95 ${f(summary.workspace_pull_ms.p95)}  max ${f(summary.workspace_pull_ms.max)}   (${summary.workspace_pull_items ?? '-'} items, ${summary.workspace_pull_ms.n} pulls)`);
console.log(`rss MiB           p50 ${f(summary.rss_mib.p50)}  max ${f(summary.rss_mib.max)}`);
console.log('scenario'.padEnd(34), 'cold p50    p95    max |  warm p50    p95    max | typed p50   p95 | items   bytes');
for (const [name, s] of Object.entries(summary.scenarios)) {
  console.log(
    name.padEnd(34), f(s.cold.p50), f(s.cold.p95), f(s.cold.max), '|', f(s.warm.p50), f(s.warm.p95), f(s.warm.max), '|', f(s.typed.p50), f(s.typed.p95), '|',
    String(s.items ?? '-').padStart(5), String(s.bytes ?? '-').padStart(8), s.error ? `ERR ${s.error}` : '',
  );
}
process.exit(0);
