// The in-editor measurement, run inside VS Code's extension host (scripts/perf/editor/run.mjs starts it
// with @vscode/test-electron): the same positions as scripts/perf/lsp-bench.mjs, through the editor's own
// commands, so the language client, its middleware and VS Code's merge of providers are in the time.
//
//   vscode.executeCompletionItemProvider   completion latency, cold (first of its kind) and warm
//   onDidChangeDiagnostics                 first diagnostics after open, and after an edit
//
// Environment: OPENTIDE_PERF_OUT (result file), OPENTIDE_PERF_DOC, OPENTIDE_PERF_WARM, OPENTIDE_PERF_PAUSE,
// OPENTIDE_PERF_PROC (a substring of the server's command line, for its memory).
const vscode = require('vscode');
const fs = require('node:fs');
const path = require('node:path');
const { performance } = require('node:perf_hooks');

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const env = process.env;
const WARM = Number(env.OPENTIDE_PERF_WARM || 10);
const PAUSE = Number(env.OPENTIDE_PERF_PAUSE || 100);

function posOf(text, offset) {
  const before = text.slice(0, offset);
  const line = before.split('\n').length - 1;
  return new vscode.Position(line, offset - (before.lastIndexOf('\n') + 1));
}
const at = (text, anchor, delta) => {
  const i = text.indexOf(anchor);
  if (i < 0) throw new Error(`anchor not found: ${JSON.stringify(anchor)}`);
  return posOf(text, i + delta);
};

function scenarios(text) {
  const swap = (from, to) => {
    if (!text.includes(from)) throw new Error(`anchor not found: ${JSON.stringify(from)}`);
    return text.replace(from, to);
  };
  const pipe = swap('      | take 1\n', '      | \n');
  const where = swap('      | where EventID == 4688\n      | take 1\n', '      | where \n');
  const topKey = swap('status: STAGING\nseverity', 'status: STAGING\n\nseverity');
  const block = swap('    enabled: true\n', '    enabled: true\n    \n');
  const technique = swap('  - T1059\n', '  - T10\n');
  return [
    { name: 'completion:kql-after-pipe', text: pipe, pos: at(pipe, '      | \n', 8), trigger: ' ' },
    { name: 'completion:kql-after-where', text: where, pos: at(where, '      | where \n', 14), trigger: ' ' },
    { name: 'completion:yaml-top-key', text: topKey, pos: at(topKey, 'status: STAGING\n\n', 16) },
    { name: 'completion:platform-block-key', text: block, pos: at(block, '    enabled: true\n    \n', 22) },
    { name: 'completion:attack-technique', text: technique, pos: at(technique, '  - T10', 7) },
  ];
}

function serverRss() {
  const pattern = env.OPENTIDE_PERF_PROC;
  if (!pattern) return null;
  let rss = 0;
  for (const pid of fs.readdirSync('/proc').filter((n) => /^\d+$/.test(n))) {
    try {
      const cmd = fs.readFileSync(`/proc/${pid}/cmdline`, 'utf8').replace(/\0/g, ' ');
      if (!cmd.includes(pattern)) continue;
      rss += Number(/VmRSS:\s+(\d+)/.exec(fs.readFileSync(`/proc/${pid}/status`, 'utf8'))?.[1] ?? 0) / 1024;
    } catch { /* gone */ }
  }
  return rss;
}

exports.run = async function run() {
  const result = { vscode: vscode.version, scenarios: {}, errors: [] };
  const out = env.OPENTIDE_PERF_OUT;
  const folder = vscode.workspace.workspaceFolders[0].uri.fsPath;
  const file = path.join(folder, env.OPENTIDE_PERF_DOC || 'objects/rules/rule-0001-sentinel-kql.yaml');
  const uri = vscode.Uri.file(file);
  const original = fs.readFileSync(file, 'utf8');
  try {
    const t0 = performance.now();
    const ext = vscode.extensions.getExtension('opentidehq.opentide');
    await ext.activate();
    result.activate_ms = performance.now() - t0;

    // First diagnostics after the document opens: the language server's start is in this when it is not up.
    const changed = (pred) =>
      new Promise((resolve, reject) => {
        const t = setTimeout(() => { d.dispose(); reject(new Error('no diagnostics change within 30 s')); }, 30000);
        const d = vscode.languages.onDidChangeDiagnostics((e) => {
          if (e.uris.some((u) => u.toString() === uri.toString()) && pred()) { clearTimeout(t); d.dispose(); resolve(performance.now()); }
        });
      });
    const tOpen = performance.now();
    const waiting = changed(() => vscode.languages.getDiagnostics(uri).length > 0);
    const doc = await vscode.workspace.openTextDocument(uri);
    const editor = await vscode.window.showTextDocument(doc);
    const tFirst = await waiting;
    result.first_diag_ms = tFirst - tOpen;
    result.first_diag_count = vscode.languages.getDiagnostics(uri).length;
    await sleep(500);

    const whole = () => new vscode.Range(doc.positionAt(0), doc.positionAt(doc.getText().length));
    const setText = async (text) => { await editor.edit((b) => b.replace(whole(), text), { undoStopBefore: false, undoStopAfter: false }); };

    // Diagnostics after an edit: one that breaks the severity (a diagnostic appears) and one that mends
    // it (it goes), as the editor sees them change; an edit that changes none fires no event.
    const base = vscode.languages.getDiagnostics(uri).length;
    const sev = at(original, 'severity: High', 'severity: Hig'.length);
    result.edit_diag_ms = [];
    for (let i = 0; i < Math.min(WARM, 6); i += 1) {
      const breaking = i % 2 === 0;
      const p = changed(() => (breaking ? vscode.languages.getDiagnostics(uri).length > base : vscode.languages.getDiagnostics(uri).length === base)).catch(() => null);
      const t = performance.now();
      if (breaking) await editor.edit((b) => b.delete(new vscode.Range(sev, sev.translate(0, 1))));
      else await editor.edit((b) => b.insert(sev, 'h'));
      const done = await p;
      result.edit_diag_ms.push(done === null ? null : done - t);
    }
    if (doc.getText() !== original) await setText(original);
    await sleep(500);

    const complete = async (sc) => {
      const t = performance.now();
      const list = await vscode.commands.executeCommand('vscode.executeCompletionItemProvider', uri, sc.pos, sc.trigger);
      const ms = performance.now() - t;
      return { ms, items: list?.items?.length ?? 0 };
    };
    for (const sc of scenarios(original)) {
      await setText(sc.text);
      await sleep(50);
      const cold = await complete(sc);
      const warm = [];
      for (let i = 0; i < WARM; i += 1) { warm.push((await complete(sc)).ms); await sleep(PAUSE); }
      const typed = [];
      for (let i = 0; i < Math.min(WARM, 5); i += 1) {
        const pos = at(sc.text, 'description: |', 'description: |'.length);
        if (i % 2 === 0) await editor.edit((b) => b.insert(pos, ' '));
        else await editor.edit((b) => b.delete(new vscode.Range(pos, pos.translate(0, 1))));
        typed.push((await complete(sc)).ms);
        await sleep(PAUSE);
      }
      result.scenarios[sc.name] = { cold: cold.ms, items: cold.items, warm, typed };
      await setText(original);
      await sleep(50);
    }
    result.rss_mib = serverRss();
  } catch (e) {
    result.errors.push(String(e && e.stack || e));
  }
  if (out) fs.writeFileSync(out, JSON.stringify(result, null, 1));
  // Revert the buffer so VS Code exits without a save prompt.
  try { await vscode.commands.executeCommand('workbench.action.revertAndCloseActiveEditor'); } catch { /* ignore */ }
  if (result.errors.length) throw new Error(result.errors.join('\n'));
};
