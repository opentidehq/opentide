#!/usr/bin/env node
// Writes a fixed LSP session to stdout, for profilers that wrap the server (callgrind, perf):
//   node lsp-script.mjs WORKSPACE DOC SCENARIO | valgrind --tool=callgrind opentide-lsp --stdio
// SCENARIO: wspull (three workspace/diagnostic pulls), edit (typing + document diagnostics),
//           editpull (a keystroke, then a workspace pull), complete (completion, hover and tokens at fixed positions, repeated).
import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const [wsArg, doc = 'objects/rules/rule-0001-sentinel-kql.yaml', scenario = 'wspull', reps = '3'] = process.argv.slice(2);
const ws = resolve(wsArg);
const caps = JSON.parse(readFileSync(join(import.meta.dirname, 'vscode-caps.json'), 'utf8'));
caps.workspace.didChangeWatchedFiles = { dynamicRegistration: true };
caps.workspace.workspaceFolders = true;
caps.workspace.diagnostics = { refreshSupport: true };
caps.textDocument.diagnostic = { dynamicRegistration: true };
const rootUri = pathToFileURL(ws).href;
const file = join(ws, doc);
const uri = pathToFileURL(file).href;
const text = readFileSync(file, 'utf8');
let id = 0;
const out = (m) => { const b = Buffer.from(JSON.stringify(m)); process.stdout.write(`Content-Length: ${b.length}\r\n\r\n`); process.stdout.write(b); };
const req = (method, params) => out({ jsonrpc: '2.0', id: ++id, method, params });
const note = (method, params) => out({ jsonrpc: '2.0', method, params });
const pos = (anchor, d) => { const i = text.indexOf(anchor) + d; const before = text.slice(0, i); return { line: before.split('\n').length - 1, character: i - (before.lastIndexOf('\n') + 1) }; };

req('initialize', { processId: process.pid, rootUri, workspaceFolders: [{ uri: rootUri, name: 'ws' }], capabilities: caps });
note('initialized', {});
note('textDocument/didOpen', { textDocument: { uri, languageId: 'yaml', version: 1, text } });
req('textDocument/diagnostic', { textDocument: { uri } });
const n = Number(reps);
for (let i = 0; i < n; i += 1) {
  if (scenario === 'wspull') req('workspace/diagnostic', { previousResultIds: [] });
  if (scenario === 'edit') {
    const p = pos('description: |', 14);
    note('textDocument/didChange', { textDocument: { uri, version: 2 + i }, contentChanges: [{ range: { start: p, end: p }, text: ' ' }] });
    req('textDocument/diagnostic', { textDocument: { uri } });
  }
  if (scenario === 'editpull') {
    const p = pos('description: |', 14);
    note('textDocument/didChange', { textDocument: { uri, version: 2 + i }, contentChanges: [{ range: { start: p, end: p }, text: ' ' }] });
    req('workspace/diagnostic', { previousResultIds: [] });
  }
  if (scenario === 'complete') {
    req('textDocument/completion', { textDocument: { uri }, position: pos('  - T1059', 7), context: { triggerKind: 1 } });
    req('textDocument/completion', { textDocument: { uri }, position: pos('    enabled: true', 4), context: { triggerKind: 1 } });
    req('textDocument/hover', { textDocument: { uri }, position: pos('EventID', 3) });
    req('textDocument/semanticTokens/full', { textDocument: { uri } });
  }
}
req('shutdown', null);
note('exit', null);
