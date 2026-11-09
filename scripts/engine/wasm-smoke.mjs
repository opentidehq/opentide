// Smoke tests for scripts/engine/build-wasm.sh.
//   imports <wasm>   the browser artifact imports only wasm-bindgen glue
//   browser <js>     wasm-bindgen's nodejs glue: highlight() for every language
//   wasi <wasm>      the CLI under node:wasi: analyze an ES|QL file, then an
//                    LSP session over --stdio (#185 P1.4: no threads there)
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const [mode, file] = process.argv.slice(2);
if (mode === 'imports') {
  const module = new WebAssembly.Module(readFileSync(file));
  const foreign = WebAssembly.Module.imports(module).filter((i) => !i.module.startsWith('__wbindgen'));
  assert.deepEqual(foreign.map((i) => `${i.module}.${i.name}`), [], 'browser artifact has non-wasm-bindgen imports');
  console.log('browser artifact: wasm-bindgen imports only');
} else if (mode === 'browser') {
  const wasm = createRequire(import.meta.url)(file);
  const samples = {
    kql: 'SecurityEvent | where EventID == 4688 | take 1',
    spl: 'index=main | stats count by host',
    esql: 'FROM logs-* /* a /* nested */ b */ | WHERE x == 1',
    eql: 'process where process.name : "cmd.exe"',
    kuery: 'event.category:process and not user.name:SYSTEM',
    lucene: 'event.category:process AND process.name:/power.*/',
    falco: 'spawned_process and container and proc.name in (shell_binaries)',
    cql: '#event_simpleName=ProcessRollup2 | groupBy([aid, ComputerName], function=count())',
  };
  for (const [id, text] of Object.entries(samples)) {
    const result = wasm.highlight(id, new TextEncoder().encode(text));
    assert.ok(result.tokens.length > 0, `${id}: no tokens`);
  }
  assert.ok(wasm.legend().length > 0);
  console.log(`browser artifact: highlight() works for ${Object.keys(samples).join(', ')}`);

  // The language server itself, one JSON-RPC message at a time, as a worker drives it.
  const server = new wasm.LanguageServer();
  let id = 0;
  const send = (method, params, request = true) =>
    server
      .handle(JSON.stringify({ jsonrpc: '2.0', ...(request ? { id: ++id } : {}), method, params }))
      .map((text) => JSON.parse(text));
  const [init] = send('initialize', { processId: null, rootUri: null, capabilities: {} });
  assert.equal(init.result.serverInfo.name, 'opentide-lsp');
  assert.equal(init.result.serverInfo.version, wasm.version());
  send('initialized', {}, false);
  const open = (uri, languageId, text) =>
    send('textDocument/didOpen', { textDocument: { uri, languageId, version: 1, text } }, false).find(
      (m) => m.method === 'textDocument/publishDiagnostics',
    ).params.diagnostics;
  const broken = open('untitled:broken.esql', 'esql', 'FROM logs-* | WEHRE x == 1');
  assert.ok(broken.some((d) => d.code === 'esql_unknown_command'), `language server: ${JSON.stringify(broken)}`);
  assert.deepEqual(open('untitled:q.kql', 'kql', 'SecurityEvent\n| where EventID == 4688\n'), []);
  const at = { textDocument: { uri: 'untitled:q.kql' }, position: { line: 1, character: 3 } };
  const [hover] = send('textDocument/hover', at);
  assert.match(hover.result.contents.value, /where/);
  const [completion] = send('textDocument/completion', { ...at, position: { line: 1, character: 2 } });
  assert.ok(completion.result.some((item) => item.label === 'where'));
  send('shutdown', null);
  send('exit', null, false);
  assert.ok(server.closed);
  console.log('browser artifact: the language server answers initialize, diagnostics, hover and completion');
} else if (mode === 'wasi') {
  const { WASI } = await import('node:wasi');
  const dir = mkdtempSync(join(tmpdir(), 'opentide-wasi-'));
  writeFileSync(join(dir, 'q.esql'), 'FROM logs-* /* a /* nested */ b */ | WEHRE x == 1\n');
  const out = join(dir, 'out.json');
  const { openSync, closeSync } = await import('node:fs');
  const fd = openSync(out, 'w');
  const wasi = new WASI({ version: 'preview1', args: ['opentide-lsp', 'analyze', '/work/q.esql'], preopens: { '/work': dir }, stdout: fd });
  const instance = await WebAssembly.instantiate(await WebAssembly.compile(readFileSync(file)), wasi.getImportObject());
  assert.equal(wasi.start(instance), 0);
  closeSync(fd);
  const codes = JSON.parse(readFileSync(out, 'utf8')).map((d) => d.code);
  assert.ok(codes.includes('esql_unknown_command'), `wasi artifact: ${codes}`);
  console.log(`wasi artifact: analyze works (${codes.join(', ')})`);

  // An LSP session: the frames are on stdin before the server starts, so the
  // sync driver reads them as batches of what is buffered.
  const frame = (body) => {
    const text = JSON.stringify({ jsonrpc: '2.0', ...body });
    return `Content-Length: ${Buffer.byteLength(text)}\r\n\r\n${text}`;
  };
  const uri = 'file:///work/q.esql';
  const session = [
    { id: 1, method: 'initialize', params: { capabilities: {} } },
    { method: 'initialized', params: {} },
    { method: 'textDocument/didOpen', params: { textDocument: { uri, languageId: 'esql', version: 1, text: 'FROM logs-* | WEHRE x == 1\n' } } },
    { id: 2, method: 'textDocument/hover', params: { textDocument: { uri }, position: { line: 0, character: 1 } } },
    { id: 3, method: 'shutdown' },
    { method: 'exit' },
  ].map(frame).join('');
  writeFileSync(join(dir, 'in.lsp'), session);
  const input = openSync(join(dir, 'in.lsp'), 'r');
  const output = openSync(join(dir, 'out.lsp'), 'w');
  const lsp = new WASI({ version: 'preview1', args: ['opentide-lsp', '--stdio'], preopens: { '/work': dir }, stdin: input, stdout: output, returnOnExit: true });
  const server = await WebAssembly.instantiate(await WebAssembly.compile(readFileSync(file)), lsp.getImportObject());
  assert.equal(lsp.start(server), 0, 'exit after shutdown is 0');
  closeSync(input);
  closeSync(output);
  const raw = readFileSync(join(dir, 'out.lsp'), 'utf8');
  const messages = [];
  for (let rest = raw; rest.length > 0; ) {
    const header = rest.match(/^Content-Length: (\d+)\r\n\r\n/i);
    assert.ok(header, `wasi --stdio: not a frame: ${rest.slice(0, 80)}`);
    const start = header[0].length;
    const body = Buffer.from(rest.slice(start)).subarray(0, Number(header[1])).toString('utf8');
    messages.push(JSON.parse(body));
    rest = rest.slice(start + body.length);
  }
  const reply = (id) => messages.find((m) => m.id === id && !m.method);
  assert.equal(reply(1).result.capabilities.positionEncoding, 'utf-16');
  const published = messages.find((m) => m.method === 'textDocument/publishDiagnostics');
  assert.ok(published.params.diagnostics.some((d) => d.code === 'esql_unknown_command'), JSON.stringify(published));
  assert.ok(reply(2), 'hover answered');
  assert.equal(reply(3).result, null);
  console.log(`wasi artifact: --stdio session works (${messages.length} messages)`);
} else {
  throw new Error(`unknown mode ${mode}`);
}
