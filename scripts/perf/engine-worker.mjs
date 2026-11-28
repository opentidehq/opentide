// The engine (opentide-wasm, built --target web) in a worker_threads Worker, serving one JSON-RPC
// message per worker message as JSON text: what the VS Code extension's dist/engine/worker.js and
// src/engine/host.ts do (tiers 4 and 5 of the extension's runtimes, and the browser engine's node
// stand-in). workerData: { module: path to opentide_wasm_bg.wasm, glue: path to opentide_wasm.js }.
import { readFileSync } from 'node:fs';
import { parentPort, workerData } from 'node:worker_threads';
import { pathToFileURL } from 'node:url';

const glue = await import(pathToFileURL(workerData.glue).href);
glue.initSync({ module: readFileSync(workerData.module) });
const server = new glue.LanguageServer();
parentPort.on('message', (text) => {
  let replies;
  try {
    replies = server.handle(text);
  } catch (e) {
    parentPort.postMessage(JSON.stringify({ jsonrpc: '2.0', method: 'window/logMessage', params: { type: 1, message: String(e) } }));
    return;
  }
  for (const reply of replies) parentPort.postMessage(reply);
  if (server.closed) parentPort.close();
});
