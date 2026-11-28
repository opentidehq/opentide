// Runs a WASI (preview 1) module under Node's own WASI, as wasmtime would
// run it (packages/wasi-host's tests use it): the host's root is the guest's root, the
// environment is passed in whole, and the module's exit code is this
// process's. A local stand-in for wasmtime, not a host for users.
//
//   node --no-turbo-fast-api-calls scripts/engine/wasi-run.mjs [--poll-oneoff=vscode] <module.wasm> [args...]
//
// --no-turbo-fast-api-calls: Node 22's fast WASI calls can start a garbage
// collection inside a call, which crashes once the instance holds enough
// memory (scripts/engine/build-wasm.sh runs its smoke test the same way).
//
// --poll-oneoff=vscode answers `poll_oneoff` as VS Code's WASI host
// (@vscode/wasm-wasi-core 1.0.x) does: every subscription at once, whether or
// not its stream has bytes, a clock's as fired and a pipe's `fd_read` with
// `nosys` (its pipe driver has no `fd_bytesAvailable`). The language server's
// tests run under it: a host that says nothing true about stdin must not
// make the server wait for input (crates/opentide-lsp/src/stdin.rs).
import { readFileSync } from 'node:fs';
import { WASI } from 'node:wasi';

const argv = process.argv.slice(2);
const vscodePoll = argv[0] === '--poll-oneoff=vscode';
if (vscodePoll) argv.shift();
const [module, ...args] = argv;
if (!module) {
  console.error('usage: wasi-run.mjs [--poll-oneoff=vscode] <module.wasm> [args...]');
  process.exit(2);
}
const wasi = new WASI({
  version: 'preview1',
  args: ['opentide', ...args],
  env: process.env,
  preopens: { '/': '/' },
  returnOnExit: true,
});
const imports = wasi.getImportObject();
let memory;
if (vscodePoll) {
  /** WASI's `errno` `nosys`, and the layouts of `subscription` (48 bytes) and `event` (32). */
  const NOSYS = 52;
  const CLOCK = 0;
  imports.wasi_snapshot_preview1.poll_oneoff = (input, output, count, written) => {
    const view = new DataView(memory.buffer);
    for (let i = 0; i < count; i += 1) {
      const subscription = input + i * 48;
      const event = output + i * 32;
      const type = view.getUint8(subscription + 8);
      view.setBigUint64(event, view.getBigUint64(subscription, true), true); // userdata
      view.setUint16(event + 8, type === CLOCK ? 0 : NOSYS, true); // error
      view.setUint8(event + 10, type); // type
      view.setBigUint64(event + 16, 0n, true); // fd_readwrite.nbytes
      view.setUint16(event + 24, 0, true); // fd_readwrite.flags
    }
    view.setUint32(written, count, true);
    return 0;
  };
}
const instance = await WebAssembly.instantiate(
  await WebAssembly.compile(readFileSync(module)),
  imports,
);
memory = instance.exports.memory;
process.exitCode = wasi.start(instance);
