// Runs a WASI (preview 1) module under Node's own WASI, as wasmtime would
// run it for `cargo xtask golden check --runner wasi`
// (OPENTIDE_WASI_RUNTIME=node): the host's root is the guest's root, the
// environment is passed in whole, and the module's exit code is this
// process's. A local stand-in for wasmtime, not a host for users.
//
//   node --no-turbo-fast-api-calls scripts/engine/wasi-run.mjs <module.wasm> [args...]
//
// --no-turbo-fast-api-calls: Node 22's fast WASI calls can start a garbage
// collection inside a call, which crashes once the instance holds enough
// memory (scripts/engine/build-wasm.sh runs its smoke test the same way).
import { readFileSync } from 'node:fs';
import { WASI } from 'node:wasi';

const [module, ...args] = process.argv.slice(2);
if (!module) {
  console.error('usage: wasi-run.mjs <module.wasm> [args...]');
  process.exit(2);
}
const wasi = new WASI({
  version: 'preview1',
  args: ['opentide', ...args],
  env: process.env,
  preopens: { '/': '/' },
  returnOnExit: true,
});
const instance = await WebAssembly.instantiate(
  await WebAssembly.compile(readFileSync(module)),
  wasi.getImportObject(),
);
process.exitCode = wasi.start(instance);
