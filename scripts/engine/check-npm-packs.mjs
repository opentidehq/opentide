// Each npm package packs only its built JavaScript, its declarations and its
// licence files (#167). Run after `npm ci` in each package:
//   node scripts/engine/check-npm-packs.mjs
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const allowed = /^(package\.json|LICENSE|NOTICE|README\.md|dist\/.+\.(js|d\.ts))$/;
for (const name of ['lsp-client', 'lsp-worker']) {
  const cwd = join(root, 'packages', name);
  const out = execFileSync('npm', ['pack', '--dry-run', '--json'], { cwd, encoding: 'utf8' });
  const files = JSON.parse(out)[0].files.map((f) => f.path);
  const stray = files.filter((f) => !allowed.test(f));
  assert.deepEqual(stray, [], `${name} packs ${stray.join(', ')}`);
  assert.ok(files.includes('dist/index.js') && files.includes('dist/index.d.ts'), `${name}: no build`);
  assert.ok(files.includes('LICENSE'), `${name}: no LICENSE`);
  console.log(`${name}: ${files.join(', ')}`);
}
