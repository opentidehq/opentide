// The generated Tide grammar embeds the query languages whose path fixes the
// language (#171): a KQL token inside `configurations.sentinel.query: |`
// carries both the embedded region and a KQL scope. Elastic queries, whose
// language depends on sibling keys, get no region.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import oniguruma from 'vscode-oniguruma';
import textmate from 'vscode-textmate';

const here = dirname(fileURLToPath(import.meta.url));
const generated = join(here, '..', 'generated');
const require = createRequire(import.meta.url);
const wasm = readFileSync(require.resolve('vscode-oniguruma/release/onig.wasm')).buffer;
await oniguruma.loadWASM(wasm);

const files = {
  'source.opentide-yaml': 'tide.tmLanguage.json',
  'source.kql': 'kql.tmLanguage.json',
  'source.spl': 'spl.tmLanguage.json',
  'source.lucene': 'lucene.tmLanguage.json',
  'source.esql': 'esql.tmLanguage.json',
  'source.eql': 'eql.tmLanguage.json',
  'source.kuery': 'kuery.tmLanguage.json',
};
const registry = new textmate.Registry({
  onigLib: Promise.resolve({
    createOnigScanner: (patterns) => new oniguruma.OnigScanner(patterns),
    createOnigString: (s) => new oniguruma.OnigString(s),
  }),
  loadGrammar: async (scope) => {
    const file = files[scope];
    if (!file) return null;
    return textmate.parseRawGrammar(readFileSync(join(generated, file), 'utf8'), join(generated, file));
  },
});
const tide = await registry.loadGrammar('source.opentide-yaml');

/** Every token of `text`, as `[text, scopes]`. */
function tokens(text) {
  let stack = textmate.INITIAL;
  const out = [];
  for (const line of text.split('\n')) {
    const result = tide.tokenizeLine(line, stack);
    for (const t of result.tokens) out.push([line.slice(t.startIndex, t.endIndex), t.scopes]);
    stack = result.ruleStack;
  }
  return out;
}

const scopesOf = (all, text) => all.filter(([t]) => t.trim() === text).map(([, s]) => s);

const RULE = `name: Rule
metadata:
  schema: rule::1.0
configurations:
  sentinel:
    query: |
      SecurityEvent
      | where EventID == 4688
  splunk:
    query: index=main | stats count by host
  carbon_black_cloud:
    query: process_name:cmd.exe
  elastic:
    type: query
    language: lucene
    query: process.name:cmd.exe
description: where
`;

test('a KQL block under configurations.sentinel.query is embedded KQL', () => {
  const all = tokens(RULE);
  const where = scopesOf(all, 'where')[0];
  assert.ok(where.includes('meta.embedded.block.kql'), where.join(' '));
  // The KQL grammar's own keyword scope, inside the region.
  assert.ok(where.some((s) => s.startsWith('keyword.')), where.join(' '));
});

test('a plain SPL scalar and a Carbon Black query are embedded too', () => {
  const all = tokens(RULE);
  const stats = scopesOf(all, 'stats')[0];
  assert.ok(stats.includes('meta.embedded.block.spl'), stats.join(' '));
  const cmd = all.find(([t, s]) => t.includes('process_name') && s.includes('meta.embedded.block.lucene'));
  assert.ok(cmd, 'carbon_black_cloud.query is embedded Lucene');
});

test('Elastic queries and text after the block get no region', () => {
  const all = tokens(RULE);
  const elastic = all.filter(([t]) => t.includes('process.name'));
  assert.ok(elastic.length > 0);
  for (const [, scopes] of elastic) {
    assert.ok(!scopes.some((s) => s.startsWith('meta.embedded')), scopes.join(' '));
  }
  // `description: where` is YAML again.
  const last = scopesOf(all, 'where').at(-1);
  assert.ok(!last.some((s) => s.startsWith('meta.embedded')), last.join(' '));
});

test('package-contributions.json maps each region to its language id', () => {
  const contributions = JSON.parse(readFileSync(join(generated, 'package-contributions.json'), 'utf8'));
  const grammar = contributions.contributes.grammars.find((g) => g.scopeName === 'source.opentide-yaml');
  assert.deepEqual(grammar.embeddedLanguages, {
    'meta.embedded.block.kql': 'kql',
    'meta.embedded.block.spl': 'spl',
    'meta.embedded.block.lucene': 'lucene',
  });
});
