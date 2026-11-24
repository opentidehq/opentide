// The Tide grammar's colours are the server's (#1809): for every construct of
// a representative rule, the grammar's last TextMate scope is one the theme
// resolves like a scope of the semantic token type the server sends for the
// same text (`semantic-token-scopes.json`: the opentide-yaml
// `semanticTokenScopes` of the VS Code extension, copied), so nothing
// recolours when the server's tokens land. The server's types for these rows
// are checked against the server itself by crates/opentide-analysis/tests/
// tide_alignment.rs, from the same fixture. A key's colon and a list dash get
// no semantic token, so their scopes are YAML punctuation.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import textmate from 'vscode-textmate';
import { grammarFor } from './coverage.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const fixtures = join(here, 'fixtures');
const typeScopes = JSON.parse(readFileSync(join(fixtures, 'semantic-token-scopes.json'), 'utf8')).scopes;
const alignment = JSON.parse(readFileSync(join(fixtures, 'tide-alignment.json'), 'utf8'));
const yaml = readFileSync(join(fixtures, alignment.yaml), 'utf8');

/** Whether `scope` is one a theme resolves like one of the scopes `type` maps to. */
const underType = (scope, type) =>
  typeScopes[type].some((mapped) => scope === mapped || scope.startsWith(`${mapped}.`));

const grammar = await grammarFor('tide');
let state = textmate.INITIAL;
const lines = yaml.split('\n').map((line) => {
  const result = grammar.tokenizeLine(line, state);
  state = result.ruleStack;
  return {
    line,
    tokens: result.tokens.map((t) => ({ ...t, text: line.slice(t.startIndex, t.endIndex), scopes: t.scopes.slice(1) })),
  };
});

/** The token covering the first `text` of the first line that contains `row`. */
function tokenAt(row, text) {
  const hit = lines.find(({ line }) => line.includes(row));
  assert.ok(hit, `no line contains ${JSON.stringify(row)}`);
  const offset = hit.line.indexOf(text);
  assert.ok(offset >= 0, `${JSON.stringify(row)} has no ${JSON.stringify(text)}`);
  const token = hit.tokens.find((t) => t.startIndex <= offset && offset < t.endIndex);
  assert.ok(token, `no token at ${offset} of ${JSON.stringify(hit.line)}`);
  return token;
}

for (const { row, text, type } of alignment.tokens) {
  test(`${JSON.stringify(text)} (${type}): the grammar's last scope is under the type's scopes`, () => {
    const token = tokenAt(row, text);
    const last = token.scopes.at(-1);
    assert.ok(underType(last, type), `${JSON.stringify(token.text)}: ${token.scopes.join(' ')} is not under ${typeScopes[type].join(', ')}`);
  });
}

for (const { row, text, scope } of alignment.punctuation) {
  test(`${JSON.stringify(text)} in ${JSON.stringify(row)} is ${scope} (the server sends no token)`, () => {
    const token = tokenAt(row, text);
    assert.equal(token.text, text);
    assert.ok(token.scopes.some((s) => s === scope || s.startsWith(`${scope}.`)), token.scopes.join(' '));
  });
}

test('every scope of the generated Tide grammar for a server construct is under some type', () => {
  const all = [];
  const walk = (rule) => {
    if (Array.isArray(rule)) return rule.forEach(walk);
    if (!rule || typeof rule !== 'object') return;
    for (const key of ['name', 'contentName']) if (typeof rule[key] === 'string') all.push([rule.comment, rule[key]]);
    for (const captures of [rule.captures, rule.beginCaptures, rule.endCaptures]) {
      for (const capture of Object.values(captures ?? {})) walk(capture);
    }
    walk(rule.patterns);
  };
  walk(JSON.parse(readFileSync(join(here, '..', 'generated', 'tide.tmLanguage.json'), 'utf8')).patterns);
  const free = /^(?:punctuation\.|meta\.embedded\.|string\.quoted\.yaml)/;
  const types = Object.keys(typeScopes);
  const stray = all.filter(([, scope]) => scope.split(' ').every((s) => !free.test(s)) && !types.some((t) => underType(scope, t)));
  assert.deepEqual(stray, []);
});
