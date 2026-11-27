// What each generated query grammar colours on its own, before a language
// server answers: functions, fields, boolean operators, a leading table, the
// SPL ```comment``` form, a block comment over several lines, and that no
// language leaves more than 30% of its real queries in the default foreground
// (`coverage.mjs`). Scopes are the HighlightSpec's, never a colour.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { LANGS, grammarFor, measure } from './coverage.mjs';
import textmate from 'vscode-textmate';

/** `[text, scopes]` of every token of `text` in the grammar of `lang`. */
async function tokens(lang, text) {
  const grammar = await grammarFor(lang);
  let stack = textmate.INITIAL;
  const out = [];
  for (const line of text.split('\n')) {
    const r = grammar.tokenizeLine(line, stack);
    for (const t of r.tokens) out.push([line.slice(t.startIndex, t.endIndex), t.scopes.slice(1).join(' ')]);
    stack = r.ruleStack;
  }
  return out;
}

/** The scope of the first token whose trimmed text is `word`. */
async function scopeOf(lang, text, word) {
  const hit = (await tokens(lang, text)).find(([t]) => t.trim() === word);
  assert.ok(hit, `${lang}: no token ${JSON.stringify(word)} in ${JSON.stringify(await tokens(lang, text))}`);
  return hit[1];
}

const FUNCTION = 'entity.name.function.opentide';
const BUILTIN = 'support.function.opentide';
const PROPERTY = 'variable.other.property.opentide';
const TYPE = 'entity.name.type.opentide';
const LOGICAL = 'keyword.operator.logical.opentide';

const CASES = [
  // [language, text, token, expected scope]
  ['kql', 'SecurityEvent\n| where EventID == 4688', 'EventID', PROPERTY],
  ['kql', 'SecurityEvent\n| where EventID == 4688', 'SecurityEvent', TYPE],
  ['kql', 'T | where tolower(x) == "a"', 'tolower', BUILTIN],
  ['kql', 'T | extend y = my_udf(x)', 'my_udf', FUNCTION],
  ['kql', 'T | where Computer has "a"', 'Computer', PROPERTY],
  ['esql', 'FROM logs-endpoint.* | LIMIT 1', 'logs-endpoint.*', TYPE],
  ['esql', 'FROM logs-a, logs-b | LIMIT 1', 'logs-a, logs-b', TYPE],
  ['esql', 'FROM logs-* | WHERE process.name == "a"', 'process.name', PROPERTY],
  ['esql', 'FROM a | EVAL x = TO_LOWER(b)', 'TO_LOWER', BUILTIN],
  ['eql', 'process where process.name == "cmd.exe"', 'process.name', PROPERTY],
  ['eql', 'process where length(a) > 1', 'length', BUILTIN],
  ['spl', 'index=main | stats count(x) by host', 'index', PROPERTY],
  ['spl', 'index=main | eval a=coalesce(b, c)', 'coalesce', FUNCTION],
  ['kuery', 'process.name:cmd.exe and not user.id:1', 'process.name', PROPERTY],
  ['kuery', 'process.name:cmd.exe and not user.id:1', 'and', LOGICAL],
  ['kuery', 'a:1 OR b:2', 'OR', LOGICAL],
  ['lucene', 'process.name:cmd.exe AND NOT user.id:1', 'process.name', PROPERTY],
  ['lucene', 'process.name:cmd.exe AND NOT user.id:1', 'AND', LOGICAL],
  ['lucene', 'a:1 OR b:2', 'OR', LOGICAL],
  ['cql', 'ComputerName=foo and not aid=bar', 'ComputerName', PROPERTY],
  ['cql', 'ComputerName=foo and not aid=bar', 'and', LOGICAL],
  ['cql', 'x | groupBy([aid], function=count())', 'groupBy', BUILTIN],
  ['cql', 'x | array:append(a, b)', 'array:append', BUILTIN],
  ['falco', 'evt.type = execve and proc.name in (a, b)', 'evt.type', PROPERTY],
  ['falco', 'evt.type = execve and proc.name in (a, b)', 'in', 'keyword.operator.opentide'],
  ['exabeam', 'activity_type = "x" AND user = "y"', 'activity_type', PROPERTY],
  ['datadog', 'source:okta AND @evt.outcome:FAILURE', '@evt.outcome', PROPERTY],
  ['datadog', 'source:okta OR @evt.outcome:FAILURE', 'OR', LOGICAL],
  ['datadog', '@http.status_code:[400 TO 499]', 'TO', 'keyword.control.opentide'],
  ['yaral', 'rule r {\n events:\n  $e.principal.hostname = "h"\n}', '$e.principal.hostname', PROPERTY],
  ['yaral', 'condition: $e and re.regex($e.a, "x")', 're.regex', BUILTIN],
  ['yara', 'rule a { condition: uint16(0) == 0x5A4D and pe.is_dll() }', 'uint16', FUNCTION],
];
for (const [lang, text, word, expected] of CASES) {
  test(`${lang}: ${word} in ${JSON.stringify(text).slice(0, 40)}`, async () => {
    const scope = await scopeOf(lang, text, word);
    assert.ok(scope.split(' ').includes(expected), `${scope} lacks ${expected}`);
  });
}

test('a keyword still beats the call rule: `where (` and `in (` are no calls', async () => {
  for (const [lang, text, word] of [
    ['kql', 'T | where (a == 1)', 'where'],
    ['kql', 'T | where a in (1, 2)', 'in'],
    ['esql', 'FROM a | WHERE (b == 1)', 'WHERE'],
  ]) {
    const scope = await scopeOf(lang, text, word);
    assert.ok(!scope.includes(FUNCTION) && !scope.includes(BUILTIN), `${lang} ${word}: ${scope}`);
  }
});

test('an SPL ```comment``` is a comment, even between pipes', async () => {
  const all = await tokens('spl', 'index=main ```a note, with | pipes``` | stats count');
  const note = all.find(([t]) => t.includes('a note'));
  assert.ok(note && note[1].includes('comment'), JSON.stringify(all));
  const stats = all.find(([t]) => t.trim() === 'stats');
  assert.ok(stats && !stats[1].includes('comment'), JSON.stringify(all));
});

test('a block comment over several lines is a comment on every line', async () => {
  for (const lang of ['esql', 'eql', 'yaral', 'yara']) {
    const all = await tokens(lang, '/* first\nsecond where\nthird */ x');
    for (const piece of ['first', 'second where', 'third']) {
      const hit = all.find(([t]) => t.includes(piece));
      assert.ok(hit && hit[1].includes('comment'), `${lang} ${piece}: ${JSON.stringify(all)}`);
    }
  }
});

test('no language leaves more than 30% of its real queries in the default foreground', async () => {
  for (const lang of Object.keys(LANGS)) {
    const m = await measure(lang);
    assert.ok(m.meaningful > 50, `${lang}: only ${m.meaningful} tokens measured`);
    assert.ok(m.share <= 0.3, `${lang}: ${(m.share * 100).toFixed(1)}% plain (${m.plain}/${m.meaningful})`);
  }
});

test('CQL: `/*` inside a value opens no comment (the engine reads a terminated /* */ only)', async () => {
  const all = await tokens('cql', 'repo.name=docker/* foo=1\ncount(x) | groupBy([a])');
  const comment = all.filter(([, scope]) => scope.includes('comment'));
  assert.deepEqual(comment, [], JSON.stringify(all));
  // The next line is CQL: a function call and a pipe.
  assert.ok((await scopeOf('cql', 'count(x) | groupBy([a])', 'groupBy')).includes('support.function'));
  // The `//` form and a terminated block still start where a token may.
  for (const text of ['x | // note', 'x | /* note */ y', '/* first */ x']) {
    const hit = (await tokens('cql', text)).find(([t]) => t.includes('note') || t.includes('first'));
    assert.ok(hit && hit[1].includes('comment'), `${text}: ${JSON.stringify(await tokens('cql', text))}`);
  }
  // No begin/end rule: an unterminated `/*` at a token start does not run on.
  const next = await tokens('cql', 'x | /* open\ncount(x)');
  assert.ok(!next.find(([t]) => t.includes('count'))[1].includes('comment'), JSON.stringify(next));
});

test('a `/*` inside a regular expression literal is no comment in YARA and YARA-L', async () => {
  for (const [lang, text] of [
    ['yaral', '$e.target.url = /https?:\\/*foo/\n$e.principal.hostname = "h"'],
    ['yara', 'rule a { strings: $r = /ab\\/*c/\ncondition: $r }'],
  ]) {
    const all = await tokens(lang, text);
    assert.deepEqual(all.filter(([, scope]) => scope.includes('comment')), [], `${lang}: ${JSON.stringify(all)}`);
  }
});

test('KQL has no block comment rule that runs on', async () => {
  const all = await tokens('kql', 'T | where a /* b\n| where c == 1');
  const next = all.filter(([t]) => t.includes('c') || t.includes('1') || t.trim() === 'where').slice(-3);
  assert.ok(next.length > 0 && next.every(([, scope]) => !scope.includes('comment')), JSON.stringify(all));
});
