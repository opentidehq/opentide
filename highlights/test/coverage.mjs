// How much of each language's real query text the generated TextMate grammar
// leaves in the default foreground (#PR2): the share of word-like tokens whose
// scope stack is only the grammar's root scope, over the external conformance
// corpus (valid files only). Not a test: `node coverage.mjs [--max 0.30]`
// prints the table and, with --max, exits 1 when a language is over it.
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import oniguruma from 'vscode-oniguruma';
import textmate from 'vscode-textmate';

const here = dirname(fileURLToPath(import.meta.url));
const generated = join(here, '..', 'generated');
const corpus = join(here, '..', '..', 'crates', 'testdata', 'conformance', 'external');
const require = createRequire(import.meta.url);
await oniguruma.loadWASM(readFileSync(require.resolve('vscode-oniguruma/release/onig.wasm')).buffer);

export const LANGS = {
  kql: ['source.kql', 'kql', ['kql']],
  esql: ['source.opentide.esql', 'esql', ['esql']],
  eql: ['source.eql', 'eql', ['eql']],
  spl: ['source.spl', 'spl', ['spl']],
  lucene: ['source.lucene', 'lucene', ['lucene', 'lucene-carbon-black']],
  kuery: ['source.kuery', 'kuery', ['kuery-opensearch-dashboards']],
  cql: ['source.opentide.cql', 'cql', ['cql']],
  falco: ['source.falco', 'falco', ['falco']],
  exabeam: ['source.exabeam', 'exabeam', ['exabeam']],
  yara: ['source.opentide.yara', 'yara', ['yara']],
  yaral: ['source.yaral', 'yaral', ['yaral']],
};
const scopeFile = Object.fromEntries(Object.values(LANGS).map(([s, f]) => [s, `${f}.tmLanguage.json`]));
const registry = new textmate.Registry({
  onigLib: Promise.resolve({
    createOnigScanner: (p) => new oniguruma.OnigScanner(p),
    createOnigString: (s) => new oniguruma.OnigString(s),
  }),
  loadGrammar: async (scope) => {
    const file = scopeFile[scope];
    return file ? textmate.parseRawGrammar(readFileSync(join(generated, file), 'utf8'), file) : null;
  },
});

function* files(dir) {
  for (const name of readdirSync(dir).sort()) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) yield* files(p);
    else if (!name.includes('.broken.') && /\.(kql|esql|eql|spl|lucene|falco|exabeam|cql|yara|yar|yaral|yl2)$/.test(name)) yield p;
  }
}

function texts(lang, dirs) {
  if (lang === 'kuery') {
    const tsv = readFileSync(join(corpus, dirs[0], 'cases.tsv'), 'utf8').split('\n');
    return tsv.filter((l) => l.startsWith('accept\t')).map((l) => JSON.parse(l.split('\t')[1]));
  }
  return dirs.flatMap((d) => [...files(join(corpus, d))].map((p) => readFileSync(p, 'utf8')));
}

const WORD = /^[A-Za-z_#@$][\w.\-]*$|^[0-9]/;
export const grammarFor = (lang) => registry.loadGrammar(LANGS[lang][0]);

export async function measure(lang) {
  const [, , dirs] = LANGS[lang];
  const grammar = await grammarFor(lang);
  let meaningful = 0;
  let plain = 0;
  const examples = new Map();
  for (const text of texts(lang, dirs)) {
    let stack = textmate.INITIAL;
    for (const line of text.split('\n')) {
      const r = grammar.tokenizeLine(line, stack);
      for (const t of r.tokens) {
        const s = line.slice(t.startIndex, t.endIndex).trim();
        if (!WORD.test(s)) continue;
        meaningful++;
        if (t.scopes.length === 1) {
          plain++;
          examples.set(s, (examples.get(s) ?? 0) + 1);
        }
      }
      stack = r.ruleStack;
    }
  }
  return { meaningful, plain, share: plain / Math.max(meaningful, 1), examples };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const max = process.argv.includes('--max') ? Number(process.argv[process.argv.indexOf('--max') + 1]) : null;
  const only = process.argv.filter((a) => LANGS[a]);
  let over = false;
  for (const lang of only.length ? only : Object.keys(LANGS)) {
    const m = await measure(lang);
    if (max !== null && m.share > max) over = true;
    const top = [...m.examples].sort((a, b) => b[1] - a[1]).slice(0, only.length ? 25 : 0).map(([k, v]) => `${k}×${v}`).join(' ');
    console.log(`${lang.padEnd(8)} ${(m.share * 100).toFixed(0).padStart(3)}%  (${m.plain}/${m.meaningful}) ${top}`);
  }
  if (over) process.exit(1);
}
