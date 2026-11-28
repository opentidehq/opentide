// EQL oracle: Elasticsearch's EqlBase.g4 (ELv2), generated with antlr-ng at
// CI time only. The grammar has no actions, so the parser is exact.
// Usage: node eql.mjs <generated dir> <antlr4 runtime dir> <dir of .eql files>
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
const [gen, runtime, dir] = process.argv.slice(2);
const { default: Lexer } = await import(pathToFileURL(path.join(gen, 'EqlBaseLexer.js')));
const { default: Parser } = await import(pathToFileURL(path.join(gen, 'EqlBaseParser.js')));
const antlr4 = (await import(pathToFileURL(path.join(runtime, 'dist', 'antlr4.node.mjs')))).default;
for (const f of fs.readdirSync(dir).filter((f) => f.endsWith('.eql')).sort()) {
  const errors = [];
  const listener = {
    syntaxError: (_r, _s, line, col, msg) => errors.push(`${line}:${col + 1} ${msg}`),
    reportAmbiguity() {}, reportAttemptingFullContext() {}, reportContextSensitivity() {},
  };
  const lexer = new Lexer(new antlr4.InputStream(fs.readFileSync(path.join(dir, f), 'utf8')));
  lexer.removeErrorListeners(); lexer.addErrorListener(listener);
  const parser = new Parser(new antlr4.CommonTokenStream(lexer));
  parser.removeErrorListeners(); parser.addErrorListener(listener);
  parser.singleStatement();
  console.log(errors.length ? `${f}\tERR\t${errors[0].replace(/\s+/g, ' ')}` : `${f}\tOK\t`);
}
