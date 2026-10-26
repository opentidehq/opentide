// ES|QL oracle: @elastic/esql's parser (ELv2, installed at CI time only).
// Usage: node esql.cjs <node_modules parent> <dir of .esql files>
// Prints `<file>\tOK|ERR\t<message>` per file.
const { createRequire } = require('module');
const fs = require('fs'), path = require('path');
const { Parser } = createRequire(path.join(process.argv[2], 'package.json'))('@elastic/esql');
const dir = process.argv[3];
for (const f of fs.readdirSync(dir).filter((f) => f.endsWith('.esql')).sort()) {
  const src = fs.readFileSync(path.join(dir, f), 'utf8');
  let message = null;
  try {
    const errs = Parser.parseErrors(src);
    if (errs.length) message = `${errs[0].startLineNumber}:${errs[0].startColumn} ${errs[0].message}`;
  } catch (e) {
    message = `parser crash: ${String((e && e.message) || e)}`;
  }
  console.log(message === null ? `${f}\tOK\t` : `${f}\tERR\t${message.replace(/\s+/g, ' ')}`);
}
