// Kibana KQL oracle: Kibana's grammar.peggy (ELv2/AGPL/SSPL), compiled with
// peggy at CI time only. AST helpers are stubs: this checks syntax only.
// Usage: node kuery.cjs <compiled parser .cjs> <dir of .kuery files>
const fs = require('fs'), path = require('path');
const { parse } = require(path.resolve(process.argv[2]));
const dir = process.argv[3];
const W = '@kuery-wildcard@';
const fn = (name, args) => ({ type: 'function', function: name, arguments: args });
const nodeTypes = {
  function: { buildNode: (name, ...a) => fn(name, a), buildNodeWithArgumentNodes: (name, args) => fn(name, args) },
  literal: { buildNode: (value, isQuoted) => ({ type: 'literal', value, isQuoted: !!isQuoted }) },
  namedArg: { buildNode: (name, value) => ({ type: 'namedArg', name, value }) },
  wildcard: {
    KQL_WILDCARD_SYMBOL: W, wildcardSymbol: W,
    buildNode: (value) => ({ type: 'wildcard', value }),
    isNode: (n) => n && n.type === 'wildcard',
    hasLeadingWildcard: (n) => n.value !== W && n.value.startsWith(W),
  },
};
// The detection engine allows leading wildcards (get_query_filter.ts).
const opts = { helpers: { nodeTypes }, allowLeadingWildcards: true };
for (const f of fs.readdirSync(dir).filter((f) => f.endsWith('.kuery')).sort()) {
  try {
    parse(fs.readFileSync(path.join(dir, f), 'utf8'), opts);
    console.log(`${f}\tOK\t`);
  } catch (e) {
    const at = e.location ? `${e.location.start.line}:${e.location.start.column} ` : '';
    console.log(`${f}\tERR\t${at}${String(e.message).replace(/\s+/g, ' ')}`);
  }
}
