#!/usr/bin/env node
// The `opentide` command: the same main(argv) as the PyPI console script, in
// this process. Ctrl-C stops the run, which exits 130.
'use strict'
const { main } = require('./index.js')
main(process.argv.slice(2)).then(
  (code) => process.exit(code),
  (error) => {
    process.stderr.write(`opentide: ${error.message}\n`)
    process.exit(1)
  },
)
