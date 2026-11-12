#!/usr/bin/env node
// The `opentide` command: the same main(argv) as the PyPI console script, in
// this process. Ctrl-C stops the run, which exits 130.
'use strict'
const { main } = require('./index.js')
process.exit(main(process.argv.slice(2)))
