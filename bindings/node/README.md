# @opentide/opentide

[opentide](https://opentide.org) for Node.js: spec-driven development for agentic detection
engineering. One package is the SDK and the `opentide` command line, as the `opentide` package
is on PyPI: both run the same Rust core, in process.

```js
const { Workspace, runJson } = require('@opentide/opentide')

const ws = Workspace.open('.')
const validation = ws.validate()
for (const issue of validation.report.issues) console.log(issue.code, issue.message)

const tree = runJson(['commands'])
```

```bash
npx @opentide/opentide validate
```

A native package for this machine (`@opentide/opentide-<platform>`) comes with it as an optional
dependency. Documentation: [opentide.org/docs/sdk/typescript](https://opentide.org/docs/sdk/typescript).
