# opentide-analysis

The analysis engine and language server of [opentide](https://opentide.org), compiled for Python. `pip install opentide` installs it; there is nothing to install separately and no extra to name.

It binds the Rust crates [`opentide-analysis`](https://crates.io/crates/opentide-analysis) and [`opentide-lsp`](https://crates.io/crates/opentide-lsp) from [opentidehq/language-server](https://github.com/opentidehq/language-server): KQL, SPL, ES|QL, EQL, Kibana KQL (kuery), Lucene and Tide YAML, analyzed without I/O.

Use it through the `opentide` command:

| Command | What the engine does |
| --- | --- |
| `opentide validate query` | Checks every rule query offline, in its platform's language |
| `opentide validate --deep` | Object validation plus those query checks |
| `opentide lsp check PATH` | The diagnostics an editor shows for a file |
| `opentide lsp start` | Serves the language server protocol on stdio, for editors |

The Python API follows what `opentide` needs and may change in any release. Wheels are built for Linux (glibc and musl), macOS and Windows; each serves CPython 3.10 and later.

Source: [`analysis/`](https://github.com/opentidehq/opentide/tree/development/analysis) in the opentide repository. Licence: EUPL-1.2.
