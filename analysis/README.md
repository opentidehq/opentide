# analysis/: the engine opentide compiles in

The query and Tide object analysis engine and the language server, compiled into the `opentide` package as `opentide._native`. `pip install opentide` installs it: there is no separate package and no extra.

This crate binds [`opentide-analysis`](https://crates.io/crates/opentide-analysis) and [`opentide-lsp`](https://crates.io/crates/opentide-lsp) from [opentidehq/language-server](https://github.com/opentidehq/language-server) with PyO3: KQL, SPL, ES|QL, EQL, Kibana KQL (kuery), Lucene and Tide YAML, analyzed without I/O. Python reaches it only through `src/opentide/analysis.py`.

| Command | What the engine does |
| --- | --- |
| `opentide validate` | Object validation, with every rule query checked offline (the `queries` check): the queries a platform would reject |
| `opentide validate query` | That queries check on its own, for rules or query files (`--file hunting/lsass.kql`) |
| `opentide lint` | The engine's warnings and notes on queries, and Elastic block advisories (the `queries` check) |
| `opentide lsp start` | Serves the language server protocol on stdio, for editors |
| `opentide tui` | The editor's findings for each object, as you browse |

## Building

`hatch_build.py` (a hatchling build hook) runs `cargo build` on this crate whenever a wheel of opentide is built, and puts the library in the wheel as `opentide/_native.abi3.so` (`_native.pyd` on Windows). The extension uses CPython's stable ABI from 3.10, so each wheel is tagged `cp310-abi3-<platform>`.

- `uv sync` builds an editable install with the `develop` profile (no link-time optimisation) and copies the module to `src/opentide/`. It rebuilds when a file under `analysis/` changes.
- A wheel (`uv build`, the release workflow) uses the `release` profile. `OPENTIDE_ENGINE_PROFILE` overrides it.
- The release workflow builds a wheel per platform with cibuildwheel: Linux (manylinux and musllinux, x86_64 and aarch64), macOS (x86_64, arm64) and Windows (x64). Elsewhere pip builds the sdist, which needs a Rust toolchain.

After changing the bindings (`src/lib.rs`), update the stub `src/opentide/_native.pyi` and run `cargo fmt`, `cargo clippy --all-targets -- -D warnings` and `cargo test` here.

Licence: EUPL-1.2.
