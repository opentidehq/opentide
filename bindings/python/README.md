# bindings/python: the engine opentide compiles in

The query and Tide object analysis engine and the language server, compiled into the `opentide` package as `opentide._native`. `pip install opentide` installs it: there is no separate package and no extra.

This crate binds [`opentide-analysis`](../../crates/opentide-analysis), the engine crate of this repository's Cargo workspace (imported from opentidehq/language-server, [`docs/engine/IMPORT.md`](../../docs/engine/IMPORT.md)), by path with PyO3: KQL, SPL, ES|QL, EQL, Kibana KQL (kuery), Lucene and Tide YAML, analyzed without I/O. Python reaches it only through `src/opentide/analysis.py`.

| Command | What the engine does |
| --- | --- |
| `opentide validate` | Object validation, with every rule query checked offline (the `queries` check): the queries a platform would reject |
| `opentide validate query` | That queries check on its own, for rules or query files (`--file hunting/lsass.kql`) |
| `opentide lint` | The engine's warnings and notes on queries, and Elastic block advisories (the `queries` check) |
| `opentide lsp start` | Serves the language server protocol on stdio, for editors |
| `opentide tui` | The editor's findings for each object, as you browse |

## Building

maturin, PyO3's build backend (`[build-system]` and `[tool.maturin]` in the root `pyproject.toml`), compiles this crate in the workspace at the repository root and puts it in the package as `opentide/_native.abi3.so` (`_native.pyd` on Windows), beside the Python sources in `src/opentide/` (a mixed layout). The extension uses CPython's stable ABI from 3.10 (pyo3's `abi3-py310` feature), so each wheel is tagged `cp310-abi3-<platform>`. The package's version is this crate's: the workspace's (`scripts/engine/release.py bump`), which `opentide._native.__version__` reports in PEP 440.

- `uv sync` builds an editable install with the `develop` profile (no link-time optimisation, defined in the root `Cargo.toml`; `[tool.uv] config-settings-package` in `pyproject.toml`) and puts the module in `src/opentide/`. It rebuilds when the workspace's manifests, lock, sources or the data the crates compile in change (`cache-keys` in `pyproject.toml`). `maturin develop --uv --profile develop` does the same by hand.
- A published wheel uses the `release` profile: `.github/workflows/release-pipeline.yml` builds one per platform with PyO3/maturin-action (manylinux_2_28 x86_64 and aarch64, macOS x86_64 and arm64, Windows x64 and arm64). Elsewhere pip builds the sdist (`maturin sdist`), which needs a Rust toolchain.

After changing the bindings (`src/lib.rs`), update the stub `src/opentide/_native/__init__.pyi` (the stubs of the models and the SDK, `_native/models.pyi` and `_native/sdk.pyi`, are generated: `cargo xtask stubs`) and run `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings` and `cargo test --workspace` from the repository root.

Licence: EUPL-1.2.
