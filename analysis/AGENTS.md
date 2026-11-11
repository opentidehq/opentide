# opentide-native (analysis/) — agent guide

The PyO3 binding of the engine, compiled into the `opentide` Python package as `opentide._native`
(package name `opentide-native`, library `_native`, `publish = false`). It binds
`opentide-analysis` and `opentide-lsp` by path; `hatch_build.py` runs `cargo build -p
opentide-native` whenever a wheel or an editable install of opentide is built. Python reaches it
only through `src/opentide/analysis.py`. [`README.md`](README.md) describes the build.

## Place

bindings (`xtask/layers.toml`): depends on opentide-analysis, opentide-lsp and opentide-compare
(`compare_runs`, for the CLI's `OPENTIDE_ENGINE=compare`), opentide-schema (`models`) and
opentide-cli (`cli_main`; `opentide_cli::embed` for `run_cli`, `interrupt_cli`, the warm
workspaces of `serve` and `validate_report`, UC-2.7); nothing depends on it. The plan's `bindings/python` (§4): after the facade (UC-5.1, #836) it depends on `opentide`
alone (D-5). It inherits the workspace lints, `unsafe_code = "forbid"` included: PyO3's macros
need no `unsafe` of its own.

## Invariants

- A thin wrapper: each function converts arguments, calls one engine function and converts the
  result. Logic in a binding fails review (plan §4).
- abi3 from CPython 3.10 (`abi3-py310`): one wheel per platform; no API outside the stable ABI.
- The stub `src/opentide/_native/__init__.pyi` matches the module: update it with every change to
  `src/lib.rs` (ty checks the Python side against it). The submodule `models`
  (`opentide-schema`'s classes, UC-1.9, ADR 0011) has a generated stub,
  `src/opentide/_native/models.pyi`: `cargo xtask stubs` rewrites it, never by hand.
- Positions leave the binding as opentide's CLI counts them (1-based lines, code-point columns;
  `tests` in `src/lib.rs`): a change there is plan invariant 3.
- A missing engine is `engine_unavailable` on the Python side, never a skipped check.

## Test

```bash
cargo nextest run --profile fast -p opentide-native     # the binding's unit tests
uv sync --group dev                                      # rebuild _native into src/opentide/
uv run pytest tests/test_lsp tests/test_validation -q --no-cov
```

`uv sync` builds with the `develop` profile and rebuilds when the workspace's manifests, lock,
sources or compiled-in data change (`cache-keys` in `pyproject.toml`). `scripts/ci-local.sh
--full` runs the whole Python suite on the built module.

## Do not

- Add logic, caching or I/O here: it belongs in the engine crates.
- Hand-edit `src/opentide/_native.*.so`; it is built, and gitignored.
- Change `crate-type`, the module name `_native` or the abi3 feature: `hatch_build.py` and the
  release wheels depend on them.

## Work items that change this crate

- UC-1.9 (#815): the Tide model's pyclasses and `.pyi` exposed through it.
- UC-2.7 (#822): `validate`, `lint`, `info` and MCP read tools call Rust through it.
- UC-3.8 (#830): the console script, `opentide = "opentide._native:main"` (UC-3.8b, #960): `main` hands
  its arguments to `opentide.cli.launch`, which reads the command path with `command_words` and
  runs a Rust command through `cli_main`.
- UC-5.2 (#837) and UC-5.5 (#840): the Python SDK and the wheels.

Lints, tests and the layer rule: [`crates/AGENTS.md`](../crates/AGENTS.md).
