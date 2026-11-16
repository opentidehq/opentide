# opentide-native (bindings/python/) — agent guide

The PyO3 binding of the engine, compiled into the `opentide` Python package as `opentide._native`
(package name `opentide-native`, library `_native`, `publish = false`). It binds the facade
crate `opentide` by path, and nothing else from the workspace, with the features `cli`,
`analysis`, `python`, `connectors` and `plugins` (`Cargo.toml`); maturin (`[tool.maturin]` in the root
`pyproject.toml`) compiles it whenever a wheel or an editable install of opentide is built, and
takes the package's version from it (`version.workspace = true`). Python reaches it
through `src/opentide/analysis.py`; the SDK (`src/opentide/sdk.py`, `opentide.Workspace`) loads it
there, then imports its submodule `sdk`. [`README.md`](README.md) describes the build.

| Path | What |
| --- | --- |
| `src/lib.rs` | The module `_native`: the engine's functions behind `opentide.analysis` (`analyze_query`, `highlight`, `describe_code`, `language_for_path`), the command line's entry point (`cli_main`), the submodules |
| `src/sdk.rs` | `opentide._native.sdk` (UC-5.2, #837): the facade's `Workspace` and `run_json`, one to one, documents as JSON text; `SdkError(code, message, detail)` |
| `src/sdk/tenants.rs` | The facade's tenant operations (`connectors`, UC-5.2b): `TenantConfig`, `Connection` (`open`; `query`, `validate_query` and `deploy` as awaitables through pyo3-async-runtimes, on a tokio runtime started on the first operation, without the GIL), `Canceller`, `platforms`, `capabilities` |
| `src/plugins.rs` | The platform plugin host (UC-4.5, #835), installed at module init: `opentide.plugins._discover()` and `_invoke()` behind the connectors' traits, JSON text across, the GIL taken on a blocking thread for the plugin call alone |

## Place

bindings (`xtask/layers.toml`, `may_depend_on = ["opentide"]`): from the workspace it depends
on the facade `opentide` alone (D-5, ADR 0005, UC-5.1 #836): `opentide::analysis` (the engine
behind `opentide.analysis`), `opentide::cli` (`cli_main`, which the console script runs),
`opentide::python` (the models), the facade's `Workspace` and tenant operations (`sdk`, UC-5.2)
and `opentide::plugins` (the plugin host, UC-4.5). Outside it: pyo3, pyo3-async-runtimes and
tokio (the tenant operations as awaitables) and serde. Nothing depends on it. What the binding
needs goes into the facade's API first. It inherits the workspace lints, `unsafe_code =
"forbid"` included: PyO3's macros need no `unsafe` of its own.

## Invariants

- A thin wrapper: each function converts arguments, calls one engine function and converts the
  result. Logic in a binding fails review (plan §4).
- abi3 from CPython 3.10 (`abi3-py310`): one wheel per platform; no API outside the stable ABI.
- The stub `src/opentide/_native/__init__.pyi` matches the module: update it with every change to
  `src/lib.rs` (ty checks the Python side against it). The submodule `models`
  (`opentide-schema`'s classes, UC-1.9, ADR 0011) has a generated stub,
  `src/opentide/_native/models.pyi`: `cargo xtask stubs` rewrites it, never by hand. So does the
  submodule `sdk`'s, `src/opentide/_native/sdk.pyi` (UC-5.2b): run `cargo xtask stubs` after a
  change to `src/sdk.rs` or `src/sdk/`; `tests/test_sdk/test_stubs.py` holds it to the module's
  names and parameters, and CI's `stubs` job runs `cargo xtask stubs --check`. A value the
  introspection cannot type (an awaitable, an exception class) gets its type hint from a wrapper's
  `OUTPUT_TYPE` (`Pending`, `SdkErrorClass`).
- An async operation returns an awaitable (`pyo3_async_runtimes::tokio::future_into_py`) and
  holds no GIL while it runs; the runtime starts on the first one, never at import
  (`tests/test_sdk/test_import_time.py`, `test_tenants.py`).
- Positions leave the binding as opentide's CLI counts them (1-based lines, code-point columns;
  `tests` in `src/lib.rs`): a change there is plan invariant 3.
- A missing engine is `engine_unavailable` on the Python side, never a skipped check.

## Test

```bash
cargo nextest run --profile fast -p opentide-native     # the binding's unit tests
uv sync --group dev                                      # rebuild _native into src/opentide/
uv run pytest tests/test_sdk -q --no-cov
```

`uv sync` builds with the `develop` profile and rebuilds when the workspace's manifests, lock,
sources or compiled-in data change (`cache-keys` in `pyproject.toml`). `scripts/ci-local.sh
--full` runs the whole Python suite on the built module.

## Do not

- Add logic, caching or I/O here: it belongs in the engine crates.
- Hand-edit `src/opentide/_native.*.so`; it is built, and gitignored.
- Change `crate-type`, the module name `_native` or the abi3 feature: `[tool.maturin]` and the
  release wheels (`cp310-abi3`) depend on them.
- Give the crate a version of its own: the package's is the workspace's, which
  `scripts/engine/release.py pypi-version` overrides in a candidate's or a CI build's checkout.

## Work items that change this crate

- UC-1.9 (#815): the Tide model's pyclasses and `.pyi` exposed through it.
- UC-2.7 (#822): `validate`, `lint`, `info` and MCP read tools call Rust through it.
- UC-3.8 (#830), UC-6.2 (#841): the console script, `opentide = "opentide._cli:main"`, loads this
  module and runs every command through `cli_main`, in process. When this module does not load,
  the console script says so and exits 1: there is no other implementation. `main`,
  `command_words`, `run_cli`, `compare_runs`, `ServeHost`, `validate_report` and the catalog
  functions, which the Python implementation called, went with it; so did the engine's own
  `Workspace` (`analyze`, `analyze_queries`, `hover`), `QueryReport` and `install_visibility`,
  and with them the dependency on opentide-lsp.
- UC-5.2 (#837): the crate moved here from `analysis/`, and `sdk` binds the facade for
  `opentide.Workspace`; UC-5.2b its tenant operations for `opentide.Connection`, and the generated
  `sdk.pyi`. UC-5.5 (#840): the wheels.

Lints, tests and the layer rule: [`crates/AGENTS.md`](../../crates/AGENTS.md).
