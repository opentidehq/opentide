# src/opentide — Agent Guide: the Python package

The `opentide` package on PyPI: the console script, the Python SDK, the Tide models, the platform
plugin API and the bundled data, around the Rust core compiled into it as `opentide._native`. The
root [`AGENTS.md`](../AGENTS.md) is the map and holds the ground rules and the definition of done;
this guide covers what is particular to the package. (It sits in `src/`, not `src/opentide/`, so
that it never ships in the wheel.)

The command line, the MCP server, the language server, `serve`, the TUI and the platform
connectors are the Rust workspace's ([`crates/AGENTS.md`](../crates/AGENTS.md)): the Python
implementation they replaced was removed by UC-6.2 ([#841](https://github.com/opentidehq/opentide/issues/841)).
Nothing here implements a command.

## Layout

| Path | What |
|------|------|
| `_cli.py`, `__main__.py` | The `opentide` console script and `python -m opentide`: `opentide._native.cli_main` with the package's version, in process; an engine that does not load is an error on stderr, exit 1 |
| `sdk.py` | The SDK (UC-5.2): `opentide.Workspace`, `Connection`, `TenantConfig`, `run_json` and `OpentideError`, over `opentide._native.sdk`; docs in `docs/sdk/` |
| `models/` | The public Tide models: the Rust classes (`opentide._native.models`) under their Pydantic names (ADR 0011) |
| `plugins.py` | The platform plugin API (`PlatformPlugin`, the `opentide.platforms` entry points) and the binding's side of the plugin boundary (`bindings/python/src/plugins.rs`) |
| `analysis.py` | `check_query` and the engine's door (`engine()`, `EngineUnavailableError`) |
| `_native/` | The stubs of the compiled module: `__init__.pyi` by hand, `models.pyi` and `sdk.pyi` generated (`cargo xtask stubs`) |
| `data/` | Bundled data the Rust core compiles in or reads: vocabularies, pins, configuration and log-source defaults, the `opentide explain` pages (`diagnostics/`), setup templates and skills |
| `schemas/data/` | The platform templates `cargo xtask codegen` writes |

## Rules of the package

- **No command logic in Python.** A behaviour of the command line is a change to the Rust
  workspace, held by the goldens ([golden](../.agents/skills/golden/SKILL.md)).
- **`import opentide` stays light**: it loads neither the SDK nor the engine
  (`tests/test_sdk/test_import_time.py`, 30 ms at most). The console script imports nothing
  heavy before handing over.
- **The engine:** a missing engine is `engine_unavailable` (`analysis.EngineUnavailableError`) or,
  for the console script, an error on stderr, never a skipped check. After a change to the
  binding, update `_native/__init__.pyi`; after a change to a Rust model or to the SDK's binding,
  `cargo xtask stubs` regenerates `_native/models.pyi` and `_native/sdk.pyi`
  ([`bindings/python/AGENTS.md`](../bindings/python/AGENTS.md)).
- **Dependencies:** `pydantic` alone, for the plugin API's `configuration_model`. Anything else a
  change needs is Rust.
- **Object models, vocabulary or pins:** regenerate the engine's bundled Tide catalog in the same
  change, `cargo xtask codegen` (`--check` in CI).
- **Docs follow the code** in the same PR: the table in
  [docs-maintenance](../.agents/skills/docs-maintenance/SKILL.md) maps each module to its page.

## Test

```bash
uv run pytest tests/<area> -q --no-cov          # while editing
scripts/ci-local.sh --full                       # before a push
```

The Python suite tests what is here: the SDK (`tests/test_sdk/`), the plugin API
(`tests/test_platforms/`), the console script (`tests/test_cli/`), the MCP and LSP stdio tests,
the package (`tests/test_package/`), the docs' snippets (`tests/test_docs/`) and CI's contracts
(`tests/test_ci/`). Test design: [python-testing-patterns](../.agents/skills/python-testing-patterns/SKILL.md).
