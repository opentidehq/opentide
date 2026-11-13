---
title: Default-flip readiness
description: The flip to Rust as opentide's only engine (UC-6.2, #841) — done. What it removed, what the package keeps, how it was proven, and what was kept back.
---

# Default-flip readiness (UC-6.0 → UC-6.2)

> Status: **done** (UC-6.2, [#841](https://github.com/opentidehq/opentide/issues/841), under
> [#790](https://github.com/opentidehq/opentide/issues/790)). Rust is opentide's only engine, for
> every command path; the Python implementation and `OPENTIDE_ENGINE` are removed. This page was
> UC-6.0's inventory of what still ran on Python; it now records how the flip closed it.

## The decisions

The maintainer decided D6 (flip granularity) as **every path at once**, with **no escape hatch**:
the plan's three releases per command (compare, default flip, deletion, §7) collapsed into one
change, since `golden check` compared every path with no unexplained difference before it.

| # | Decision | Outcome |
|---|----------|---------|
| D1 | `--help` | clap's help, compared by content (UC-6.0b) |
| D2 | Shell completion | `clap_complete` (UC-6.0b) |
| D3 | The home screen | ported (UC-6.0b) |
| D4 | The MCP server | the Rust server (UC-6.0c); the Python server removed (UC-6.2) |
| D5 | `doctor`'s Python rows | dropped (UC-6.0d) |
| D6 | Flip granularity | every path at once, no `OPENTIDE_ENGINE=python` (UC-6.2) |
| D7 | `query` routing (G6) | no routing left: every `query` run is Rust's (UC-6.2) |

## What UC-6.2 changed

- **The console script** is `opentide._cli:main`: it hands its arguments to
  `opentide._native.cli_main` in process, and says so on stderr (exit 1) when the engine does not
  load. The launcher's routing (`opentide.cli.launch`, `engines.py`, `engine_defaults.py`) is gone.
- **The Python implementation is removed**: the Typer commands and services, the Python platform
  clients, the Pydantic models behind `opentide.models` (`opentide._models`), the Python MCP server,
  the Textual UI, the serve bridge, and every module only they used. `src/opentide` keeps the
  console script, the SDK (`sdk.py`), the Rust models (`models/`), the plugin API (`plugins.py`),
  `analysis.py` (`check_query`), the stubs of the binding, and the bundled data: 1,994 lines of
  Python, from 93,630.
- **The deprecated SDK entry points are removed** with no shims: `Opentide.initialise()` and its
  registry, `run_validation` and `ValidationScope`, the documentation writers. CHANGELOG lists them
  under Breaking, with an Upgrade step each; [`docs/sdk/migration.md`](../sdk/migration.md) maps
  them to `opentide.Workspace`.
- **Dependencies:** `pydantic` alone (the plugin API's `configuration_model`), from 22.
- **The Rust command line** no longer reads `OPENTIDE_ENGINE`, lists it in `--json commands`, or
  refuses a run as not ported: a rule's query on a platform plugin (`query --rule`/`--file`) is a
  usage error, and a status promotion that cannot rewrite a push fails the run (`--skip-promotion`
  named). `engine_not_ported` and `engine_mismatch` (and exit 70) are gone with their explain pages.
- **Plugins** always run through the Rust core: `validate` on a workspace that enables a plugin's
  platform needs nothing set (the rest of UC-4.5c, [#835](https://github.com/opentidehq/opentide/issues/835)).
- **Tooling:** `cargo xtask golden check --engine rust` runs every case (it replaced
  `--engine compare`, which ran the cases `RUST_COMMANDS` covered); `cargo xtask mcp replay
  --engine rust` replays the recorded Python sessions against the Rust server; `cargo xtask
  codegen` writes the bundled Tide catalog, router and highlights key list that
  `scripts/engine/sync_opentide_schemas.py` wrote from the Python models. The parity dashboard is
  retired ([test strength](./test-strength.md#parity-dashboard-retired)).

## How it was proven

```bash
cargo xtask golden check --engine rust           # every case against the oracle's recording
cargo xtask mcp replay --engine rust tests/golden/mcp/*.jsonl
cargo xtask conformance --runners rust,python,node
uv build && <fresh venv> pip install dist/*.whl  # --version, validate on the tide corpus, the SDK
```

The goldens stay as the specification of the Rust command line; the oracle stays opentide 0.23.0
from its PyPI wheel (`tests/golden/ORACLE`), which `record` runs. The recorded MCP sessions are the
Python server's, frozen.

## Kept back

| What | Why | Where it runs now |
|------|-----|-------------------|
| The vocabulary ingest (ATT&CK STIX, MISP actors, malapi: `opentide.vocabulary`, `scripts/vocabulary/`) | Maintainer tooling not yet ported to `cargo xtask vocab`; it writes into specifications only | From the last commit that has it (`INGEST_REV` in `.github/workflows/vocab-upstream.yml`, [`scripts/vocabulary/README.md`](https://github.com/opentidehq/opentide/blob/development/scripts/vocabulary/README.md)) |
| The check of the model field docstrings against the specifications' field tables | It read the Pydantic models' docstrings; the Rust models' docs have no such check yet | Not run: a follow-up |
| The 48-case matrix of GitLab pipelines the Python renderer was linted on | The renderer is Rust's; the lint job now lints what `opentide setup ci gitlab` writes on the tide corpus, with and without platforms | `gitlab-ci-lint` |
