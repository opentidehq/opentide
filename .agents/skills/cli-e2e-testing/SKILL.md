---
name: cli-e2e-testing
description: >-
  Write and debug opentide's console-script end-to-end tests: subprocess smoke tests of the
  installed `opentide`, the MCP and LSP stdio tests, the wheel install tests, the tide_corpus
  fixture workspace, E2E shards, the full_set marker and .test_durations_e2e. Use when adding
  or changing a test that runs the console script, or when an E2E shard fails.
---

# CLI E2E Testing

The command line is the Rust core's (UC-6.2, #841): what a command prints and writes is held by
the goldens (`cargo xtask golden check --engine rust`, [golden](../golden/SKILL.md)) and by
`crates/opentide-cli`'s tests (`tests/cmd/*.trycmd`, `command_goldens.rs`). The Python E2E tests
cover what only the installed package can show: the console script and `python -m opentide`,
signals through them, the MCP and LSP servers over stdio, a wheel installed in a fresh
environment, and platform plugins loaded from their entry points.

## Terminology

Use **threat**, **objective**, and **rule** in fixture names and test labels. Do **not** use legacy prefixes MDR, DOM, or TVM.

| Object   | Schema id        | Filename pattern                    |
|----------|------------------|-------------------------------------|
| threat   | `threat::1.0`    | `threat-{id}-{slug}.yaml`           |
| objective| `objective::1.0` | `objective-{id}-{slug}.yaml`        |
| rule     | `rule::1.0`      | `rule-{id}-{platform}-{slug}.yaml`  |

## Layout

```
tests/
  corpus_support.py        # tide_corpus fixtures (root conftest registers it as a plugin)
  fixtures/tide_corpus/
    manifest.toml          # slice lifecycle (current active, future reserved)
    current/               # canonical E2E workspace
  fixtures/plugin_platform/  # the sample platform plugin (acme)
  test_cli/
    test_launch.py         # opentide._cli.main, in process
    e2e/                   # @pytest.mark.cli_e2e / cli_smoke: the console script as a subprocess
  test_mcp/e2e/            # `opentide mcp start` NDJSON JSON-RPC
  test_lsp/e2e/            # `opentide lsp start` over stdio
  test_platforms/          # the plugin API, the plugin through `python -m opentide`
```

`tide_corpus_repo` and friends live in `tests/corpus_support.py`, registered from the
root `conftest.py` via `pytest_plugins`: `materialise_corpus(dest)` and `corpus_env(repo)` build
a corpus plus its environment for subprocess tests.

## Running tests

```bash
# E2E only (development) — selected by marker, not by path
uv run pytest tests/ -m "(cli_e2e or cli_smoke) and not full_set" --no-cov

# Unit tests (excludes E2E markers — matches CI matrix)
uv run pytest tests/ -m "not cli_e2e and not cli_smoke"

# The nightly set's E2E: a wheel built and installed per test
uv run pytest tests/ -m full_set --no-cov
```

## CI

- **Unit matrix** (Python 3.14 on every pull request, 3.10–3.13 in the nightly set): `-m "not cli_e2e and not cli_smoke"`
- **`cli-e2e` job** (Python 3.14 only, 4 shards, not gated on `test`): `tests/ -m "(cli_e2e or cli_smoke) and not full_set"` — whole
  tree, so a new E2E directory is picked up by its marker alone
- **`cli-e2e-full` job** (the nightly set: nightly and Run workflow): `tests/ -m full_set` —
  E2E tests too slow for every pull request, such as a wheel built and installed per test
  (`test_wheel_plugin_platform.py`). A `full_set` test also carries `cli_e2e`, so the unit matrix leaves it out
- **`cli-windows-smoke` job**: `test_console_script_smoke.py -m cli_smoke` — the only coverage of `spawn` platforms; `test_launcher_signals_e2e.py`, Ctrl-C (CTRL_BREAK_EVENT) through the console script

E2E does not contribute to coverage metrics.

### `cli_smoke` must stay out-of-process

`cli_smoke` tests run the installed console script and carry
`@pytest.mark.script_launch_mode("subprocess")` — `pytest-console-scripts` defaults to
`inprocess`, which only loads the entry point as a function and cannot catch import-time
failures.

`test_console_script_smoke.py` takes `tide_corpus_repo` so the console script indexes a
real corpus. Running those smokes against the default empty workspace makes them pass
vacuously, because object parsing never engages.

## tide_corpus extension

1. Add YAML under `tests/fixtures/tide_corpus/current/Objects/…`
2. Use deterministic UUIDs (`00000000-0000-4000-8xxx-…`)
3. Include platform `configurations.*` blocks for deploy payload tests
4. Register new forward slices in `manifest.toml` (`status = "reserved"` → `"active"`)

A change to the corpus changes the golden recordings that use it: re-record them from the oracle
(`cargo xtask golden record`) in the same pull request.

### Author-shaped YAML (do not sanitize timestamps)

`metadata.created` / `modified` in **tutorial fences**, **tide_corpus objects**, and **documentation fixtures** must be unquoted `YYYY-MM-DD` (the format templates emit and authors write). Issue #178 shipped because every first-user simulation quoted dates.

Guard: `tests/test_cli/test_simulation_yaml_shape.py` (unit matrix). Do not re-quote dates to make a test pass.

## Mocking policy

Mock only the network boundary: a stand-in tenant on loopback (`tests/stand_in_support.py`,
the plugin tests' `StandIn`), never the command line's own parsing, planning or output.
