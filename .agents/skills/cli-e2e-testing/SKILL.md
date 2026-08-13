# CLI E2E Testing

Typer-native end-to-end tests for the `opentide` CLI using `CliRunner` (in-process) plus a small subprocess smoke layer.

## When to use

- Adding or changing CLI commands, flags, or JSON output shape
- Extending the simulated Tide workspace (`tide_corpus`)
- Deploy dry-run payload verification (unit + E2E)
- Schema forward-evolution scaffolds (`future/rule_1_1`)

## Terminology

Use **threat**, **objective**, and **rule** in fixture names and test labels. Do **not** use legacy prefixes MDR, DOM, or TVM.

| Object   | Schema id        | Filename pattern                    |
|----------|------------------|-------------------------------------|
| threat   | `threat::1.0`    | `threat-{id}-{slug}.yaml`           |
| objective| `objective::1.0` | `objective-{id}-{slug}.yaml`        |
| rule     | `rule::1.0`      | `rule-{id}-{platform}-{slug}.yaml`  |

Baseline is current `*::1.0` only — no tide_1 legacy slices.

## Layout

```
tests/
  fixtures/tide_corpus/
    manifest.toml          # slice lifecycle (current active, future reserved)
    current/               # canonical E2E workspace
    future/rule_1_1/       # reserved until rule::1.1 lands
  test_cli/
    conftest.py            # cli_runner, tide_corpus_repo, invoke_cli, parse_cli_json
    e2e/                   # @pytest.mark.cli_e2e (and cli_smoke for subprocess)
  test_deployment/
    test_deploy_payloads.py  # per-platform API payload golden tests
```

## Running tests

```bash
# E2E only (development)
uv run pytest tests/test_cli/e2e/ -m "cli_e2e or cli_smoke" --no-cov

# Unit tests (excludes E2E markers — matches CI matrix)
uv run pytest tests/ -m "not cli_e2e and not cli_smoke"

# Local CI parity (unit then E2E)
scripts/ci-local.sh --full

# Update syrupy snapshots
uv run pytest tests/test_cli/e2e/ --snapshot-update
uv run pytest tests/test_deployment/test_deploy_payloads.py --snapshot-update
```

## CI

- **Unit matrix** (Python 3.10–3.14): `-m "not cli_e2e and not cli_smoke"`
- **`cli-e2e` job** (Python 3.14 only, `needs: [test]`): `-m "cli_e2e or cli_smoke"`
- **`cli-windows-smoke` job**: `test_console_script_smoke.py -m cli_smoke` — the only coverage of `spawn` platforms

E2E does not contribute to coverage metrics.

### `cli_smoke` must stay out-of-process

`cli_e2e` uses `CliRunner`, which calls `app` inside the pytest process and never runs
the installed console script. `cli_smoke` covers that gap and therefore carries
`@pytest.mark.script_launch_mode("subprocess")` — `pytest-console-scripts` defaults to
`inprocess`, which only loads the entry point as a function and cannot catch import-time
failures (for example multiprocessing `spawn` re-importing the entry point).

Smoke tests also take `tide_corpus_repo` so the console script indexes a real corpus.
Running them against the default empty workspace makes them pass vacuously, because
object parsing never engages.

## Shared fixtures

| Fixture              | Purpose                                              |
|----------------------|------------------------------------------------------|
| `cli_runner`         | `typer.testing.CliRunner()`                          |
| `tide_corpus_repo`   | Copy of `current/` slice into `tmp_path` with env    |
| `invoke_cli`         | Helper: `--repo`, `--json` defaults                  |
| `parse_cli_json`     | Extract top-level JSON from stdout (after indexer)   |
| `corpus_rule_uuids`  | Deterministic rule UUIDs per platform              |
| `mock_query_validators` | No-op validators for validate query E2E          |

## tide_corpus extension

1. Add YAML under `tests/fixtures/tide_corpus/current/Objects/…`
2. Use deterministic UUIDs (`00000000-0000-4000-8xxx-…`)
3. Include platform `configurations.*` blocks for deploy payload tests
4. Register new forward slices in `manifest.toml` (`status = "reserved"` → `"active"`)

## Deploy payload testing

**Unit** (`test_deploy_payloads.py`): load corpus rule → `preview_rule_deployment()` → syrupy snapshot of `api_request`.

**E2E** (`test_deploy_e2e.py`):

```
opentide --json --repo <corpus> deploy --dry-run --platform <platform> --plan FULL --wide --skip-promotion
```

Assert `ok`, `dry_run`, `plan[platform]`, and `payloads[platform][]` with `uuid` + `api_request`.

Mock only the network boundary (`DeployTide.mdr` deployer); do not mock payload compilation.

## Mocking policy

| Mock                         | Do not mock                    |
|------------------------------|--------------------------------|
| HTTP / cloud SDK clients     | Index loading, deploy plan     |
| Query validators (E2E only)  | JSON emission, exit codes      |
| `modified_mdr_files` (mutate)| Payload preview compile path   |

## Schema bump checklist

1. Bump Pydantic models / `SchemaVersionChain`
2. Add objects under `future/<slice>/`
3. Flip `manifest.toml` slice `status` to `active`
4. Regenerate syrupy snapshots
5. Remove `xfail` from `test_schema_compat_e2e.py` when slice is live

## JSON parsing note

The indexer prints progress to stdout before JSON. Use `parse_cli_json()` (first top-level `{` + `JSONDecoder.raw_decode`) — do not assume stdout is JSON-only.
