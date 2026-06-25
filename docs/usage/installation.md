---
title: Installation
description: Install opentide from PyPI with the right extras for your platforms, CLI, and MCP server.
---

<Callout type="info">
Platform plugins are included with the base `opentide` package. **PyPI extras** only add the Typer CLI, MCP server, or optional Python SDK dependencies for Splunk and Carbon Black.
</Callout>

## Requirements

- Python **3.10–3.14**
- A detection content repository (or use `opentide setup repo` to scaffold one)
- Platform credentials configured under `.opentide/configurations/` when deploying or running live queries

## PyPI install

```bash
pip install opentide
```

```bash
pip install "opentide[sentinel,cli,mcp]>=0.1"
```

### Optional extras

| Extra | Provides |
|-------|----------|
| `cli` | `opentide` Typer command |
| `mcp` | `opentide-mcp` MCP server |
| `sentinel` | Microsoft Sentinel plugin (no extra Python deps) |
| `splunk` | Splunk plugin + `splunk-sdk`, `pandas` |
| `crowdstrike` | CrowdStrike Falcon plugin |
| `carbon-black` | Carbon Black Cloud plugin + SDK |

Combine extras in one install string:

```bash
pip install "opentide[sentinel,splunk,cli,mcp]>=0.1"
```

### Platform plugins (always in base package)

These `--platform` values are registered at install time — **no separate PyPI extra**:

| `--platform` | Product |
|--------------|---------|
| `sentinel` | Microsoft Sentinel |
| `defender_for_endpoint` | Defender for Endpoint |
| `splunk` | Splunk Enterprise Security |
| `sentinel_one` | SentinelOne |
| `carbon_black_cloud` | Carbon Black Cloud |
| `crowdstrike` | CrowdStrike Falcon |
| `harfanglab` | HarfangLab |

See [Platforms](./concepts/platforms.md) for deploy vs query-validation capabilities.

## Contributing to OpenTide

To work on the [opentide](https://github.com/OpenTideHQ/opentide) package itself:

```bash
git clone https://github.com/OpenTideHQ/opentide.git
cd opentide
uv sync --group dev
uv run pre-commit install --install-hooks
```

## Environment variables

| Variable | Purpose |
|----------|---------|
| `OPENTIDE_REPO_ROOT` | Root of the detection content repository (objects, configurations) |
| `OPENTIDE_DATA_ROOT` | Override bundled package data (advanced; defaults to wheel contents) |
| `DEPLOYMENT_PLAN` | Default deployment plan for `deploy` and `validate query` |
| `DEBUG` | Enable debug logging when set |

Set the repo root before every command, or pass `--repo`:

```bash
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate
```

## Verify installation

```bash
opentide --json info | python -c "import sys,json; print(json.load(sys.stdin)['version'])"
opentide --json info
```

Expected: package version, rule/threat/objective counts, and per-platform capability flags.

## Normative reference

Workspace layout and configuration files are defined in the [Specifications](/docs/specifications/specs/workspace/) and [Configuration](/docs/specifications/specs/configuration/) specs.

## Next steps

- [Quickstart](./quickstart.md)
- [Repository setup](./repository-setup.md)
- [Platforms](./concepts/platforms.md)
