---
title: Installation
description: Install opentide from PyPI with the right extras for your platforms, CLI, and MCP server.
---

# Installation

## Requirements

- Python **3.10–3.14**
- A detection content repository (or use `opentide setup repo` to scaffold one)
- Platform credentials configured under `.opentide/configurations/` when deploying or running live queries

## PyPI install

```bash
pip install opentide
```

Install extras for the surfaces you need:

```bash
pip install "opentide[sentinel,cli,mcp]>=0.1"
```

| Extra | Provides |
|-------|----------|
| `cli` | `opentide` Typer command |
| `mcp` | `opentide-mcp` MCP server |
| `sentinel` | Microsoft Sentinel platform plugin |
| `defender` | Defender for Endpoint (via `defender_for_endpoint` entry point) |
| `splunk` | Splunk + `splunk-sdk`, `pandas` |
| `crowdstrike` | CrowdStrike Falcon plugin |
| `carbon-black` | Carbon Black Cloud + SDK |
| `sentinel-one` | SentinelOne plugin |
| `harfanglab` | HarfangLab plugin |

Combine extras in one install string:

```bash
pip install "opentide[sentinel,splunk,cli,mcp]>=0.1"
```

## Development install

Contributors to this repository:

```bash
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
# or: pip show opentide | grep Version
opentide --json info
```

Expected: package version, rule/threat/objective counts, and per-platform capability flags.

## Next steps

- [Quickstart](./quickstart.md)
- [Repository setup](./repository-setup.md)
- [CLI installation extras](../cli/index.md)
