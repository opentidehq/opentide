---
title: Installation
description: Install opentide from PyPI — one package, CLI, MCP, and all platforms.
---

<Callout type="info">
One install gets the CLI, MCP server (`opentide-mcp`), all seven platform adapters, validate, generate, and deploy. Enable platforms in your repo with `opentide setup platforms` — not at pip install time.
</Callout>

## Requirements

- Python **3.10–3.14**
- A detection content repository (or use `opentide setup repo` to scaffold one)
- Platform credentials when deploying or running live queries — configured under `.opentide/configurations/`, see [Configuration → credentials](./configuration.md#credentials)

## Recommended: an isolated environment

Install OpenTide into a virtual environment so its dependencies never collide with other tools:

<Tabs items={['venv + pip', 'uv']}>

<Tab value="venv + pip">

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install opentide
```

</Tab>

<Tab value="uv">

```bash
uv venv
uv pip install opentide
```

</Tab>

</Tabs>

For agent/MCP hosts, remember the path to this environment's `opentide-mcp` binary — you point the host at it in [MCP configuration](../mcp/configuration.md).

## PyPI install

```bash
pip install opentide
```

That installs the **DetectionOps engine**: the `opentide` CLI, `opentide-mcp` MCP server, validation, generation, deploy adapters, and all seven platforms. You do **not** pick Sentinel or Splunk at install time — enable platforms in your repo with `opentide setup platforms` (writes `.opentide/configurations/platforms/*.toml`).

### Live deploy SDKs (when needed)

OpenTide ships platform logic in the wheel. **Third-party SDKs** are only required for live API deploy to some vendors — install them separately in the same environment if you use live deploy (not for validate, generate, or dry-run):

| Live deploy target | Additional `pip install` |
|--------------------|---------------------------|
| Splunk | `splunk-sdk` `pandas` |
| Carbon Black Cloud | `carbon-black-cloud-sdk` |

Sentinel, Defender, CrowdStrike, SentinelOne, and HarfangLab use HTTP clients bundled with opentide.

### Platform identifiers

These `--platform` values are built into the package — **no separate PyPI extra**:

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
