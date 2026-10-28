---
title: Installation
description: Install opentide from PyPI — one package, CLI, MCP, and all platforms.
---

<Callout type="info">
One install gets the CLI, the MCP server (`opentide mcp start`), all eight platform adapters, validate, generate, and deploy. Enable platforms in your repo with `opentide setup platforms` — not at pip install time.
</Callout>

## Requirements

- Python **3.10–3.14**
- A detection content repository (or use `opentide setup repo` to scaffold one)
- Platform credentials when deploying or running live queries — configured under `.opentide/configurations/`, see [Configuration → credentials](./configuration.md#credentials)

## Recommended: an isolated environment

Install opentide into a virtual environment so its dependencies never collide with other tools:

<Tabs items={['venv + pip', 'uv']}>

<Tab value="venv + pip">

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate.ps1
```

</Tab>

<Tab value="uv">

```bash
uv venv
```

</Tab>

</Tabs>

## PyPI install

The latest release is **0.18.0** (27 October 2026). The first public release was **0.1.0** (9 September 2026). Notes: [Releases](./releases.md).

<Tabs items={['venv + pip', 'uv']}>

<Tab value="venv + pip">

```bash
pip install opentide              # latest on PyPI
# python -m pip install opentide  # in constrained environments
pip install 'opentide==0.18.0'     # pin the current release
```

</Tab>

<Tab value="uv">

```bash
uv pip install opentide              # latest on PyPI
uv pip install 'opentide==0.18.0'    # pin the current release
```

</Tab>

</Tabs>

That installs all of opentide: the `opentide` CLI, validation, generation, deploy adapters, the MCP server, the language server and its query analysis engine, and all eight platforms with every vendor SDK they call. `pip install opentide` is the only install — there are no extras. You do **not** pick Sentinel or Splunk at install time — enable platforms in your repo with `opentide setup platforms` (writes `.opentide/configurations/platforms/*.toml`).

### MCP server

For agent/MCP hosts, remember the path to this environment's `opentide` binary — you point the host at `opentide mcp start` in [MCP configuration](../mcp/configuration.md).

The base install above already ships the MCP server. There is no extra step:

```bash
opentide mcp start        # mcp (>=2.3,<3) is a base dependency since 0.14.0
```

An older command such as `pip install 'opentide[mcp]'` still installs opentide: pip and uv warn that the extra does not exist and install the package anyway. Drop the brackets when you next touch it. See [MCP installation](../mcp/installation.md).

### The analysis engine and the language server

The offline query checks (`opentide validate query`, `opentide validate --deep`), the language server (`opentide lsp start`, `opentide lsp check`) and MCP `validate_query` run a compiled engine, which is part of the opentide package: `pip install opentide` installs it, with nothing else to install. There is no `opentide[lsp]` extra and no separate `opentide-lsp` to install.

opentide has a wheel for CPython 3.10 and later on Linux (x86_64 and arm64, glibc and musl), macOS (Intel and Apple silicon) and Windows x64, with the engine compiled in. On any other platform, or on a free-threaded interpreter (`python3.14t`), pip builds opentide from its sdist, which compiles the engine and needs a Rust toolchain ([rustup.rs](https://rustup.rs)). `opentide doctor` reports it (`analysis_engine`); see [`opentide lsp`](../cli/lsp.md) to set up an editor.

### Windows and PowerShell

`pip` and `uv` create the `opentide` console launcher in the active environment's `Scripts` directory. Ensure that directory is on `PATH`, then run the package directly:

1. Find the path of opentide binaries:

```powershell
Get-Command opentide -All
where.exe opentide
```

opentide does not ship or generate `opentide.bat`. Inspect any bat wrapper reported by these commands before using it; it may have been created by local tooling or an agent.

2. check the path is on:

```powershell
Get-ChildItem Env:PATH    # via the Env: drive
```

3. use the binary

```powershell
opentide --help
```

in constrained environment you may create a PS function

```powershell
function opentide { python -c "from opentide.cli import main; main()" @args }
opentide --help
```

## Environment variables

| Variable | Purpose |
|----------|---------|
| `OPENTIDE_REPO_ROOT` | Root of the detection content repository (objects, configurations). See [Repository setup](./repository-setup.md) |
| `OPENTIDE_DATA_ROOT` | Override bundled package data (advanced; defaults to wheel contents) |
| `DEBUG` | Enable debug logging when set |

## Verify installation

```bash
export OPENTIDE_REPO_ROOT=/path/to/detection-repo     # see Repository setup for other ways
opentide --version         # opentide <version>
opentide validate          # should return OK
opentide generate
opentide --json info
opentide info         # concise tabular view
```

Expected: package version, rule/threat/objective counts, and per-platform capability flags.

### Vendor SDKs

Every vendor SDK a platform calls ships with `pip install opentide`, so live deploy, `opentide validate query --live` and the importers work for every platform on a stock install, including in the pipelines `opentide setup ci` generates:

| Platform | Packages |
|----------|----------|
| Microsoft Sentinel | `azure-identity` `azure-monitor-query`. Rules are deployed through the ARM `alertRules` REST API directly. |
| Splunk | `splunk-sdk` `pandas` |
| Carbon Black Cloud | `carbon-black-cloud-sdk` |
| Defender, Elastic, CrowdStrike, SentinelOne, HarfangLab | HTTP clients bundled with opentide |

`deploy --dry-run` compiles each Sentinel rule into the exact request a live deploy sends. A bare `opentide validate query` checks the queries offline with the analysis engine; `generate`, `validate`, offline query checks and dry-run deploy need no credentials. If a live check reports that an SDK will not import, the environment is damaged: reinstall with `pip install --force-reinstall opentide`.

Releases up to 0.15.0 shipped the SDKs as extras (`opentide[sentinel]`, `opentide[splunk]`, `opentide[carbon-black]`). Those names are gone; an install command that still names one installs opentide with every SDK and a warning about the unknown extra.

### Platform identifiers

These `--platform` values are built into the package:

| `--platform` | Product |
|--------------|---------|
| `sentinel` | Microsoft Sentinel |
| `defender_for_endpoint` | Defender for Endpoint |
| `elastic` | Elastic Security |
| `splunk` | Splunk Enterprise Security |
| `sentinel_one` | SentinelOne |
| `carbon_black_cloud` | Carbon Black Cloud |
| `crowdstrike` | CrowdStrike Falcon |
| `harfanglab` | HarfangLab |

See [Platforms](./concepts/platforms.md) for deploy vs query-validation capabilities.

## Contributing to opentide

To work on the [opentide](https://github.com/opentidehq/opentide) package itself:

```bash
git clone https://github.com/opentidehq/opentide.git
cd opentide
uv sync --group dev
uv run pre-commit install --install-hooks
```

## Normative reference

Workspace layout and configuration files are defined in the [Specifications](/docs/specifications/specs/workspace/) and [Configuration](/docs/specifications/specs/configuration/) specs.

## Next steps

- [Quickstart](./quickstart.md)
- [Repository setup](./repository-setup.md)
- [Platforms](./concepts/platforms.md)
