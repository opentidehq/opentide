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

The latest release is **0.9.0** (5 October 2026). The first public release was **0.1.0** (9 September 2026). Notes: [Releases](./releases.md).

```bash
pip install opentide              # latest on PyPI
# python -m pip install opentide  # in constrained environments
pip install 'opentide==0.9.0'     # pin the current release
```

</Tab>

<Tab value="uv">

```bash
uv pip install opentide              # latest on PyPI
uv pip install 'opentide==0.9.0'     # pin the current release
```

</Tab>

</Tabs>

That installs the **DetectionOps engine**: the `opentide` CLI, validation, generation, deploy adapters, and all seven platforms. You do **not** pick Sentinel or Splunk at install time — enable platforms in your repo with `opentide setup platforms` (writes `.opentide/configurations/platforms/*.toml`).

### opentide-mcp

The MCP server needs one extra step:

<Tabs items={['venv + pip', 'uv']}>

<Tab value="venv + pip">

```bash
pip install 'opentide[mcp]'       # adds mcp (>=1.28.1,<2) for `opentide-mcp`
```

</Tab>

<Tab value="uv">

```bash
uv pip install 'opentide[mcp]'       # adds mcp (>=1.28.1,<2) for `opentide-mcp`
```

</Tab>

</Tabs>

The `opentide-mcp` script is on `PATH` either way; without the extra it prints the install command and exits 1. See [MCP installation](../mcp/installation.md).

### Windows and PowerShell

`pip` and `uv` create the `opentide` console launcher in the active environment's `Scripts` directory. Ensure that directory is on `PATH`, then run the package directly:

1. Find the path of opentide binaries:

```powershell
Get-Command opentide -All
where.exe opentide
```

OpenTide does not ship or generate `opentide.bat`. Inspect any bat wrapper reported by these commands before using it; it may have been created by local tooling or an agent.

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
| `OPENTIDE_REPO_ROOT` | Root of the detection content repository (objects, configurations). See [Repository setup](./repository-setup/) |
| `OPENTIDE_DATA_ROOT` | Override bundled package data (advanced; defaults to wheel contents) |
| `DEPLOYMENT_PLAN` | Default deployment plan for `deploy` and `validate query --live` |
| `DEBUG` | Enable debug logging when set |

## Verify installation

```bash
export OPENTIDE_REPO_ROOT=/path/to/detection-repo     # see Repository setup for other ways
opentide validate          # should return OK
opentide generate
opentide --json info | python -c "import sys,json; print(json.load(sys.stdin)['version'])"
opentide --json info
opentide info         # concise tabular view
```

Expected: package version, rule/threat/objective counts, and per-platform capability flags.

### Live deploy SDKs (when needed)

OpenTide ships platform logic in the wheel. **Third-party SDKs** are only required for live API deploy to some vendors — install them separately in the same environment if you use live deploy (not for validate, generate, or dry-run):

| Live target | Extra | Packages |
|-------------|-------|----------|
| Microsoft Sentinel | `opentide[sentinel]` | `azure-identity` `azure-monitor-query` `azure-mgmt-securityinsight` |
| Splunk | `opentide[splunk]` | `splunk-sdk` `pandas` |
| Carbon Black Cloud | `opentide[carbon-black]` | `carbon-black-cloud-sdk` |

Defender, CrowdStrike, SentinelOne, and HarfangLab use HTTP clients bundled with opentide.

Extras are only needed for live API calls — live deploy, and `opentide validate
query --live`. The default `opentide validate query` is offline and works on a
stock install, as do `generate`, `validate`, and dry-run deploy. If you hit a
missing SDK, the command names the extra to install.

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

## Normative reference

Workspace layout and configuration files are defined in the [Specifications](/docs/specifications/specs/workspace/) and [Configuration](/docs/specifications/specs/configuration/) specs.

## Next steps

- [Quickstart](./quickstart.md)
- [Repository setup](./repository-setup.md)
- [Platforms](./concepts/platforms.md)
