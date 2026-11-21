---
title: Installation
description: Install opentide from PyPI — one package, CLI, MCP, and all platforms.
---

<Callout type="info">
One install gets the CLI, the MCP server (`opentide mcp start`), all thirteen platform adapters, validate, generate, and deploy. Enable platforms in your repo with `opentide setup platforms` — not at pip install time.
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

The latest release is **0.28.1** (13 November 2026), which `pip install opentide` installs: pip leaves out pre-releases. The next one is 1.0.0, now a release candidate, **1.0.0rc2**, on PyPI as a pre-release ([release candidates](#release-candidates)). The first public release was **0.1.0** (9 September 2026). Notes: [Releases](./releases.md).

<Tabs items={['venv + pip', 'uv']}>

<Tab value="venv + pip">

```bash
pip install opentide              # latest on PyPI
# python -m pip install opentide  # in constrained environments
pip install 'opentide==0.28.1'     # pin the current release
```

</Tab>

<Tab value="uv">

```bash
uv pip install opentide              # latest on PyPI
uv pip install 'opentide==0.28.1'    # pin the current release
```

</Tab>

</Tabs>

That installs all of opentide: the `opentide` CLI, validation, generation, deploy adapters, the MCP server, the language server and its query analysis engine, and all thirteen platforms. `pip install opentide` is the only install: the package has no Python dependencies, and its one extra, `plugins` (pydantic), is for writing a [platform plugin](../sdk/platforms.md). You do **not** pick Sentinel or Splunk at install time — enable platforms in your repo with `opentide setup platforms` (writes `.opentide/configurations/platforms/*.toml`).

### Release candidates

The 1.0 release, opentide on one Rust core, is out as a release candidate before it is final. A candidate is a pre-release on every channel, so none of them installs it unless you ask. One candidate has one version in two spellings, which name the same release: Python's `1.0.0rc2` (PyPI, `opentide --version` from pip) and SemVer's `1.0.0-rc.2` (crates.io, the GitHub Release, the binaries). From the candidate after 1.0.0-rc.1, `opentide --version`, `opentide-lsp --version` and `opentide doctor` report the candidate on every channel, and `doctor` treats the two spellings as one version. 1.0.0-rc.1 itself was built before that: its `opentide-lsp` reports `1.0.0`, and `doctor` can warn that a catalog is "from opentide 1.0.0rc1, not 1.0.0-rc.1", when a pip install and a binary share a workspace (it is only a warning).

**PyPI**

```bash
pip install --pre opentide              # the newest pre-release
pip install 'opentide==1.0.0rc2'        # or pin the candidate
uv pip install --prerelease=allow opentide
```

`pipx install --pip-args=--pre opentide` and `uv tool install 'opentide==1.0.0rc2'` install it as a tool. A candidate has the same wheels as a release (and the same sdist for musl and free-threaded Python), and `pip install opentide` without `--pre` stays on 0.28.1.

**crates.io**

```bash
cargo install opentide --version 1.0.0-rc.2 --features cli --locked      # the opentide binary
cargo install opentide-lsp --version 1.0.0-rc.2 --locked                 # the language server alone
```

Cargo needs the version spelled out for a pre-release. The same crate is the [Rust SDK](../sdk/rust.md): `cargo add opentide@=1.0.0-rc.2`.

**GitHub Release binaries**

The `v1.0.0-rc.2` [GitHub Release](https://github.com/opentidehq/opentide/releases/tag/v1.0.0-rc.2) is marked a pre-release. It carries the `opentide` and `opentide-lsp` binaries for glibc Linux, macOS and Windows, and an installer that installs both:

```bash
curl --proto '=https' --tlsv1.2 -sSfLO \
  https://github.com/opentidehq/opentide/releases/download/v1.0.0-rc.2/opentide-installer.sh
sh opentide-installer.sh                 # into ~/.local/bin; OPENTIDE_INSTALL_DIR changes it
opentide --version                       # opentide 1.0.0-rc.2
opentide-lsp --version                   # opentide-lsp 1.0.0-rc.2
```

On Windows, `opentide-installer.ps1` from the same release does the same. The installer checks each binary against the release's `SHA256SUMS` before it installs it. To check what you downloaded yourself, and where it was built:

```bash
BASE=https://github.com/opentidehq/opentide/releases/download/v1.0.0-rc.2
curl -sSfLO "$BASE/SHA256SUMS"
curl -sSfLO "$BASE/opentide-v1.0.0-rc.2-x86_64-unknown-linux-gnu"
sha256sum --check --ignore-missing SHA256SUMS
gh attestation verify opentide-v1.0.0-rc.2-x86_64-unknown-linux-gnu -R opentidehq/opentide
```

`sha256sum --check` names each file that matches. `gh attestation verify` checks the file's build provenance, an attestation signed by the release workflow (`publish.yml` of opentidehq/opentide); it exits 0 when the file is genuine and prints nothing on a non-terminal, so check the exit status (add `--format json` to see the workflow). There are no musl binaries: on Alpine, install from the sdist or `cargo install`, as [below](#the-analysis-engine-and-the-language-server) describes. The npm packages ship with 1.0.0, not with a candidate.

### MCP server

For agent/MCP hosts, remember the path to this environment's `opentide` binary — you point the host at `opentide mcp start` in [MCP configuration](../mcp/configuration.md).

The base install above already ships the MCP server. There is no extra step:

```bash
opentide mcp start        # the server is compiled into opentide
```

An older command such as `pip install 'opentide[mcp]'` still installs opentide: pip and uv warn that the extra does not exist and install the package anyway. Drop the brackets when you next touch it. See [MCP installation](../mcp/installation.md).

### The analysis engine and the language server

The offline query checks (`opentide validate`, `opentide validate query`, `opentide lint`), the language server (`opentide lsp start`) and MCP `validate_query` run a compiled engine, which is part of the opentide package: `pip install opentide` installs it, with nothing else to install. There is no `opentide[lsp]` extra and no separate `opentide-lsp` to install.

opentide has a wheel for CPython 3.10 and later on Linux (x86_64 and arm64, glibc), macOS (Intel and Apple silicon) and Windows (x64 and Arm), with the engine compiled in. There is no wheel for musl Linux (Alpine), by decision. On musl, on any other platform, or on a free-threaded interpreter (`python3.14t`), pip builds opentide from its sdist, which compiles the engine and needs a Rust toolchain ([rustup.rs](https://rustup.rs)) and a C compiler. On Alpine:

```bash
apk add build-base curl
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
. "$HOME/.cargo/env"
pip install opentide
```

The build takes several minutes. `opentide doctor` reports it (`analysis_engine`); see [`opentide lsp`](../cli/lsp.md) to set up an editor.

### Windows and PowerShell

On Windows on Arm, `pip install opentide` installs opentide's own Arm wheel and nothing else: the package has no Python dependencies. Only the `plugins` extra adds one, pydantic, whose pydantic-core publishes Windows on Arm wheels from CPython 3.11, so on CPython 3.10 pip compiles it, which needs a Rust toolchain and the MSVC build tools.

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
function opentide { python -m opentide @args }
opentide --help
```

## Environment variables

| Variable | Purpose |
|----------|---------|
| `OPENTIDE_REPO_ROOT` | Root of the detection content repository (objects, configurations). See [Repository setup](./repository-setup.md) |
| `OPENTIDE_DATA_ROOT` | Changes only `--technique` shell completion: the vocabularies and default configurations the commands read are compiled into opentide |
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

None: each platform's connector, compiled into opentide's Rust core, speaks its vendor's REST API itself, so live deploy, `opentide validate query --live`, `opentide query` and the importers work for every platform on a stock install, including in the pipelines `opentide setup ci` generates. Sentinel deploys through the ARM `alertRules` REST API.

`deploy --dry-run` compiles each rule into the exact request a live deploy sends. A bare `opentide validate query` checks the queries offline with the analysis engine; `generate`, `validate`, offline query checks and dry-run deploy need no credentials.

Releases up to 0.28.0 installed the vendors' Python SDKs (`azure-identity`, `azure-monitor-query`, `splunk-sdk`, `carbon-black-cloud-sdk` with `boto3`, `pymisp`, `google-auth`) for the Python implementation; opentide no longer depends on them. Releases up to 0.15.0 shipped them as extras (`opentide[sentinel]`, `opentide[splunk]`, `opentide[carbon-black]`); an install command that still names one installs opentide with a warning about the unknown extra.

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
| `sysdig` | Sysdig Secure (Falco) |
| `bitdefender` | Bitdefender GravityZone |
| `graylog` | Graylog |
| `exabeam` | Exabeam New-Scale SIEM |
| `google_secops` | Google Security Operations (YARA-L 2.0) |

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
