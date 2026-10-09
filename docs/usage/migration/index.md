---
title: Migration guide
description: Upgrade detection repositories from CoreTide git submodules to the opentide PyPI package.
---

# Client migration guide

Upgrade detection repositories from **CoreTide git submodules** to the **`opentide` PyPI package**.

## Before and after

### Before (git submodule)

```python
import sys, git
sys.path.append(str(git.Repo(".", search_parent_directories=True).working_dir))
from Engines.modules.tide import DataTide
from Engines.modules.plugins import DeployTide
```

```bash
python Orchestration/validate.py
```

### After (pip package)

```toml
dependencies = ["opentide==0.12.1"]
```

```python
from opentide import OpenTide

OpenTide.initialise()
rule = OpenTide.Rules[uuid]
rule.deploy("sentinel")
```

```bash
opentide validate --strict
opentide validate query --platform sentinel --live
```

Use `--platform`, not legacy `--system`.

## Migration steps

### 1. Install

```bash
pip install 'opentide==0.12.1'
```

Enable platforms in the repo (not at pip install time):

```bash
opentide setup platforms --sentinel --splunk --yes
```

Optional MCP server setup: `opentide setup mcp --cursor --yes` (after `pip install 'opentide==0.12.1'`).

### 2. Remove submodule

```bash
git submodule deinit -f CoreTide
git rm -f CoreTide
rm -rf .git/modules/CoreTide
```

### 3. Environment variables

| Variable | Purpose |
|----------|---------|
| `OPENTIDE_REPO_ROOT` | Detection content root |
| `OPENTIDE_DATA_ROOT` | Optional bundled data override |

### 4. Replace imports

| Legacy | New |
|--------|-----|
| `DataTide` | `OpenTide` |
| `IndexTide` | `IndexManager` |
| `TideModels.MDR` | `DetectionRule` |
| `DeployTide` | `OpenTide.Platforms` |

v0.x: legacy imports warn via `DeprecationWarning`. **v1.0 removes shims.**

### 5. Replace scripts

| Script | CLI |
|--------|-----|
| `Orchestration/validate.py` | `opentide validate` |
| `Orchestration/deploy.py` | `opentide deploy` |
| `Orchestration/generate.py` | `opentide generate` |
| `Orchestration/document.py` | `opentide generate docs` |
| (repository onboarding) | `opentide setup` |
| (CI pipeline files) | `opentide setup ci github` |

Query validation: **five platforms only** (no CrowdStrike/HarfangLab).

### 6. Update CI

Remove `submodules: recursive`. Add:

```yaml
- run: pip install 'opentide==0.12.1'
- run: opentide validate --strict
  env:
    OPENTIDE_REPO_ROOT: ${{ github.workspace }}
```

See [CI/CD workflow](../workflows/ci-cd.md).

### 7. IDE and agents

```bash
opentide setup mcp --cursor --yes
opentide setup skills --generic --yes
```

Or configure manually:

```json
{ "mcpServers": { "opentide": { "command": "opentide", "args": ["mcp", "start"], "env": { "OPENTIDE_REPO_ROOT": "${workspaceFolder}" } } } }
```

## 0.10.0 authoring changes

- One `objective.composition` block, inside `objective`. A root `composition` block is still accepted and is not required.
- Technique lists are `mitre_attack` on threats and objectives. `att&ck` and `attack` are not accepted. Actor values stay scoped (`att&ck::G0007`).
- `surface` and `signal.entities` values are the key names. Stages group those keys. Do not prefix a value with `<stage>::`.
- `signals[].data.logsources` are names from `visibility.toml`, not ATT&CK data sources.
- Signal `severity` uses alert labels (`Informational` through `Critical`), including `Medium`. Threat `severity` stays the incident vocabulary.
- HTTP proxy configuration is `opentide --proxy http://[user:pass@]host:port`. `[proxy]`, `[cve].proxy`, and tenant `setup.proxy` are errors.
- `opentide generate docs` writes `docs/`. Wiki publishing is gone.
- `opentide migrate objects` also moves `Models Library/Threat Vector Models`, `Models Library/Detection Objectives`, and `Models Library/Managed Detection Rules`, plus object folders named in `Configurations/global.toml`.

## Layout migration

If the repository still uses CoreTide directory names (`Configurations/`, `Objects/Threat Vectors`, `.opentide/framework/`), preview and apply:

```bash
opentide migrate objects          # dry-run
opentide migrate objects --apply
```

Full flag list: [CLI migrate](../../cli/migrate.md).

## Agent-assisted migration

Replacing a CoreTide **git submodule**, Orchestration scripts, and Python imports is not a single CLI command. Use the [CoreTide migration prompt](./prompt.md) with your coding agent.

## Deprecation timeline

| Version | Shims |
|---------|-------|
| v0.x | Active with warnings |
| v1.0 | Removed |

## Verification checklist

- [ ] `pip install 'opentide==0.12.1'` succeeds
- [ ] `OPENTIDE_REPO_ROOT` set
- [ ] `opentide validate --strict` passes
- [ ] CI no longer uses submodule
- [ ] No `sys.path.append` hacks

## Related

- [Behaviour inventory (internal)](../../internal/behaviour-inventory.md) — legacy vs new behaviour mapping
- [Repository setup](../repository-setup.md)
- [CoreTide migration prompt](./prompt.md)
- [CLI migrate](../../cli/migrate.md)
