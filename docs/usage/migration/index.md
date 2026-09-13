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
dependencies = ["opentide==0.1.0"]
```

```python
from opentide import OpenTide

OpenTide.initialise()
rule = OpenTide.Rules[uuid]
rule.deploy("sentinel")
```

```bash
opentide validate --strict
opentide validate query --platform sentinel
```

Use `--platform`, not legacy `--system`.

## Migration steps

### 1. Install

```bash
pip install 'opentide==0.1.0'
```

Enable platforms in the repo (not at pip install time):

```bash
opentide setup platforms --sentinel --splunk --yes
```

Optional MCP server setup: `opentide setup mcp --cursor --yes` (after `pip install 'opentide==0.1.0'`).

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
| (CI pipeline files) | `opentide setup ci` |

Query validation: **five platforms only** (no CrowdStrike/HarfangLab).

### 6. Update CI

Remove `submodules: recursive`. Add:

```yaml
- run: pip install 'opentide==0.1.0'
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
{ "mcpServers": { "opentide": { "command": "opentide-mcp" } } }
```

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

- [ ] `pip install 'opentide==0.1.0'` succeeds
- [ ] `OPENTIDE_REPO_ROOT` set
- [ ] `opentide validate --strict` passes
- [ ] CI no longer uses submodule
- [ ] No `sys.path.append` hacks

## Related

- [Behaviour inventory (internal)](../../internal/behaviour-inventory.md) — legacy vs new behaviour mapping
- [Repository setup](../repository-setup.md)
- [CoreTide migration prompt](./prompt.md)
- [CLI migrate](../../cli/migrate.md)
