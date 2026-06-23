# Client Migration Guide — Submodule to pip install

**Phase 8** ([#69](https://github.com/OpenTideHQ/CoreTide/issues/69)) · [Project TideKit](https://github.com/OpenTideHQ/CoreTide/issues/60)

---

## Before & After

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
dependencies = ["opentide[sentinel,splunk,cli]>=0.1"]
```

```python
from opentide import OpenTide
OpenTide.initialise()
rule = OpenTide.Rules[uuid]
rule.deploy("sentinel")
```

```bash
opentide validate --platform sentinel --all
```

Use `--platform`, not `--system`.

---

## Migration Steps

### 1. Install

```bash
pip install "opentide[sentinel,defender,cli]>=0.1"
```

| Extra | Platform |
|-------|----------|
| `sentinel` | Microsoft Sentinel |
| `defender` | Defender for Endpoint |
| `splunk` | Splunk |
| `crowdstrike` | CrowdStrike |
| `carbon-black` | Carbon Black Cloud |
| `sentinel-one` | SentinelOne |
| `harfanglab` | HarfangLab |
| `cli` | `opentide` command |
| `mcp` | `opentide-mcp` |

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
| `Orchestration/document.py` | `opentide document` |

Query validation: **5 platforms only** (no CrowdStrike/HarfangLab).

### 6. Update CI

Remove `submodules: recursive`. Add:

```yaml
- run: pip install "opentide[sentinel,cli]>=0.1"
- run: opentide validate --platform sentinel --all
env:
  OPENTIDE_REPO_ROOT: ${{ github.workspace }}
```

### 7. IDE / agents

```json
{ "mcpServers": { "opentide": { "command": "opentide-mcp" } } }
```

Or run `opentide init` for scaffolded Copilot instructions and MCP config.

---

## Automated Helper

```bash
opentide migrate --check
opentide migrate --apply
```

Rewrites common `Engines.modules.*` imports and `Orchestration/` invocations.

---

## Deprecation Timeline

| Version | Shims |
|---------|-------|
| v0.x | Active with warnings |
| v1.0 | Removed |

---

## Verification Checklist

- [ ] `pip install opentide[<platforms>,cli]` succeeds
- [ ] `OPENTIDE_REPO_ROOT` set
- [ ] `opentide validate` passes
- [ ] CI no longer uses submodule
- [ ] No `sys.path.append` hacks

---

## Related

- [`AGENTS.md`](https://github.com/OpenTideHQ/opentide/blob/development/AGENTS.md)
- [`TEST_PLAN.md`](../TEST_PLAN.md)
- [#69](https://github.com/OpenTideHQ/CoreTide/issues/69) · [#67 CLI](https://github.com/OpenTideHQ/CoreTide/issues/67)
