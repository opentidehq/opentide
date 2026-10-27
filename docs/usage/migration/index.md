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
dependencies = ["opentide==0.18.0"]
```

```python
from opentide import Opentide

Opentide.initialise()
rule = Opentide.Rules[uuid]
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
pip install 'opentide==0.18.0'
```

Enable platforms in the repo (not at pip install time):

```bash
opentide setup platforms --sentinel --splunk --yes
```

Optional MCP server setup: `opentide setup mcp --cursor --yes` (after `pip install 'opentide==0.18.0'`).

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
| `DataTide` | `Opentide` |
| `IndexTide` | `IndexManager` |
| `TideModels.MDR` | `DetectionRule` |
| `DeployTide` | `Opentide.Platforms` |

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

Query validation: **six platforms only** (no CrowdStrike/HarfangLab).

### 6. Update CI

Remove `submodules: recursive`. Add:

```yaml
- run: pip install 'opentide==0.18.0'
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

## Vendor rule ids move to deployment state

**Breaking.** Releases after 0.14.2 no longer accept vendor rule ids on rules. `rule_id`, `rule_id_bundle` and `rule_id::<tenant>` are unknown keys on every platform block, `opentide validate` fails them with `external_id_in_rule`, and `opentide deploy` refuses those rules before any HTTP call. The ids live in `.opentide/states/deployment/<uuid>.json` instead ([Deployment state](../concepts/deployment-state.md)).

There is no fallback that keeps reading the old keys. Microsoft Defender for Endpoint, SentinelOne and CrowdStrike only know a deployed rule by the id written on the rule at create time; a deploy that finds neither the key nor a shard creates a second live rule.

Every workspace that has deployed to one of those three platforms:

1. In `.gitignore`, replace the line `.opentide/states/` with `.opentide/states/sharing.jsonl`. The shards must be committed.
2. Run the migration:

   ```bash
   opentide deploy migrate-state
   opentide validate --strict
   ```

3. Commit the edited rules and every new file under `.opentide/states/deployment/` in one commit, before the next deploy.
4. If CI deploys, make it commit `.opentide/states/deployment/` after a deploy that creates rules, together with any promoted rule files.

Keys on every other platform (Sentinel, Splunk, HarfangLab, Carbon Black Cloud, Elastic) were never read; the migration removes them without storing them and prints each one as `external_id_unused` with its platform, tenant, value and file. Those warnings do not fail the command. Workspaces that only deploy to Sentinel or Splunk have no shard to write.

`ExternalIdHelper` is removed from `opentide.deployment`. Use `opentide.states.deployment` (`DeploymentState`, `record_external_id`, `forget_external_id`) instead.

## Skill pack `detection-ops` renamed

The skill pack bundled under `data/setup/skills/detection-ops/` is now `data/setup/skills/detection-workflow/`, and its skill is named `opentide-detection-workflow` instead of `opentide-detection-ops`. `copy_skill_pack("detection-ops", …)` still copies it.

`opentide setup skills` never installed this pack, so repositories set up with that command have nothing to change. If you copied the pack into your repository by hand, the copy keeps working. To match the new name, rename its folder to `detection-workflow` and its `name:` line to `opentide-detection-workflow`. Do not name it `detection-engineering`: `opentide setup skills` installs a different skill under that name and replaces the folder.

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

- [ ] `pip install 'opentide==0.18.0'` succeeds
- [ ] `OPENTIDE_REPO_ROOT` set
- [ ] `opentide validate --strict` passes
- [ ] `opentide deploy migrate-state` exits `0`, and `.opentide/states/deployment/` is committed and not gitignored
- [ ] CI no longer uses submodule
- [ ] No `sys.path.append` hacks

## Related

- [Behaviour inventory (internal)](../../internal/behaviour-inventory.md) — legacy vs new behaviour mapping
- [Repository setup](../repository-setup.md)
- [CoreTide migration prompt](./prompt.md)
- [CLI migrate](../../cli/migrate.md)
