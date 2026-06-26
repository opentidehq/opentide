---
title: ShareTide to Library migration
description: Lessons learned migrating the ShareTide community corpus into the OpenTide Library catalogue.
---

# ShareTide → Library migration

Case study for migrating a **CoreTide-era public corpus** (ShareTide) into a **greenfield opentide workspace** (OpenTide Library).

## Preconditions

- Local editable install until PyPI publish: `pip install -e ../opentide`
- Normative object schemas: `threat::1.0`, `objective::1.0`, `rule::1.0` ([specifications](https://github.com/OpenTideHQ/specifications))
- Source corpus read-only; ShareTide and WikiTide left unchanged during initial library launch

## Setup (post CLI #104)

Use subcommands — not the removed parent `--mcp` / `--skills` flags:

```bash
opentide setup repo --yes --name "OpenTide Library" --org OpenTideHQ
opentide setup mcp --cursor --yes
# skills install requires network; optional for catalogue repos
```

**Skip for catalogues:**

- `setup platforms` — no query validation or deploy
- `setup ci github` — generated workflow includes deploy stages; hand-write validate-only CI instead

## Layout mapping

| Legacy (ShareTide / CoreTide) | Library (opentide workspace) |
|-------------------------------|------------------------------|
| `Objects/Threat Vectors/` | `objects/threats/` |
| `Objects/Detection Objectives/` | `objects/objectives/` |
| `Objects/Detection Rules/` | `objects/rules/` |
| `Configurations/` | `.opentide/configurations/` (minimal; no deploy secrets) |
| Committed `Schemas/` | `.opentide/schemas/` (generated, gitignored) |
| WikiTide publish | `docs/` via `opentide generate docs` (committed) |

## Schema identifier mapping

| Legacy | New |
|--------|-----|
| `tvm::2.0`, `tvm::2.1` | `threat::1.0` |
| `dom::1.0` | `objective::1.0` |
| `mdr::2.0`, `mdr::2.1` | `rule::1.0` |

## Required field transforms

Pydantic models use `extra="forbid"`. Automated migration handled:

### Threats (~246)

| Legacy field | Transform |
|--------------|-----------|
| `threat.actors` as `{name: ...}` list | Flatten to `list[str]` |
| `threat.impact` / `leverage` as lists | Join to single string |
| `domains`, `targets`, `cve`, `misp`, `platforms`, `surface` | Fold into `terrain`, then remove |

### Objectives (11)

| Legacy field | Transform |
|--------------|-----------|
| Missing top-level `composition` | Duplicate from `objective.composition` |
| `objective.att&ck` | Rename to `objective.attack` |

### Rules (8)

| Legacy field | Transform |
|--------------|-----------|
| Platform blocks (`sentinel::2.0`, etc.) | Run through `load_platform_config()` and re-serialize |
| `detection_model` = signal UUID | Map to parent objective `metadata.uuid` |
| Missing top-level `status` / `severity` | Default `STAGING`; severity from `response.alert_severity` |

Migration script: `library/scripts/migrate_sharetide.py`.

## Validation loop

```bash
export OPENTIDE_REPO_ROOT=$PWD
python scripts/opentide_run.py generate schemas
python scripts/opentide_run.py generate templates
python scripts/opentide_run.py validate --strict
python scripts/opentide_run.py generate docs --output docs --flavor github
```

`scripts/opentide_run.py` forces sequential YAML loading — `ProcessPoolExecutor` can crash on macOS after engine import.

## CI pattern (pre-PyPI)

```yaml
- uses: actions/checkout@v4
- uses: actions/checkout@v4
  with:
    repository: OpenTideHQ/opentide
    path: opentide
- run: pip install -e ./opentide
- run: python scripts/opentide_run.py generate schemas
- run: python scripts/opentide_run.py generate templates
- run: python scripts/opentide_run.py validate --strict
- run: python scripts/opentide_run.py generate docs --output docs --flavor github
  env:
    OPENTIDE_REPO_ROOT: ${{ github.workspace }}
```

Skip `opentide generate` (full pipeline) if `generate exports` fails on flattened actor strings — run phases individually until export code catches up.

## What we did not migrate

| Item | Reason |
|------|--------|
| `manifest.json` | Nothing consumes it; use `docs/` + git objects |
| `Lookups/`, `Analytics/` | Client-specific, not catalogue |
| Committed `Schemas/` | Generated under `.opentide/` |
| CoreTide / WikiTide CI | Replaced by opentide validate + in-repo docs |
| ShareTide / WikiTide edits | Deferred deprecation (~1 week after library launch) |

## Checklist for future corpus migrations

- [ ] Scaffold with `setup repo` (+ optional `mcp` / `skills`)
- [ ] Write or adapt migration script with schema + field transforms
- [ ] Preserve UUIDs; slugify object filenames to dash-case from `name` (append UUID suffix on collision)
- [ ] Map signal UUIDs → objective UUIDs for `detection_model`
- [ ] `validate --strict` clean
- [ ] Generate and commit `docs/`
- [ ] Hand-tailored catalogue CI (no deploy / query validation)
- [ ] Document lessons in `opentide/docs/usage/migration/`

## Related

- [Migration guide](./index.md)
- [Repository setup](../repository-setup.md)
- [OpenTide Library](https://github.com/OpenTideHQ/library)
