---
title: Vocabulary upstream ingest
description: Weekly ATT&CK and MISP actor ingest, per-key versioning, and pin bumps via CI PRs.
---

# Vocabulary upstream ingest

OpenTide regenerates MITRE ATT&CK techniques (plus groups, mitigations, and
datasources) and MISP threat actors from upstream, versions each key per
[RFC 0003](https://github.com/OpenTideHQ/specifications/blob/main/rfcs/0003-per-key-vocabulary-versioning.md),
and opens pull requests. **Merging those PRs is the release gate.** Pins move in
the same automation; there is no separate agent step.

## What runs

[`.github/workflows/vocab-upstream.yml`](../../.github/workflows/vocab-upstream.yml)
on Mondays and on `workflow_dispatch`.

1. Fetch the latest MITRE ATT&CK STIX release (`enterprise`, `mobile`, `ics`).
2. Fetch MISP `threat-actor.json` from the galaxy URL in
   [`src/opentide/data/configurations/resources.toml`](../../src/opentide/data/configurations/resources.toml).
3. Merge into canonical TOML under [OpenTideHQ/specifications](https://github.com/OpenTideHQ/specifications)
   `vocabularies/`.
4. Bump matching schema pins (`att&ck`, `actors`, `datasources`, …) on both
   `specifications/schemas/pins/` and [`src/opentide/data/pins/`](../../src/opentide/data/pins/).
5. Open a specifications PR, then an OpenTide PR (bundle + pins + lockfile).

### Two-repo PR order

1. **specifications** (`chore/vocab-upstream` → `main`) — canonical `vocabularies/` and `schemas/pins/`.
2. **opentide** (`chore/vocab-upstream` → `development`) — bundled `src/opentide/data/vocabulary/`, `src/opentide/data/pins/`, and `data/specifications.lock.json`.

Merge specifications first so the lockfile SHA matches canonical vocabs. Nothing auto-merges. `workflow_dispatch` can re-run while a PR is open (`ignore-open-pr`, default true); scheduled runs skip when an ingest PR is already open. After those PRs merge, the next run force-pushes the same `chore/vocab-upstream` heads and opens **new** PRs. Create uses `gh pr list --state open` so a merged cycle is not treated as an existing PR.

Local equivalent:

```bash
export OPENTIDE_SPECIFICATIONS_ROOT=/path/to/specifications
uv run python scripts/vocabulary/sync_upstream.py --check
uv run python scripts/vocabulary/sync_upstream.py --apply
```

Details and bump rules: [`scripts/vocabulary/README.md`](../../scripts/vocabulary/README.md).

## Secrets

The workflow needs a GitHub App (`GH_APP_ID`, `GH_APP_KEY`) installed on
**both** `OpenTideHQ/opentide` and `OpenTideHQ/specifications` with `contents`
and `pull-requests` so it can open the specs PR. Without the App, only a
public clone of specifications is used and the specs PR step is skipped.

## What is pinned

RFC 0003 pins map **schema fields** to vocab contracts (`field::M.m`). They do not pin vocab files by themselves. Ingest only bumps vocab fields that already appear as pin values.

| Vocab | Schema pin | Role |
|-------|------------|------|
| `att&ck` | `threat.att&ck`, `objective.attack`, `rule.techniques` | Live technique lists |
| `actors` | `threat.actors.name` | Live actor `name` (ATT&CK intrusion-sets + MISP) |
| `datasources` | `objective.signals.data.logsources` | Live logsource lists |
| `att&ck.groups` | none | MITRE catalog only |
| `mitigations` | none | MITRE catalog only (name-keyed; duplicate MITRE ids) |

ATT&CK groups **are** version-gated on threat objects through `threat.actors.name` → `actors::*`. `generate_actors` merges STIX intrusion-sets (G-ids) into `actors`. The separate `att&ck.groups` file is a MITRE-only catalog; `ThreatBody` has no `groups` field, so a pin such as `"threat.groups" = "att&ck.groups::1.0"` would be unused.

## Pin policy

Existing objects keep validating: disappeared ATT&CK/MISP ids stay in the
current major (`removed = 2.0`). New techniques and actors land at the next
minor (for example `1.1`) and the pin files in the PR propose that contract on
`threat::1.0`, `threat::2.1`, `objective::1.0`, and `rule::1.0`. Reviewers can
edit or drop pin hunks before merge if a given ingest should not ship to live
schemas.
