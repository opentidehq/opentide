---
title: Vocabulary upstream ingest
description: Weekly ATT&CK and MISP actor ingest and per-key versioning via CI PRs. Schema pins never move here.
---

# Vocabulary upstream ingest

opentide regenerates MITRE ATT&CK techniques (plus groups, mitigations, and
datasources) and MISP threat actors from upstream, versions each key per
[RFC 0003](https://github.com/opentidehq/specifications/blob/main/rfcs/0003-per-key-vocabulary-versioning.md),
and opens pull requests. **Merging those PRs is the release gate.** Schema pins
never move in this automation: see [Pin policy](#pin-policy).

## What runs

[`.github/workflows/vocab-upstream.yml`](../../.github/workflows/vocab-upstream.yml)
on Mondays and on `workflow_dispatch`.

1. Fetch the latest MITRE ATT&CK STIX release (`enterprise`, `mobile`, `ics`).
2. Fetch MISP `threat-actor.json` from the galaxy URL in
   [`src/opentide/data/configurations/resources.toml`](../../src/opentide/data/configurations/resources.toml).
3. Merge into canonical TOML under [opentidehq/specifications](https://github.com/opentidehq/specifications)
   `vocabularies/`.
4. Report the contracts new keys opened (`actors::1.2`) as unpinned, in both PR bodies.
5. Open a specifications PR, then an opentide PR (bundle + lockfile).

### Two-repo PR order

1. **specifications** (`chore/vocab-upstream` → `main`) — canonical `vocabularies/`.
2. **opentide** (`chore/vocab-upstream` → `development`) — bundled `src/opentide/data/vocabulary/` and `data/specifications.lock.json` (and `src/opentide/data/pins/` when specifications `main` changed a pin table since the last sync).

Merge specifications first: opentide CI checks the bundle against specifications `main`, so the opentide PR fails until the specifications PR is in. Re-run its CI after that merge. Nothing auto-merges. `workflow_dispatch` can re-run while a PR is open (`ignore-open-pr`, default true); scheduled runs skip when an ingest PR is already open. After those PRs merge, the next run force-pushes the same `chore/vocab-upstream` heads and opens **new** PRs. Create uses `gh pr list --state open` so a merged cycle is not treated as an existing PR.

Local equivalent:

```bash
export OPENTIDE_SPECIFICATIONS_ROOT=/path/to/specifications
cargo xtask vocab ingest --check
cargo xtask vocab ingest --apply
```

Details and bump rules: [`scripts/vocabulary/README.md`](../../scripts/vocabulary/README.md).

## Secrets

The workflow needs a GitHub App (`GH_APP_ID`, `GH_APP_KEY`) installed on
**both** `opentidehq/opentide` and `opentidehq/specifications` with `contents`
and `pull-requests` so it can open the specs PR. Without the App, only a
public clone of specifications is used and the specs PR step is skipped.

## What is pinned

RFC 0003 pins map **schema fields** to vocab contracts (`field::M.m`). They do not pin vocab files by themselves. Ingest reports new contracts only for vocab fields that already appear as pin values.

| Vocab | Schema pin | Role |
|-------|------------|------|
| `att&ck` | `threat.mitre_attack`, `objective.mitre_attack`, `rule.techniques` | Live technique lists |
| `actors` | `threat.actors.name` | Live actor `name` (ATT&CK intrusion-sets + MISP) |
| `datasources` | `objective.signals.data.logsources` | Live logsource lists |
| `att&ck.groups` | none | MITRE catalog only |
| `mitigations` | none | MITRE catalog only (name-keyed; duplicate MITRE ids) |

ATT&CK groups **are** version-gated on threat objects through `threat.actors.name` → `actors::*`. The ingest merges STIX intrusion-sets (G-ids) into `actors`. The separate `att&ck.groups` file is a MITRE-only catalog; `ThreatBody` has no `groups` field, so a pin such as `"threat.groups" = "att&ck.groups::1.0"` would be unused.

`response.responders` on rules is deliberately not pinned. The team that handles a rule's alerts is per-organisation configuration, not a canonical vocabulary: the shipped `responders` vocabulary was empty, so every authored value failed validation and no instance could fix it ([#507](https://github.com/opentidehq/opentide/issues/507)). An instance declares its teams in `[[responders]]` in `deployment.toml`, and `[deployment] default_responders` fills the field for a rule that names none.

Notes like this one live here, not in the pin files: sync replaces a bundled pin file whole when its tables drift, comments included.

## Pin policy

**A shipped schema revision never changes the contracts it pins.** Moving a pin
changes what that revision accepts under objects already authored against it, so
it is a new schema revision ([versioning](https://github.com/opentidehq/specifications/blob/main/specs/versioning.md),
[RFC 0003](https://github.com/opentidehq/specifications/blob/main/rfcs/0003-per-key-vocabulary-versioning.md)
worked example).

- Existing objects keep validating: disappeared ATT&CK/MISP ids stay in the
  current major (`removed = 2.0`).
- New techniques and actors land at the next minor (for example `actors::1.2`).
  That contract exists in the vocabulary, but no shipped revision pins it, so its
  new keys do not validate yet.
- Adopting it is a deliberate change: a new revision (`threat::1.1`) with its
  own spec file, `["threat::1.1"]` pin table and fixture in specifications, and a
  registered model in opentide (`schema_registry`), as `rule::1.1` was added.
  Authors move objects to it one at a time.

The ingest does not write `schemas/pins/`. Batch adoption: one revision can pin
contracts from several ingests, since contracts are cumulative (`actors::1.3`
includes every `actors::1.2` key).

The bundled pins must match `specifications/schemas/pins/` table by table,
including revisions opentide does not ship yet (`objective::1.1`). Such a table
is unused until opentide registers that schema. When an opentide PR changes
bundled vocabularies, pins, the lockfile or the sync script, CI compares them
with specifications `main` and fails on drift. A pin change made only in
specifications arrives through the next ingest's opentide PR. See
[`scripts/build/README.md`](../../scripts/build/README.md).
