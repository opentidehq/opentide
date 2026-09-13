# Vocabulary generation scripts

Runnable scripts for fetching canonical sources and regenerating canonical
`{field}.vocab.toml` files under `specifications/vocabularies/`, then syncing
the bundled copy in `src/opentide/data/vocabulary/`.

By default, scripts expect a sibling clone at `../specifications`. Override with:

```bash
export OPENTIDE_SPECIFICATIONS_ROOT="/absolute/path/to/specifications"
```

STIX downloads default to the workspace resources path. In CI they go to a
scratch directory:

```bash
export OPENTIDE_ATTACK_STIX_DIR="/tmp/attack-stix"
```

## Automated ingest (ATT&CK + MISP)

Weekly GitHub Actions (`.github/workflows/vocab-upstream.yml`) plus:

```bash
# Dry-run: exit 1 when vocabs or pins would change
uv run python scripts/vocabulary/sync_upstream.py --check

# Fetch latest ATT&CK STIX + MISP galaxy, merge, bump pins, sync bundle
uv run python scripts/vocabulary/sync_upstream.py --apply
```

`--apply` writes:

1. `specifications/vocabularies/{att&ck,att&ck.groups,mitigations,datasources,actors}.vocab.toml`
2. Schema pin files in `specifications/schemas/pins/` and `src/opentide/data/pins/`
3. The OpenTide bundle + `data/specifications.lock.json`

Pin bumps are **additive minors only** (for example `att&ck::1.0` → `att&ck::1.1`)
and only for vocab fields already referenced in schema pin files (`att&ck`,
`actors`, `datasources`). `att&ck.groups` and `mitigations` are catalog vocabs
with no schema pin: ATT&CK groups still version-gate live objects through
`threat.actors.name` → `actors::*` (STIX intrusion-sets merge into `actors`).
Keys that disappear from upstream keep their `version` and get `removed` at the
next major, so existing schema revisions still accept them. The ingest PRs are
the review gate — nothing auto-merges.

Merge order: specifications PR first (canonical vocabs + `schemas/pins/`), then
the OpenTide companion PR (bundle, pins, lockfile).

### Per-key bump rules (RFC 0003)

| Upstream change | Key metadata | Pin |
|-----------------|--------------|-----|
| New id | `version` = next minor for this cycle | bump matching pins to that minor |
| Description/name/link only | keep `version` | none |
| Id gone | `removed` = next major | none |
| First fill of an empty file | `version = "1.0"` | none (pins already `::1.0`) |

## ATT&CK (STIX) only

```bash
uv run python scripts/vocabulary/fetch_attack_stix.py
uv run python scripts/vocabulary/generate_attack.py
uv run python scripts/vocabulary/generate_attack.py --fetch
```

`bump_versions.py` now delegates to `sync_upstream.py` (ATT&CK **and** actors).

## Threat actors

```bash
uv run python scripts/vocabulary/generate_actors.py
```

Requires STIX bundles (enterprise/mobile/ics) and fetches MISP galaxy from
`resources.toml` by default. Output is written to
`$OPENTIDE_SPECIFICATIONS_ROOT/vocabularies` and then synced into the opentide
bundle.

## Migration

```bash
uv run python scripts/vocabulary/migrate_yaml_to_toml.py --delete-yaml
```

## Keying model

| `key` | Index field | When |
|-------|-------------|------|
| `name` (default) | `name` | Simple enums, datasources (duplicate MITRE ids) |
| `id` | `id` | ATT&CK techniques, groups, NIST, indicators, actors |

Optional `id` on name-keyed entries is kept as reference metadata only.
