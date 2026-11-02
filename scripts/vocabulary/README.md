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
# Dry-run: exit 1 when vocabularies would change
uv run python scripts/vocabulary/sync_upstream.py --check

# Fetch latest ATT&CK STIX + MISP galaxy, merge, sync bundle
uv run python scripts/vocabulary/sync_upstream.py --apply
```

`--apply` writes:

1. `specifications/vocabularies/{att&ck,att&ck.groups,mitigations,datasources,actors}.vocab.toml`
2. The opentide bundle + `data/specifications.lock.json`

It never writes a schema pin. New keys open the next minor contract (for example
`actors::1.2`), and the run reports it as an unpinned contract for the vocab
fields schema pin files reference (`att&ck`, `actors`, `datasources`). A shipped
revision keeps the contracts it pins, so a new key stays unreachable until a new
schema revision (`threat::1.1`) pins its contract: that revision is a deliberate
specifications and opentide change ([versioning](https://github.com/opentidehq/specifications/blob/main/specs/versioning.md),
RFC 0003), never an ingest side effect. `att&ck.groups` and `mitigations` are
catalog vocabs with no schema pin: ATT&CK groups still version-gate objects
through `threat.actors.name` → `actors::*` (STIX intrusion-sets merge into `actors`).
Keys that disappear from upstream keep their `version` and get `removed` at the
next major, so existing schema revisions still accept them. The ingest PRs are
the review gate — nothing auto-merges.

Merge order: specifications PR first (canonical vocabs), then the opentide
companion PR (bundle, lockfile).

### Per-key bump rules (RFC 0003)

| Upstream change | Key metadata | Contract |
|-----------------|--------------|----------|
| New id | `version` = next minor for this cycle | opens that minor, unpinned |
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

## MalAPI

```bash
uv run --with beautifulsoup4 --with lxml python scripts/vocabulary/generate_malapi.py
```

Scrapes [malapi.io](https://malapi.io), one page per API, and merges the result
into `$OPENTIDE_SPECIFICATIONS_ROOT/vocabularies/malapi.vocab.toml` with the
per-key rules above, then syncs the bundle. The first run also reformats that
file into the layout the generators write, so expect a whole-file diff once.
The site rate-limits to roughly one page a minute after a short burst; the
script backs off and retries, so a full run of ~370 APIs takes hours. If the
retries run out or the connection drops, it still writes what it fetched,
leaves the APIs it did not reach as they were, skips the bundle sync and exits
with status 1. BeautifulSoup is not an opentide dependency, hence `--with`.

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
