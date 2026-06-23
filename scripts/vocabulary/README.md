# Vocabulary generation scripts

Runnable scripts for fetching canonical sources and regenerating bundled
`{field}.vocab.toml` files under `src/opentide/data/vocabulary/`.

## ATT&CK (STIX)

```bash
# Fetch latest MITRE STIX bundles
uv run python scripts/vocabulary/fetch_attack_stix.py

# Generate att&ck, att&ck.groups, mitigations, datasources
uv run python scripts/vocabulary/generate_attack.py

# Fetch + generate in one step
uv run python scripts/vocabulary/generate_attack.py --fetch

# Check for newer upstream version and regenerate
uv run python scripts/vocabulary/bump_versions.py --apply
```

Or via CLI: `opentide extract --framework attack`

## Threat actors

```bash
uv run python scripts/vocabulary/generate_actors.py
```

Requires STIX bundles (enterprise/mobile/ics) and fetches MISP galaxy from
`resources.toml` by default.

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
