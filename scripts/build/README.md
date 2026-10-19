# Build maintenance scripts

Maintainer-only helpers for syncing bundled package data from canonical upstream
repositories.

## Vocabulary and pin sync

`sync_vocabularies.py` mirrors canonical vocabulary files from
`specifications/vocabularies/*.vocab.toml` into
`src/opentide/data/vocabulary/` and schema pins from
`specifications/schemas/pins/*.toml` into `src/opentide/data/pins/`, then
refreshes `data/specifications.lock.json`.
The wrapper generators under `scripts/vocabulary/` now call this sync step
automatically after writing canonical vocabularies.

Vocabularies must match byte for byte. Pins are compared table by table, the
way OpenTide loads them: a missing or extra `[schema::M.m]` revision, a
missing or extra dot-path key, or a different `field::M.m` contract is drift.
Comments and layout are not, so sync leaves a bundled pin file alone when only
those differ. Sync refuses to run against a specifications clone with no
`schemas/pins/`, because it would delete every bundled pin.

Run commands from the repository root.

Default specifications root is a sibling clone at `../specifications` relative
to this repository root. Override it with:

```bash
export OPENTIDE_SPECIFICATIONS_ROOT="/absolute/path/to/specifications"
```

### Commands

```bash
# Synchronize bundled vocabularies and pins, and rewrite the lockfile
uv run python scripts/build/sync_vocabularies.py

# Verification mode: report drift and exit 1
uv run python scripts/build/sync_vocabularies.py --check
```

If the specifications repository is not available locally, sync mode writes a
baseline lockfile from the currently bundled vocabularies and pins, and
`--check` validates that lockfile against the bundled files.

CI has no specifications clone, so it runs `--check` in that baseline mode
whenever bundled vocabularies, pins, the lockfile or this script change: an
edit to the bundle that was not synced from specifications fails until the
lockfile is refreshed. The lockfile's `specifications_git_sha` records which
specifications commit was synced. It is provenance only and `--check` does not
compare it, so a lockfile written from a clone still passes in CI.
