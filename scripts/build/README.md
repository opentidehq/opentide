# Build maintenance scripts

Maintainer-only helpers for syncing bundled package data from canonical upstream
repositories.

## Vocabulary sync

`sync_vocabularies.py` mirrors canonical vocabulary files from
`specifications/vocabularies/*.vocab.toml` into
`src/opentide/data/vocabulary/`, then refreshes `data/specifications.lock.json`.
The wrapper generators under `scripts/vocabulary/` now call this sync step
automatically after writing canonical vocabularies.

Run commands from the repository root.

Default specifications root is a sibling clone at `../specifications` relative
to this repository root. Override it with:

```bash
export OPENTIDE_SPECIFICATIONS_ROOT="/absolute/path/to/specifications"
```

### Commands

```bash
# Synchronize bundled vocabularies and rewrite lockfile (uv alias)
uv run sync-vocabs

# CI/verification mode: fail on drift (uv alias)
uv run check-vocabs

# Equivalent direct invocations
uv run python scripts/build/sync_vocabularies.py
uv run python scripts/build/sync_vocabularies.py --check
```

If the specifications repository is not available locally, sync mode writes a
baseline lockfile from the currently bundled vocabulary state, and `--check`
validates that lockfile against the bundled files.

CI uses the `--check` behavior to ensure bundled vocabularies and
`data/specifications.lock.json` do not drift from the expected state.
