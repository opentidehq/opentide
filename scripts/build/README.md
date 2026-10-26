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
way opentide loads them: a missing or extra `[schema::M.m]` revision, a
missing or extra dot-path key, or a different `field::M.m` contract is drift.
Comments and layout are not, so sync leaves a bundled pin file alone when only
those differ. A pin file that does drift is replaced whole, comments included,
so notes about the bundled pins belong in
[`docs/internal/vocab-upstream.md`](../../docs/internal/vocab-upstream.md).
Sync refuses to run against a specifications clone with no
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
`--check` validates that lockfile against the bundled files. That baseline
check cannot tell a synced bundle from a hand edit with a refreshed lockfile.

CI therefore checks out `opentidehq/specifications` at `main` and runs
`--check` against it whenever bundled vocabularies, pins, the lockfile or this
script change. A bundle that differs from specifications fails, whatever the
lockfile says. Merge the specifications change first, then re-run the opentide
PR's CI. A change made only in specifications reaches opentide through the
weekly vocab-upstream workflow, which syncs from specifications `main` and opens
the opentide PR. The lockfile's `specifications_git_sha` records which
specifications commit was synced. It is provenance only and `--check` does not
compare it, so the check still passes after specifications `main` moves on
without a vocabulary or pin change.

## Diagnostic code reference

`render_diagnostics_docs.py` writes `docs/cli/diagnostics.md` from the
`opentide explain` pages in `src/opentide/data/diagnostics/`. Edit a page
there, then run it; `--check` exits 1 when the committed reference is stale.
`tests/test_cli/test_explain.py` fails on drift too.
