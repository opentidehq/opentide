# Build maintenance scripts

Maintainer-only helpers for syncing bundled package data from canonical upstream
repositories.

## Vocabulary and pin sync

`sync_vocabularies.py` mirrors canonical vocabulary files from
`specifications/vocabularies/*.vocab.toml` into
`src/opentide/data/vocabulary/` and schema pins from
`specifications/schemas/pins/*.toml` into `src/opentide/data/pins/`, then
refreshes `data/specifications.lock.json`.
The ingest (`cargo xtask vocab ingest --apply`, [`scripts/vocabulary/README.md`](../vocabulary/README.md))
runs this sync step after writing canonical vocabularies.

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
cargo xtask vocab sync

# Verification mode: report drift and exit 1 (what CI runs)
cargo xtask vocab sync --check
```

`cargo xtask vocab sync` (`xtask/src/vocab/sync.rs`) and `sync_vocabularies.py`
compute the same lockfile. Nothing runs the Python script any more: the
vocab-upstream workflow and the ingest use `cargo xtask vocab sync` (UC-6.3).

If the specifications repository is not available locally, sync mode writes a
baseline lockfile from the currently bundled vocabularies and pins, and
`--check` validates that lockfile against the bundled files. That baseline
check cannot tell a synced bundle from a hand edit with a refreshed lockfile.

CI therefore checks out `opentidehq/specifications` at `main` and runs
`cargo xtask vocab sync --check` against it whenever bundled vocabularies, pins,
the lockfile or `xtask/src/vocab/sync.rs` change. A bundle that differs from specifications fails, whatever the
lockfile says. Merge the specifications change first, then re-run the opentide
PR's CI. A change made only in specifications reaches opentide through the
weekly vocab-upstream workflow, which syncs from specifications `main` and opens
the opentide PR. The lockfile's `specifications_git_sha` records which
specifications commit was synced. It is provenance only and `--check` does not
compare it, so the check still passes after specifications `main` moves on
without a vocabulary or pin change.

## Sentinel's ATT&CK v18 list

`cargo xtask vocab sentinel-attack` writes `src/opentide/data/sentinel/attack-v18.json`
from MITRE's STIX bundles of ATT&CK 18.1 and of the release the `att&ck`
vocabulary was built from (its `source_version`); `--check` exits 1 when the
file would change, and `--stix-dir DIR` reads an attack-stix-data checkout
instead of downloading.

## Diagnostic code reference

`cargo xtask codegen` writes `docs/cli/diagnostics.md` from the
`opentide explain` pages (`src/opentide/data/diagnostics/`, and the analysis
engine's codes), through `opentide_cli::explain::reference_markdown`. Edit a
page there, then run it; `cargo xtask codegen --check` (CI's lint job) exits 1
when the committed reference is stale. A `<` in prose that cannot open a tag is
written `&lt;`, so the page stays MDX that opentide.org can render.

## MDX check of the docs

`check_docs_mdx.py` fails on prose in `docs/` that MDX cannot parse: a `<`
that cannot open a tag (`<=>`, `a < b`) or a bare `{` or `}`, outside code,
tags, comments and frontmatter. opentide.org renders `docs/` as MDX, and one
such page stops its docs sync. `scripts/validate-docs.sh` runs it, and
`tests/test_docs/test_docs_mdx.py` runs it over `docs/`.

```bash
python3 scripts/build/check_docs_mdx.py [DOCS_DIR]
```
