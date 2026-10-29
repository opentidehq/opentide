---
name: release
description: Cut an opentide language-server release, from the version bump to crates.io, and repin the engine in opentidehq/opentide. Covers scripts/release.py, CHANGELOG.md sections, the Release workflow, proving the GitHub Release and crates.io, and the opentide analysis/Cargo.toml pin PR without which the release is not done. Use when releasing, tagging v*, bumping the workspace version, or publishing crates.
license: EUPL-1.2
metadata:
  author: opentidehq
---

# Releasing the language server

Every crate shares the workspace version, and the internal crates pin each other to it with `=X.Y.Z`. Versions follow Semantic Versioning; before 1.0, a minor version may change diagnostics and settings. Tags are `vX.Y.Z` and independent of `opentide`.

A release has four steps. **It is not done until step 4 is merged**: opentide compiles this engine into its Python package, and it cannot publish while it builds from a git revision.

## 1. Release PR

On a branch from `origin/main`:

```bash
python3 scripts/release.py bump X.Y.Z     # workspace version, internal pins, Cargo.lock
python3 scripts/release.py check vX.Y.Z   # tag, pins and CHANGELOG.md agree
```

- The `Cargo.lock` diff is only the workspace crates' `version` lines. Anything else means Cargo re-resolved: restore the lock and bump again.
- In `CHANGELOG.md`, rename `## [Unreleased]` to `## [X.Y.Z] - YYYY-MM-DD`, keep an empty `## [Unreleased]` above it, and add `[X.Y.Z]: https://github.com/opentidehq/language-server/compare/vPREV...vX.Y.Z` to the links at the bottom.
- The section's first paragraph is its summary: the GitHub Release and opentide.org show it above the change lists. Write one.
- `release.py vendor` + `cargo package --workspace --allow-dirty` + `release.py vendor --clean`, then `cargo test --workspace` (with `scripts/requirements-opentide.txt` installed, or `tide_corpus` fails on the missing `opentide` module). The vendored `crates/*/assets`, `LICENSE` and `NOTICE` copies are never committed.

CI green on the PR, then merge it.

## 2. Release

Run **Release** on `main` (Actions → Release → Run workflow, or `workflow_dispatch` through the API). Pushing a `vX.Y.Z` tag does the same. The workflow:

1. `verify`: the tag, pins and changelog agree; every crate packages; the licence scan finds no oracle reference.
2. `native` (8 targets), `wasm`, `highlights`.
3. `release`: opens the GitHub Release with the changelog section, creating the tag.
4. `crates`: publishes in dependency order. A re-run resumes past crates already published.

Watch every job to the end, `crates` included. A green `release` with a red `crates` is a release opentide cannot use.

crates.io uses trusted publishing: later releases log in with the workflow's OIDC identity; `CARGO_REGISTRY_TOKEN` is needed only for a crate's first version.

## 3. Prove it

```bash
gh api repos/opentidehq/language-server/releases/latest --jq '.tag_name, (.assets|length)'
for c in opentide-analysis opentide-lsp opentide-core; do
  curl -s -A release-check https://crates.io/api/v1/crates/$c | jq -r '.crate | "\(.name) \(.max_version)"'
done
```

The latest release is `vX.Y.Z` with its binaries, WASM builds, highlights zip and licence files; each crate's `max_version` is `X.Y.Z`. `gh release list` uses GraphQL, which cloud sessions cannot reach: use `gh api` (REST).

## 4. Repin the engine in opentide

Open a PR against `opentidehq/opentide` `development`, branch `chore/engine-X.Y.Z`:

1. In `analysis/Cargo.toml`, set both crates together, replacing any git `rev`:
   ```toml
   opentide-analysis = "=X.Y.Z"
   opentide-lsp = "=X.Y.Z"
   ```
2. In `analysis/`: `cargo update -p opentide-analysis -p opentide-lsp`. The lock diff touches only the engine crates (`opentide-*`).
3. From the opentide root:
   ```bash
   uv run python scripts/build/check_engine_pin.py --release
   uv run python scripts/build/check_engine_catalog.py
   scripts/ci-local.sh --full
   ```
4. `CHANGELOG.md` `## [Unreleased]` → `### Changed`: one entry naming the release (linked) and the fixes opentide users see. Add no blank line inside the list; `test_the_unreleased_lists_hold_no_blank_lines` fails on one.
5. Follow opentide's PR template, drive the PR to green, and merge it.

If `check_engine_catalog.py` fails, the engine's bundled Tide catalogs are behind opentide's models. Fix it here (`scripts/sync_opentide_schemas.py`, see `skills/catalogs`) and cut a patch release; never edit the catalog in opentide.

opentide's own release (`release-management` there) then builds from the crates.io version.

## Never

- Tag or release from a branch other than `main`.
- Hand-edit a published version: fix forward with a patch release.
- Commit vendored assets, or a `Cargo.lock` Cargo re-resolved.
- Call a release done before the opentide pin PR is merged.
