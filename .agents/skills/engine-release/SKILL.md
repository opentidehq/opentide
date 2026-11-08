---
name: engine-release
description: Release the engine crates (crates/, the language server) to crates.io, npm and their GitHub Release assets. Covers scripts/engine/release.py, crates/CHANGELOG.md sections, the parked Release workflow (.github/engine-workflows/release.yml, which UC-0.3 restores here) and proving the GitHub Release and crates.io. Use when releasing the engine, bumping the workspace version, or publishing crates; not for opentide's PyPI release (release-management).
license: EUPL-1.2
metadata:
  author: opentidehq
---

# Releasing the language server

Every crate shares the workspace version, and the internal crates pin each other to it with `=X.Y.Z`. Versions follow Semantic Versioning; before 1.0, a minor version may change diagnostics and settings.

**The engine was imported from opentidehq/language-server (#800) and does not release from this repository yet.** Its Release workflow is parked in `.github/engine-workflows/release.yml`, where GitHub does not run it: it triggers on `v*.*.*` tags, which are opentide's release tags here, and would publish the crates and npm packages on an opentide release. UC-0.3 (#801) brings engine releases back with tags of their own; until then the steps below describe that workflow as it ran in language-server, except that its jobs now install the Rust release `rust-toolchain.toml` pins (`rustup toolchain install` with no name) instead of floating stable, and `native` and `wasm` add the targets they build with `rustup target add` (rustup ignores `--target` on an install with no name). That step needs rustup on the runner: when UC-0.3 restores the workflow, check each image of the `native` matrix (`publish-pypi.yml` installs Rust on `windows-11-arm`, whose image may lack it). opentide builds the engine from `crates/` by path, so nothing is pinned and no release is needed for opentide to ship an engine change.

## 1. Release PR

On a branch from `origin/development`:

```bash
python3 scripts/engine/release.py bump X.Y.Z     # workspace version, internal pins, Cargo.lock
python3 scripts/engine/release.py check vX.Y.Z   # tag, pins and CHANGELOG.md agree
```

- The `Cargo.lock` diff is only the workspace crates' `version` lines. Anything else means Cargo re-resolved: restore the lock and bump again.
- In `crates/CHANGELOG.md`, rename `## [Unreleased]` to `## [X.Y.Z] - YYYY-MM-DD`, keep an empty `## [Unreleased]` above it, and add `[X.Y.Z]: https://github.com/opentidehq/language-server/compare/vPREV...vX.Y.Z` to the links at the bottom.
- The section's first paragraph is its summary: the GitHub Release and opentide.org show it above the change lists. Write one, and check the entries, as `.agents/skills/engine-release-notes/SKILL.md` says: the parts in order (Upgrade, Breaking, Added, Changed, Deprecated, Removed, Fixed, Security), a bold lead on every entry.
- `release.py vendor` + `cargo package --workspace --exclude opentide-native --allow-dirty` + `release.py vendor --clean`, then `cargo test --workspace` after `uv sync --group dev` (`tide_corpus` runs this checkout's `src/opentide` models). The vendored `crates/*/assets`, `LICENSE` and `NOTICE` copies are never committed.

CI green on the PR, then merge it.

## 2. Release

Run **Release** on `main` (Actions → Release → Run workflow, or `workflow_dispatch` through the API). Pushing a `vX.Y.Z` tag does the same. The workflow:

1. `verify`: the tag, pins and changelog agree; every crate packages; the licence scan finds no oracle reference.
2. `native` (8 targets), `wasm`, `highlights`.
3. `assets`: the licence files (`cargo-about`) and `SHA256SUMS` for every asset (`release.py sums dist`), with no OIDC token.
4. `attest`: each asset's build provenance (`actions/attest-build-provenance`). It downloads the assets and runs the action, nothing else: crates.io and npm trust `release.yml` as a whole, so an OIDC token minted in any of its jobs can publish, and only `attest`, `crates` and `npm` may mint one (`scripts/engine/test_release.py` checks).
5. `release`: opens the GitHub Release with the changelog section, creating the tag.
6. `verify-assets`: downloads the published assets and checks `sha256sum -c`, `release.py verify-sums` (SHA256SUMS lists every asset and no other) and `gh attestation verify` on every asset, with `--cert-identity-regex` tying the signature to `release.yml` run from `main` or from the tag (`--repo` alone accepts any workflow of the repository, on any branch). It runs for `publish_only` too, so a release whose check failed is not resumed past it.
7. `crates` and `npm`: only once `verify-assets` passed. `crates` publishes in dependency order with `cargo publish --no-verify`, so no build script runs where the OIDC and registry tokens are (`verify` built every package, without them); a re-run resumes past crates already published.

Watch every job to the end, `crates` included. A green `release` with a red `crates` is a release crates.io users cannot build on.

### Re-running

A GitHub Release's assets are never uploaded twice. The zips do not rebuild byte for byte, and consumers pin the published digests (`SHA256SUMS`, the extension's pinned highlights zip), so `release.py unpublished vX.Y.Z` fails once the release has any asset: in `verify` for a tag push, and in `release` before it uploads to a release that already exists (one created by hand, with notes only, passes).

- `crates` or `npm` failed: **Re-run failed jobs**; `crates` skips what crates.io already has. From a later commit, run the workflow on `main` with `publish_only`: it builds nothing, checks the published assets (`verify-assets`) and publishes what is missing, as long as the crate sources are still the tag's.
- `verify-assets` failed: fix the cause (it is the published assets that failed), then `publish_only`.
- `release` failed partway: `gh release create` uploads to a draft and publishes it at the end. Delete the draft (nobody could download it) and re-run the workflow.
- `publish_only` fails for a version released before #196: those releases have no `SHA256SUMS` and no attestations, so `verify-assets` cannot pass. Cut a patch release instead.

crates.io uses trusted publishing: later releases log in with the workflow's OIDC identity; `CARGO_REGISTRY_TOKEN` is needed only for a crate's first version.

## 3. Prove it

```bash
gh api repos/opentidehq/language-server/releases/latest --jq '.tag_name, (.assets|length)'
for c in opentide-analysis opentide-lsp opentide-core; do
  curl -s -A release-check https://crates.io/api/v1/crates/$c | jq -r '.crate | "\(.name) \(.max_version)"'
done
```

The latest release is `vX.Y.Z` with its binaries, WASM builds, highlights zip, licence files and `SHA256SUMS`; each crate's `max_version` is `X.Y.Z`. `gh release list` uses GraphQL, which cloud sessions cannot reach: use `gh api` (REST).

## Never

- Tag or release from a branch other than `main`.
- Hand-edit a published version: fix forward with a patch release.
- Commit vendored assets, or a `Cargo.lock` Cargo re-resolved.
- Push a `v*` tag for the engine: in this repository those are opentide's release tags.
