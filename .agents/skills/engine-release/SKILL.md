---
name: engine-release
description: Release the engine crates (crates/, the language server) to crates.io, npm and their GitHub Release assets. Covers scripts/engine/release.py, crates/CHANGELOG.md sections, the Engine release workflow (.github/workflows/engine-release.yml, engine-v* tags, release candidates) and proving the GitHub Release and crates.io. Use when releasing the engine, bumping the workspace version, or publishing crates; not for opentide's PyPI release (release-management).
license: EUPL-1.2
metadata:
  author: opentidehq
---

# Releasing the language server

Every crate shares the workspace version, and the internal crates pin each other to it with `=X.Y.Z`. Versions follow Semantic Versioning; before 1.0, a minor version may change diagnostics and settings.

The engine came from opentidehq/language-server (#800) and releases from this repository since UC-0.3 (#801), with [`.github/workflows/engine-release.yml`](../../../.github/workflows/engine-release.yml). Its tags are **`engine-vX.Y.Z`**: `v*` tags are opentide's own releases (PyPI), and `tests/test_ci/test_one_ci.py` fails if any workflow but `publish-pypi.yml` can run on one. The assets keep language-server's names (`highlights-vX.Y.Z.zip`, `opentide-lsp-vX.Y.Z-<target>`), so editors that pin them find the next release by version; releases up to 0.12.0 stay on language-server. Its jobs install the Rust release `rust-toolchain.toml` pins (`rustup toolchain install` with no name; `windows-11-arm` gets rustup first) and add the targets they build with `rustup target add` (rustup ignores `--target` on an install with no name). opentide builds the engine from `crates/` by path, so nothing is pinned and no release is needed for opentide to ship an engine change.

The asset jobs live in [`engine-release-build.yml`](../../../.github/workflows/engine-release-build.yml), which `ci.yml` also runs on every pull request as a dry run (`engine-release-dry-run`, no tag, read-only): a PR that would break the release, or change its asset names, fails there.

## 1. Release PR

On a branch from `origin/development`:

```bash
python3 scripts/engine/release.py bump X.Y.Z     # workspace version, internal pins, Cargo.lock
python3 scripts/engine/release.py check engine-vX.Y.Z   # tag, pins and CHANGELOG.md agree
```

- The `Cargo.lock` diff is only the workspace crates' `version` lines. Anything else means Cargo re-resolved: restore the lock and bump again.
- In `crates/CHANGELOG.md`, rename `## [Unreleased]` to `## [X.Y.Z] - YYYY-MM-DD`, keep an empty `## [Unreleased]` above it, and add `[X.Y.Z]: https://github.com/opentidehq/opentide/compare/engine-vPREV...engine-vX.Y.Z` to the links at the bottom (from 0.11.0, the previous tag is language-server's: link `https://github.com/opentidehq/language-server/releases/tag/v0.11.0`).
- The section's first paragraph is its summary: the GitHub Release and opentide.org show it above the change lists. Write one, and check the entries, as `.agents/skills/engine-release-notes/SKILL.md` says: the parts in order (Upgrade, Breaking, Added, Changed, Deprecated, Removed, Fixed, Security), a bold lead on every entry.
- `release.py vendor` + `cargo package --workspace --exclude opentide-native --allow-dirty` + `release.py vendor --clean`, then `cargo test --workspace` after `uv sync --group dev` (`tide_corpus` runs this checkout's `src/opentide` models). The vendored `crates/*/assets`, `LICENSE` and `NOTICE` copies are never committed.

CI green on the PR, then merge it.

## 2. Release

Run **Engine release** on `development` (Actions → Engine release → Run workflow, or `workflow_dispatch` through the API). Pushing an `engine-vX.Y.Z` tag does the same. The workflow:

1. `verify`: the tag, pins and changelog agree; every crate packages; the licence scan finds no oracle reference.
2. `build` (`engine-release-build.yml`): `native` (8 targets), `wasm`, `highlights`, `licences` (`cargo-about`), then `assets`: the licence scan, `SHA256SUMS` for every asset (`release.py sums dist`) and `release.py check-assets` (exactly the asset set editors pin), with no OIDC token.
4. `attest`: each asset's build provenance (`actions/attest-build-provenance`). It downloads the assets and runs the action, nothing else: crates.io and npm trust `engine-release.yml` as a whole, so an OIDC token minted in any of its jobs can publish, and only `attest`, `crates` and `npm` may mint one (`scripts/engine/test_release.py` checks).
5. `release`: opens the GitHub Release with the changelog section, creating the tag; never marked latest (that is opentide's release), a pre-release for a release candidate.
6. `verify-assets`: downloads the published assets and checks `sha256sum -c`, `release.py verify-sums` (SHA256SUMS lists every asset and no other) and `gh attestation verify` on every asset, with `--cert-identity-regex` tying the signature to `engine-release.yml` run from `development` or from the tag (`--repo` alone accepts any workflow of the repository, on any branch). It runs for `publish_only` too, so a release whose check failed is not resumed past it.
7. `crates` and `npm`: only once `verify-assets` passed, and never for a release candidate. `crates` publishes in dependency order with `cargo publish --no-verify`, so no build script runs where the OIDC and registry tokens are (`verify` built every package, without them); a re-run resumes past crates already published.

Watch every job to the end, `crates` included. A green `release` with a red `crates` is a release crates.io users cannot build on.

### Re-running

A GitHub Release's assets are never uploaded twice. The zips do not rebuild byte for byte, and consumers pin the published digests (`SHA256SUMS`, the extension's pinned highlights zip), so `release.py unpublished engine-vX.Y.Z` fails once the release has any asset: in `verify` for a tag push, and in `release` before it uploads to a release that already exists (one created by hand, with notes only, passes).

- `crates` or `npm` failed: **Re-run failed jobs**; `crates` skips what crates.io already has. From a later commit, run the workflow on `development` with `publish_only`: it builds nothing, checks the published assets (`verify-assets`) and publishes what is missing, as long as the crate sources are still the tag's.
- `verify-assets` failed: fix the cause (it is the published assets that failed), then `publish_only`.
- `release` failed partway: `gh release create` uploads to a draft and publishes it at the end. Delete the draft (nobody could download it) and re-run the workflow.
- `publish_only` fails for a version released before #196: those releases have no `SHA256SUMS` and no attestations, so `verify-assets` cannot pass. Cut a patch release instead.

crates.io uses trusted publishing: later releases log in with the workflow's OIDC identity; `CARGO_REGISTRY_TOKEN` is needed only for a crate's first version.

### A release candidate

Push `engine-vX.Y.Z-rc.N` on a `development` commit whose workspace version is `X.Y.Z` (bump it first, as above; the changelog section may still be `[Unreleased]`, which the notes then show). The workflow builds, attests and publishes a GitHub **pre-release** with every asset; `crates` and `npm` are skipped. Check it as in "Prove it", with the RC tag, and point an editor's pins at it to try it.

```bash
git fetch origin development && git tag engine-vX.Y.Z-rc.N origin/development && git push origin engine-vX.Y.Z-rc.N
```

## 3. Prove it

```bash
gh api repos/opentidehq/opentide/releases/tags/engine-vX.Y.Z --jq '.tag_name, .prerelease, (.assets|length)'
for c in opentide-analysis opentide-lsp opentide-core; do
  curl -s -A release-check https://crates.io/api/v1/crates/$c | jq -r '.crate | "\(.name) \(.max_version)"'
done
```

The release `engine-vX.Y.Z` has its 16 assets (`release.py assets engine-vX.Y.Z`): binaries, WASM builds, highlights zip, licence files and `SHA256SUMS`; each crate's `max_version` is `X.Y.Z`. `gh release list` uses GraphQL, which cloud sessions cannot reach: use `gh api` (REST).

## Never

- Tag or release from a branch other than `development`.
- Hand-edit a published version: fix forward with a patch release.
- Commit vendored assets, or a `Cargo.lock` Cargo re-resolved.
- Push a `v*` tag for the engine: in this repository those are opentide's release tags; the engine's are `engine-v*`.
