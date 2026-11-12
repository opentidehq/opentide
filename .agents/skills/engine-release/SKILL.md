---
name: engine-release
description: Retired since UC-5.5 - the release train (.github/workflows/publish.yml) publishes the engine crates with opentide at one product version, and the engine-v* tags and engine-release.yml are gone. Use when reading how an engine-v* release was cut or verified, or what changed for the engine; to release anything, use release-management.
license: EUPL-1.2
metadata:
  author: opentidehq
---

# Releasing the language server (retired)

Since UC-5.5 (#840) the engine has no release of its own. One version and one tag (`vX.Y.Z`) publish
opentide's wheels, the crates (the engine crates and the `opentide` facade), the npm packages
(`@opentide/lsp-client` and `@opentide/lsp-worker` among them) and the GitHub Release with the
`opentide-lsp` binaries and the assets editors pin, from
[`.github/workflows/publish.yml`](../../../.github/workflows/publish.yml). The procedure is
[`release-management`](../release-management/SKILL.md); the registries' settings and the
decisions are in [`docs/internal/publishing.md`](../../../docs/internal/publishing.md#the-release-train).

What changed for the engine:

| Before (UC-0.3 to UC-5.5) | Now |
|---------------------------|-----|
| `engine-vX.Y.Z` tags, `engine-vX.Y.Z-rc.N` candidates | `vX.Y.Z`, `vX.Y.Z-rc.N`: the product's tags; no more `engine-v*` |
| `.github/workflows/engine-release.yml` | `publish.yml` (the asset jobs are still `engine-release-build.yml`) |
| The workspace version was the engine's (0.12.0) | It is the product version: `scripts/engine/release.py bump X.Y.Z` in the release's pull request, checked by `release.py lockstep` |
| `crates/CHANGELOG.md` sections were the Release body | `CHANGELOG.md` and `.github/release-notes/vX.Y.Z.md`; `crates/CHANGELOG.md` holds the engine's releases before the train |
| Eight `opentide-lsp` targets, musl included | Six: no musl build (the maintainer's decision) |
| Attestations signed by `engine-release.yml` | Signed by `publish.yml` on `development` |
| `publish_only` resumed crates.io | `checkout_ref: vX.Y.Z` resumes every registry |

`scripts/engine/release.py` stays the train's tool for the crates and the assets: `bump`,
`lockstep`, `vendor`, `publish` (and `publish --dry-run` for a candidate), `trust publish.yml`,
`assets`, `check-assets`, `sums`, `verify-sums`, `unpublished`, `npm-version`, `crate-patch`.

To verify an asset of an `engine-vX.Y.Z` release, the identity is `engine-release.yml` run from
`development` or from the tag:

```bash
gh attestation verify highlights-vX.Y.Z.zip --repo opentidehq/opentide \
  --cert-identity-regex '^https://github\.com/opentidehq/opentide/\.github/workflows/engine-release\.yml@refs/(heads/development|tags/engine-vX\.Y\.Z)$'
```

## Never

- Push an `engine-v*` tag, or any tag: `publish.yml` creates the release's tag.
- Hand-edit a published version: fix forward with a patch release.
- Commit vendored assets (`crates/*/assets`, the `LICENSE` and `NOTICE` copies), or a `Cargo.lock`
  Cargo re-resolved.
