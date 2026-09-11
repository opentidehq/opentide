---
title: PyPI trusted publishing
description: First publish of opentide 0.1.0 via OIDC — no API tokens.
---

# PyPI trusted publishing

[`.github/workflows/publish-pypi.yml`](../../.github/workflows/publish-pypi.yml) publishes on **GitHub Release** (`release: published`) using [OIDC trusted publishing](https://docs.pypi.org/trusted-publishers/). There is no PyPI token in GitHub secrets.

Version comes from hatch-vcs. Tag **`v0.1.0`** (or a later `v*`) on the commit you release. A Release without a matching tag publishes a `0.1.dev…` version.

Before tagging, `uv build` must produce both an sdist and a wheel. Overlapping `force-include` paths with `packages` will fail the wheel after hatchling 1.30 (duplicate archive members).

A **pending publisher does not reserve the name** until the first successful upload. Configure it and cut the Release the same day.

## Pending publisher (first upload only)

The project does not exist on PyPI yet. Do not register it by uploading a wheel by hand.

1. Log in at [pypi.org](https://pypi.org) with **2FA**.
2. Open [Account → Publishing](https://pypi.org/manage/account/publishing/).
3. Add a **pending GitHub publisher** with these exact fields:

   - PyPI project name: `opentide`
   - Owner: `opentidehq` (GitHub **login**, lowercase — not the display name `OpenTideHQ`)
   - Repository name: `opentide`
   - Workflow name: `publish-pypi.yml` (filename only, no `.github/workflows/`)
   - Environment name: `pypi`

4. The GitHub Environment `pypi` must exist on `OpenTideHQ/opentide` (Settings → Environments). Optional: required reviewers; optional URL `https://pypi.org/p/opentide`.
5. Make `OpenTideHQ/opentide` **public** before the Release so PyPI source links resolve.
6. Cut the Release (creates tag `v0.1.0` at `--target`). The tag **must** sit on the commit that contains `CHANGELOG.md` and `docs/usage/releases.md`, or the wheel’s long description and docs will lag the GitHub notes:

```bash
gh release create v0.1.0 \
  --repo OpenTideHQ/opentide \
  --target development \
  --title "0.1.0" \
  --notes-file .github/release-notes/v0.1.0.md
```

7. Watch [Publish to PyPI](https://github.com/OpenTideHQ/opentide/actions/workflows/publish-pypi.yml). Approve the environment if reviewers are required.
8. Confirm:

```bash
pip index versions opentide
pip install opentide==0.1.0
python -c "import opentide; print(opentide.__version__)"
```

Expect `0.1.0`. Then add the other maintainer under PyPI Project → Settings → Collaborators.

The PyPI account that saved the pending publisher **owns** the project.

## Later releases

After the first upload, the pending publisher becomes a normal publisher. Further GitHub Releases on `v*` tags publish new versions. Do not add a PyPI API token.

Cut a patch on `development` after the changelog and release notes land (example: **0.1.1**):

```bash
gh release create v0.1.1 \
  --repo OpenTideHQ/opentide \
  --target development \
  --title "0.1.1" \
  --notes-file .github/release-notes/v0.1.1.md
```

The tag must sit on the merge commit that contains `CHANGELOG.md`, `docs/usage/releases.md`, and `.github/release-notes/v0.1.1.md`. Do not tag a feature branch.

Optional TestPyPI dry run: a separate pending publisher on [test.pypi.org](https://test.pypi.org/manage/account/publishing/) with the same GitHub fields (and a `testpypi` environment if you add one). Production `publish-pypi.yml` targets pypi.org only.

## If publish fails

- Workflow filename on PyPI must be `publish-pypi.yml`; environment must be `pypi` (lowercase).
- Job needs `id-token: write` and `contents: read`.
- `0.1.dev…` means the tag was not on the checked-out commit (`fetch-depth: 0` and Release target).
- 403 / `invalid-publisher`: pending publisher missing, or fields do not match the OIDC claims. GitHub sends `repository_owner: opentidehq` (lowercase) and `environment: pypi`. Copy those from the failed Publish to PyPI log, save the pending publisher again, then re-run the workflow (do not retag).
- `'2.5' is not a valid metadata version`: hatchling defaulted to Core Metadata 2.5. This repo pins `core-metadata-version = "2.4"` on sdist/wheel. Confirm `uvx twine check dist/*` is clean before tagging.
