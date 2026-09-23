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

Cut a patch on `development` after the changelog and release notes land (example: **0.1.8**):

```bash
gh release create v0.1.8 \
  --repo OpenTideHQ/opentide \
  --target development \
  --title "0.1.8" \
  --notes-file .github/release-notes/v0.1.8.md
```

The tag must sit on the merge commit that contains `CHANGELOG.md`, `docs/usage/releases.md`, and `.github/release-notes/v0.1.8.md`. Do not tag a feature branch.

Do not pass `--latest=false` for the newest version; the default marks it Latest (check with `gh release list --repo OpenTideHQ/opentide --limit 3`).

**CDN delay:** for about 10–15 minutes after a successful upload, PyPI's CDN can serve stale data. `/pypi/opentide/json` is cached for 900 s and `/simple/opentide/` for 600 s. During that window `pip install opentide==0.1.8` can report "No matching distribution", or `https://pypi.org/pypi/opentide/0.1.8/json` can list only one of the two files. Wait, and install with `uv pip install --no-cache --index-url https://pypi.org/simple`. Do not retag or re-publish.

After a successful upload, `publish-pypi.yml` dispatches `opentide-released` to [`OpenTideHQ/website`](https://github.com/OpenTideHQ/website) so docs, changelog pages, and specs rebuild immediately:

```bash
gh api repos/OpenTideHQ/website/dispatches -f event_type=opentide-released
```

That call uses the same GitHub App as vocab-upstream (`GH_APP_ID` / `GH_APP_KEY`). Install the App on `OpenTideHQ/website` with **contents: write** (required for `repository_dispatch`). If token minting or the dispatch fails, publish still succeeds; the website hourly cron picks the docs change up. The landing-page version number is fetched live from PyPI and does not wait on a rebuild.

Optional TestPyPI dry run: a separate pending publisher on [test.pypi.org](https://test.pypi.org/manage/account/publishing/) with the same GitHub fields (and a `testpypi` environment if you add one). Production `publish-pypi.yml` targets pypi.org only.

## If publish fails

- Workflow filename on PyPI must be `publish-pypi.yml`; environment must be `pypi` (lowercase).
- Job needs `id-token: write` and `contents: read`.
- `0.1.dev…` means the tag was not on the checked-out commit (`fetch-depth: 0` and Release target).
- 403 / `invalid-publisher`: pending publisher missing, or fields do not match the OIDC claims. GitHub sends `repository_owner: opentidehq` (lowercase) and `environment: pypi`. Copy those from the failed Publish to PyPI log, save the pending publisher again, then re-run the workflow (do not retag).
- `'2.5' is not a valid metadata version`: hatchling defaulted to Core Metadata 2.5. This repo pins `core-metadata-version = "2.4"` on sdist/wheel. Confirm `uvx twine check dist/*` is clean before tagging.
- `ModuleNotFoundError: No module named 'hatch'` during **Build package**: `hatch build` isolated envs (hatch 1.18.1 / hatchling 1.32.1) import `hatch` from `BinaryBuilder`. Publish uses `uv build` like CI. A `v*` tag cut before that change still runs the old workflow on `release: published` (converting the Release to draft and back does not pick up `development`). From `development`, re-run without moving the tag:
  ```bash
  gh api repos/OpenTideHQ/opentide/dispatches \
    -f event_type=publish-pypi \
    -f client_payload[checkout_ref]=v0.x.y
  ```
  The Actions UI `workflow_dispatch` input `checkout_ref` is the same path. Do not retag.
- Release exists but Publish to PyPI never starts: the workflow file on `development` failed GitHub's parser (`secrets` in `steps.if` is a common cause). Fix the workflow on `development`, then convert the GitHub Release to draft and back to published. Do not move the tag.
