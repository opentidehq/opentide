---
title: PyPI trusted publishing
description: How the release train publishes opentide to PyPI with OIDC, with no API token, a release candidate as a pre-release, and what to do when a publish fails.
---

# PyPI trusted publishing

[`.github/workflows/publish.yml`](../../.github/workflows/publish.yml), the release train (UC-5.5, [#840](https://github.com/opentidehq/opentide/issues/840)), publishes opentide's wheels and sdist to PyPI with [OIDC trusted publishing](https://docs.pypi.org/trusted-publishers/), with the crates, the npm packages and the GitHub Release of the same version. There is no PyPI token in GitHub secrets. It runs from **Run workflow** on `development` (a release candidate also from `integration/unified-core`): a pushed `v*` tag or a GitHub Release made by hand publishes nothing. [Publishing names and trusted publishers](./publishing.md) covers every registry; this page is PyPI's part.

The wheels and the sdist are built by maturin (`[tool.maturin]` in `pyproject.toml`), at the Cargo workspace's version, which `scripts/engine/release.py bump` sets in the release's pull request and the guard checks against the newest dated `CHANGELOG.md` heading (`release.py lockstep`). A candidate's version (`X.Y.ZrcN`) is written into `bindings/python/` in the workflow's checkout (`release.py pypi-version`).

## The publishers

| Index | Project | Publisher | Environment | Used by |
|-------|---------|-----------|-------------|---------|
| pypi.org | `opentide` (exists) | `opentidehq` / `opentide` / `publish.yml` | `pypi` | a release, and a release candidate (`release_candidate: N`) as a pre-release |

There is no TestPyPI publisher. Until UC-5.5, `publish-pypi.yml` published with environment `pypi`; its publisher is removed after the first release from `publish.yml`. The step that adds the new one is [step 10 of the maintainer steps](./publishing.md#10-at-uc-55-publishyml). The GitHub environment `pypi` must allow the branches the workflow runs from (**Settings**, **Environments**): `development`, and `integration/unified-core` while release candidates run from there.

GitHub sends `repository_owner: opentidehq` (lowercase) and the job's environment in the OIDC claims; PyPI compares them, and the workflow file name, exactly.

## A release

Once the notes PR has merged and the crates are at the version (`scripts/engine/release.py lockstep X.Y.Z`), run **Publish** on `development` with no inputs: Actions → Publish → Run workflow, or `workflow_dispatch` through the API (an agent's GitHub tools run it with workflow `publish.yml`, ref `development`, no inputs). The steps are in [release-management](../../.agents/skills/release-management/SKILL.md); for PyPI:

1. The guard reads the version and runs `scripts/build/release.py check vX.Y.Z`: the changelog section and links, `.github/release-notes/vX.Y.Z.md`, the top of `docs/usage/releases.md` and the README pin. It refuses a version that is already tagged or released, and a run from another branch.
2. The wheels (maturin through PyO3/maturin-action, one `cp310-abi3` wheel per platform) and the sdist (`maturin sdist`) build from the run's commit; each wheel is installed and run on its own OS, and a smoke job installs one with `pip` on Linux, macOS and Windows and builds the sdist from source.
3. The **GitHub Release** job creates the tag `vX.Y.Z` on that commit, with the notes file as its body, marked Latest.
4. **Publish to PyPI** uploads with `skip-existing`, after refusing files of any other version than the guard approved or a missing platform, then waits until PyPI lists every file. A release notifies the website.

A **release candidate** (`release_candidate: N`, for the Rust-core transition; [Release candidates](./publishing.md#release-candidates-the-rust-core-transition)) does the same for `vX.Y.Z-rc.N`, from `integration/unified-core` or `development`, with the same environment `pypi`: the files, versioned `X.Y.ZrcN`, go to pypi.org as a pre-release, which pip and uv install only when asked (`pip install --pre opentide`, `uv pip install --prerelease=allow opentide`) or pinned exactly, and the last job installs `opentide==X.Y.ZrcN` from there. It does not notify the website.

**CDN delay:** for about 10–15 minutes after a successful upload, PyPI's CDN can serve stale data. `/pypi/opentide/json` is cached for 900 s and `/simple/opentide/` for 600 s. During that window `pip install opentide==X.Y.Z` can report "No matching distribution", or `https://pypi.org/pypi/opentide/X.Y.Z/json` can list only some of the files. Wait, and install with `uv pip install --no-cache --index-url https://pypi.org/simple`. Do not retag or re-publish.

After a successful upload, the PyPI job dispatches `opentide-released` to [`opentidehq/website`](https://github.com/opentidehq/website) so docs, changelog pages, and specs rebuild immediately:

```bash
gh api repos/opentidehq/website/dispatches -f event_type=opentide-released
```

That call mints a token from `GH_APP_ID` / `GH_APP_KEY`, the secret names vocab-upstream also reads (set them on the `pypi` environment to use a separate App for publishing). The App must be installed on `opentidehq/website` with **contents: write**, which `repository_dispatch` requires: an App with only `contents: read` mints a token and the dispatch then returns 403. If the secrets are missing, token minting fails, or the dispatch fails, publish still succeeds and the job ends with a **Website not notified** warning that names the cause. The website's hourly cron picks the docs change up; run the command above to rebuild sooner.

## If publish fails

Never retag, and never delete a published GitHub Release. Resume the release: run **Publish** on `development` with `checkout_ref=vX.Y.Z` (Actions UI, or `workflow_dispatch` through the API), or, with a GitHub App token that lacks `actions: write`, dispatch:

```bash
gh api repos/opentidehq/opentide/dispatches \
  -f event_type=publish \
  -f client_payload[checkout_ref]=v0.x.y
```

It builds from the tag, uploads nothing to the existing GitHub Release, verifies its assets, and publishes only what each registry lacks: `skip-existing` uploads only the files PyPI is missing.

- 403 / `invalid-publisher`: the publisher is missing, or its fields do not match the OIDC claims (workflow `publish.yml`, environment `pypi`, owner `opentidehq`). Copy the claims from the failed job's log, fix the publisher, then resume.
- A metadata version PyPI refuses: check the built files with `uvx twine check dist/*`; maturin's version is pinned in `pyproject.toml` (`[build-system]`) and in the workflows (`maturin-version`), so a change of metadata comes with a deliberate bump.
- PyPI 5xx (`502 Bad Gateway`) or a partial upload, where PyPI kept the wheel but not the sdist (0.4.0): resume as above. The **Verify PyPI lists every built file** step fails the job unless the index lists every wheel and the sdist, and its log prints the resume command.
- A smoke test failed: nothing was tagged or published. Fix it on `development` and run again.

## The analysis engine

There is one project on PyPI, `opentide`. The engine (`bindings/python/` and the engine crates in `crates/`, one Cargo workspace, Rust) is compiled into the package (maturin), so the workflow publishes one `cp310-abi3` wheel per platform, built with PyO3/maturin-action (Linux manylinux_2_28 on x86_64 and aarch64, macOS Intel and Apple silicon, Windows x64 and Arm64), and an sdist that carries the workspace's manifests, sources and embedded data. It refuses to publish when a platform's wheel is missing, a wheel is not `cp310-abi3`, or a musllinux wheel is there. musl (Alpine) and free-threaded CPython (3.14t) have no wheel: they build from the sdist, which needs a Rust toolchain ([The release train](./publishing.md#the-release-train)).

The engine builds from this repository by path, so a release needs no engine published first; its crates go to crates.io in the same run, at the same version.
