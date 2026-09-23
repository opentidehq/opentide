---
name: release-management
description: Cut OpenTide PyPI releases: changelog, install pins, GitHub Release tag, OIDC publish. Use when releasing, tagging v*, publishing to PyPI, or preparing 0.x.y notes.
---

# Release management — OpenTide

SOP for shipping a PyPI version of `opentide`. Version is **dynamic from git tags** via hatch-vcs (`pyproject.toml` `[tool.hatch.version] source = "vcs"`). There is no hardcoded version in pyproject. Do **not** hand-edit `src/opentide/_version.py`.

## When to use

- User asks to release, cut a version, publish to PyPI, bump the package, or "bundle this in a release"
- A user-facing fix/feature has landed on `development` but PyPI still shows the previous version
- Preparing notes / pins before `gh release create`

## When NOT to release

| Situation | Do this instead |
|----------|-----------------|
| CI-only, docs-for-agents, CodeQL Action pins, E2E tests that do not change the installed CLI/SDK/schema | No release |
| Tagging HEAD before changelog / notes / pins exist | Step 1 first |
| Releasing from a feature branch | Merge notes to `development`, then tag the **merge commit** |

Never tag a feature branch. Trunk is `development`.

## Version mechanics

| Fact | Detail |
|------|--------|
| Package | `opentide` on PyPI |
| Tag | `v0.x.y` (leading `v`) |
| GitHub Release | `release: published` → [`.github/workflows/publish-pypi.yml`](../../../.github/workflows/publish-pypi.yml) |
| Auth | OIDC trusted publishing. Environment `pypi`. **No API token.** |
| Workflow filename on PyPI | `publish-pypi.yml` (filename only) |
| Failed release | Release **without** that tag on the checked-out commit publishes `0.1.dev…` |

A GitHub Release whose `--target` is not the tagged commit is a failed release. Do not retag; fix the target and publish from the correct tag.

## Patch vs minor

The package is pre-1.0, so the minor number carries breaking and behaviour changes. Cut a **minor** (`0.x+1.0`) when any shipped change does one of these:

- changes what input is accepted (schema or model shape, validation strictness);
- changes CLI output, JSON fields, or exit codes that scripts depend on;
- changes generated files that users must regenerate (`opentide setup ci`, schemas, docs);
- adds a command or user-visible feature.

Otherwise, for fixes that restore documented behaviour without changing those surfaces, cut a **patch** (`0.x.y+1`).

Precedents:
- **0.4.0**: fixes changed output that scripts depend on, and a security fix required users to regenerate CI (#244).
- **0.5.0**: `threat.impact` and `threat.leverage` became lists (#189).

State the rationale in the CHANGELOG upgrade cue.

## Required two-step flow

**Step 1** — notes PR, merge to `development`.  
**Step 1b** — CI green on that PR.  
**Step 2** — `gh release create` on the merge commit (this publishes).  
**Step 3** — prove PyPI.  
**Step 4** — group the shipped issues under the release tracking issue and close it.

Do not skip Step 1. The tag must sit on the merge commit that **already contains** the changelog, usage notes, GitHub notes file, and install pins.

---

### Step 1 — Prepare notes PR (must merge to `development` first)

Create a `docs:` (or `chore:`) PR against `development`.

**Cloud agents:** branch `cursor/prepare-0.x.y-…`, Conventional Commit, PR to `development`.  
**Local agents:** jj bookmark `docs/prepare-0.x.y`, `scripts/jj-submit.sh`.

#### 1. `CHANGELOG.md` (Keep a Changelog)

Move `[Unreleased]` into a dated version section. Keep an empty `[Unreleased]` heading above it.

Shape (see existing `[0.1.3]` section):

- Keep a blank `## [Unreleased]` above the new version
- `## [0.x.y] — YYYY-MM-DD` plus one-line upgrade cue
- `### Added` / `### Changed` / `### Fixed` as appropriate
- `### Install` with `pip install opentide==0.x.y` and the `OPENTIDE_REPO_ROOT` + `opentide validate --strict` snippet used in prior versions

Footer compare links (bottom of `CHANGELOG.md`):

```markdown
[Unreleased]: https://github.com/OpenTideHQ/opentide/compare/v0.x.y...HEAD
[0.x.y]: https://github.com/OpenTideHQ/opentide/releases/tag/v0.x.y
```

Keep existing `[0.x.(y-1)]:` (etc.) rows.

#### 2. `docs/usage/releases.md`

Add a **new top section** (Fumadocs page users see). Copy the 0.1.3 block: title, date, upgrade cue, Install, what changed, Links (PyPI / GitHub Release / CHANGELOG).

#### 3. `.github/release-notes/v0.x.y.md`

GitHub Release body. Copy [`.github/release-notes/v0.1.3.md`](../../../.github/release-notes/v0.1.3.md):

- Title + date + "Patch on …"
- Install
- Fixed / Added (with issue links)
- Verify (commands; expect `0.x.y`)
- Links (PyPI, GitHub Release, CHANGELOG, Usage → Releases)

#### 4. User-facing install pins

Search the repo for the old pin (`opentide==0.1.3` or whatever the previous version is). Update **every** hit to the new version. Known locations from 0.1.3:

| File | Notes |
|------|--------|
| `README.md` | |
| `docs/index.md` | |
| `docs/usage/index.md` | Card copy too |
| `docs/usage/installation.md` | pip and uv pins |
| `docs/usage/quickstart.md` | |
| `docs/usage/why-opentide.md` | Latest-patch mention |
| `docs/usage/troubleshooting.md` | Pins **and** mention the new patch in the relevant bug sections |
| `docs/usage/workflows/agentic-setup.md` | |
| `docs/usage/workflows/ci-cd.md` | Hand-written pipeline examples and the callout above them |
| `docs/usage/migration/index.md` | |
| `docs/usage/migration/prompt.md` | |
| `docs/cli/index.md` | |
| `docs/mcp/index.md` | |
| `docs/mcp/installation.md` | |
| `docs/sdk/installation.md` | `dependencies = ["opentide==0.x.y"]` as well |

```bash
rg -n 'opentide==0\.[0-9]+\.[0-9]+' --glob '!CHANGELOG.md' --glob '!.github/release-notes/**'
```

Leave older historical sections in `CHANGELOG.md` / `docs/usage/releases.md` / old `.github/release-notes/` files alone.

#### 5. Do not touch generated version

`src/opentide/_version.py` is written by hatch-vcs. Do not commit edits to it.

#### 6. Local check

```bash
scripts/ci-local.sh --quick
scripts/validate-docs.sh   # if docs changed
```

---

### Step 1b — CI must actually be green

Before merge/release:

```bash
gh pr checks <n>
```

Required success:

| Check | Notes |
|-------|--------|
| Unit matrix Python 3.10–3.14 | |
| lint | ruff + ty |
| CLI E2E | Do **not** treat a skipped job (because unit tests failed) as success |
| docs | |
| CodeQL Analyze (python) | |
| CodeQL Analyze (actions) | |

CodeQL Analyze (actions) dying at "Uploading results" with no query findings is a CodeQL Action/runtime issue (v4 / Node 24), not a reason to skip the notes PR. Still wait for a green run or a known-infra skip that maintainers accept.

**Automerge:** `OpenTideHQ/opentide` currently has `allow_auto_merge: false`. Do not enable it unless the user asked. Merge the notes PR only when required checks on the **head SHA** are success (`gh pr checks` — skipped CLI E2E is not success). Then create the GitHub Release.

---

### Step 2 — GitHub Release (this publishes to PyPI)

**ONLY** after the notes PR is **merged to `development`**.

Confirm the merge commit contains the notes:

```bash
git fetch origin development
git log -1 --oneline origin/development
# CHANGELOG.md on that commit must contain ## [0.x.y]
git show origin/development:CHANGELOG.md | head -n 20
```

Then:

```bash
gh release create v0.x.y \
  --repo OpenTideHQ/opentide \
  --target development \
  --title "0.x.y" \
  --notes-file .github/release-notes/v0.x.y.md
```

`--target development` must resolve to that merge commit.

**Latest flag.** Do not pass `--latest` or `--latest=false` for the newest version: by default GitHub marks it **Latest**. When cutting several versions back to back, cut them in version order, and give each one the default flag. Pass `--latest=false` only when publishing an older version after a newer one already exists.

This bit 0.4.0. It was cut with `--latest=false` because 0.5.0 was about to follow, so Releases kept showing 0.3.0 as Latest. Verify:

```bash
gh release list --repo OpenTideHQ/opentide --limit 3   # new tag must show Latest
```

Watch [publish-pypi.yml](https://github.com/OpenTideHQ/opentide/actions/workflows/publish-pypi.yml). If the `pypi` environment has required reviewers, someone must approve. The job ends with **Verify PyPI lists every built file**, which fails unless PyPI lists both the wheel and the sdist.

---

### Step 3 — Prove PyPI

Wait for the publish workflow, then:

```bash
uv venv /tmp/opentide-0.x.y && source /tmp/opentide-0.x.y/bin/activate
uv pip install --no-cache --index-url https://pypi.org/simple "opentide==0.x.y"
python -c "import opentide; print(opentide.__version__)"
curl -s https://pypi.org/pypi/opentide/0.x.y/json | python -c \
  "import json,sys; print(sorted((u['packagetype'], u['filename']) for u in json.load(sys.stdin)['urls']))"
```

The Python check must print `0.x.y`, **not** `0.x.dev…`. The JSON check must list both a `bdist_wheel` and an `sdist`.

**CDN delay:** for about 10–15 minutes after a successful upload, PyPI can serve stale data from different edges:
- `/pypi/opentide/json` is cached for 900 s and `/simple/opentide/` for 600 s;
- `pip install` can report "No matching distribution";
- the per-version JSON can list only some files, even though both uploads succeeded.

Query-string cache busting does not help. Wait and retry with `--no-cache`. Do not retag or re-publish during that window.

If version is `0.1.dev…`: the tag was not on the checkout (`fetch-depth: 0` is already in the workflow; usually the Release targeted the wrong commit). Do not retag; fix target and publish from the correct tag.

---

### Step 4 — Group the shipped issues

Every release gets a tracking issue. Examples: [#285](https://github.com/OpenTideHQ/opentide/issues/285) and [#286](https://github.com/OpenTideHQ/opentide/issues/286) for 0.4.0 / 0.5.0, and [#301](https://github.com/OpenTideHQ/opentide/issues/301) for 0.6.0.

1. Create or reuse an issue titled `Release 0.x.y — …` with the `epic` label. Its body lists the scope, the bump rationale, and a PR → issue table.
2. Attach every shipped issue as a sub-issue. With the GitHub MCP, use `sub_issue_write`, which takes the issue's database `id`, not its number.
3. After Step 3, close shipped sub-issues that are still open, then close the tracking issue as completed. Link the GitHub Release and the PyPI page.

Milestones are optional; `setup-cli-v1` is the only precedent. The Cursor GitHub App token gets 403 on milestone creation, so a maintainer must create `0.x.y` first; agents can then assign issues to it.

## Failure table

Copied from [`docs/internal/pypi-trusted-publishing.md`](../../../docs/internal/pypi-trusted-publishing.md):

| Symptom | Cause / fix |
|--------|-------------|
| `0.1.dev…` | Tag not on the checked-out commit. Wrong `--target`. Do not retag; retarget. |
| 403 `invalid-publisher` | OIDC fields: owner `opentidehq` (lowercase), workflow `publish-pypi.yml`, env `pypi`. Re-run; do not retag. |
| `No module named 'hatch'` in Build package | `hatch build` isolated env (hatch 1.18.1 / hatchling 1.32.1). Publish uses `uv build`. A tag cut before that still runs the old YAML on `release: published`. From `development`: `gh api repos/OpenTideHQ/opentide/dispatches -f event_type=publish-pypi -f client_payload[checkout_ref]=v0.x.y`. Do not retag. |
| `502` / 5xx on upload, job failed, some files already on PyPI (0.4.0) | From `development`: `gh api repos/OpenTideHQ/opentide/dispatches -f event_type=publish-pypi -f client_payload[checkout_ref]=v0.x.y`. The upload sets `skip-existing: true`, so the retry uploads only the missing files. `gh run rerun` and `workflow_dispatch` return 403 for the GitHub App token (no `actions:write`), so dispatch is the agent path. Do not retag. |
| Verify PyPI lists every built file fails | Wait out the CDN delay (Step 3), then use the same dispatch retry. The step log prints the exact command. |
| New tag not shown as Latest | It was created with `--latest=false`. `gh release edit v0.x.y --repo OpenTideHQ/opentide --latest`. |
| Release exists but Publish to PyPI never starts | Workflow file on `development` failed GitHub's parser (`secrets` in `steps.if` is a common cause). Fix the workflow on `development`, then convert the GitHub Release to draft and back to published. Do not move the tag. |
| Core Metadata 2.5 | Already pinned to `2.4` in pyproject sdist/wheel. `uvx twine check dist/*` before tag. |

Job needs `id-token: write` and `contents: read` (already set in the workflow).

## Related

- [`docs/internal/pypi-trusted-publishing.md`](../../../docs/internal/pypi-trusted-publishing.md) — OIDC publisher fields, first-upload vs later releases
- [`docs/usage/releases.md`](../../../docs/usage/releases.md) — public release page
- [`CHANGELOG.md`](../../../CHANGELOG.md)
- [`.github/release-notes/v0.1.3.md`](../../../.github/release-notes/v0.1.3.md) — notes template
- [`docs-maintenance`](../docs-maintenance/SKILL.md) — Fumadocs pages in Step 1
- `AGENTS.md` — trunk, Conventional Commits, `scripts/jj-submit.sh`
