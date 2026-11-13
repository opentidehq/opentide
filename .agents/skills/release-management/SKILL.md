---
name: release-management
description: >-
  Cut opentide releases with the release train (publish.yml): changelog, install pins, the
  lockstep version, release candidates, then one Run workflow that tags and publishes the
  wheels, crates, npm packages and binaries with OIDC. Use when releasing, tagging v*, publishing
  to PyPI, crates.io or npm, or preparing 0.x.y notes.
---

# Release management — opentide

SOP for shipping a version of opentide. One version and one tag (`vX.Y.Z`) publish everything: the PyPI wheels and sdist, the crates (the `opentide` facade and the engine crates), the npm packages (`@opentide/opentide`, its native packages, the `opentide` alias, `@opentide/lsp-client`, `@opentide/lsp-worker`), and a GitHub Release with the `opentide` and `opentide-lsp` binaries, their installers, the engine assets editors pin, the SBOMs and `SHA256SUMS` ([`publish.yml`](../../../.github/workflows/publish.yml), UC-5.5). The Python version is **dynamic from git tags** via hatch-vcs (`pyproject.toml` `[tool.hatch.version] source = "vcs"`); do **not** hand-edit `src/opentide/_version.py`. The crates carry the same version in `Cargo.toml` (`[workspace.package]`), which `scripts/engine/release.py bump` sets; the npm packages get it from the workflow.

## When to use

- User asks to release, cut a version, publish to PyPI, bump the package, or "bundle this in a release"
- A user-facing fix/feature has landed on `development` but PyPI still shows the previous version
- Preparing notes / pins before a release, or a release candidate

## When NOT to release

| Situation | Do this instead |
|----------|-----------------|
| CI-only, docs-for-agents, CodeQL Action pins, E2E tests that do not change the installed CLI/SDK/schema | No release |
| Tagging HEAD before changelog / notes / pins exist | Step 1 first |
| Releasing from a feature branch | Merge notes to `development`, then Run workflow there |
| Pushing a `v*` tag or creating a Release by hand | Nothing publishes it: Run workflow on `publish.yml` creates both |

Never tag by hand. Trunk is `development`.

## Version mechanics

| Fact | Detail |
|------|--------|
| Package | `opentide` on PyPI |
| Tag | `v0.x.y` (leading `v`); a release candidate `v1.0.0-rc.N` (the Rust-core transition: 1.0.0, held at candidates) |
| Release | **Run workflow** on `development`, no inputs → [`publish.yml`](../../../.github/workflows/publish.yml) checks, builds, smoke-tests, attests, creates the tag + GitHub Release, then publishes to PyPI, crates.io and npm. Nothing else publishes: no workflow runs on a `v*` tag or a Release made by hand |
| Version before the tag | Newest dated `CHANGELOG.md` heading: `uv run python scripts/build/release.py version` |
| Lockstep | The crates are at that version: `python3 scripts/engine/release.py lockstep 0.x.y` (the workspace version and every internal pin). The workflow writes it into the npm packages (`release.py npm-version`) and checks them (`lockstep --npm`) |
| Auth | OIDC trusted publishing on all three registries. PyPI environment `pypi`, for releases and candidates (no TestPyPI). Workflow filename `publish.yml` everywhere. `CARGO_REGISTRY_TOKEN` only for a crate's first version (the first candidate's, for the six new names) |
| Engine tags | The engine's own `engine-vX.Y.Z` series (`engine-release.yml`) ended with the release train; the engine skill is retired |

## What a release publishes

| Where | What | Built by |
|-------|------|----------|
| PyPI | One `cp310-abi3` wheel per platform (manylinux_2_28 x86_64 and aarch64, macOS Intel and Apple silicon, Windows x64 and Arm64) and the sdist | cibuildwheel, hatchling and `hatch_build.py` (`[tool.cibuildwheel]` in `pyproject.toml`), `uv build --sdist` |
| crates.io | Every crate without `publish = false`, dependencies first: the engine crates, `opentide-schema`, `-schema-derive`, `-workspace`, `-compile`, `-connectors`, `-cli`, `-lsp`, and the facade `opentide` (`cargo install opentide --features cli`) | `scripts/engine/release.py publish` |
| npm | `@opentide/opentide` and its six native packages (napi-rs), the `opentide` alias, `@opentide/lsp-client`, `@opentide/lsp-worker`, with provenance | `bindings/node/build.mjs` per target, `npm pack` |
| GitHub Release | `opentide-vX.Y.Z-<target>` and `opentide-lsp-vX.Y.Z-<target>` for six targets, `opentide-installer.sh` and `.ps1`, `highlights-vX.Y.Z.zip`, `opentide-wasm-web-vX.Y.Z.zip`, the WASI build, the licences, seven CycloneDX SBOMs, `SHA256SUMS` (`release.py assets vX.Y.Z` lists them) | `engine-release-build.yml` |

Every artifact carries a GitHub artifact attestation (build provenance). **No musl builds** (no musllinux wheel, musl binary or musl npm package): the maintainer's decision; Alpine builds from the sdist. **No free-threaded wheel** (`cp314t`): it has no stable ABI, and builds from the sdist. **npm:** the standard napi-rs layout, the native packages named `@opentide/opentide-<platform>` (each with its `os`, `cpu`, glibc `libc`, one `.node` and `LICENSE`), and **no WebAssembly fallback** (`wasm32-wasi`: WASI preview 1 has no sockets under Node.js, so tenant commands could not work), [ADR 0006](../../../docs/internal/adr/0006-npm-packages.md#amendment-2026-11-12-the-package-layout-and-names) as amended. All are recorded in [`docs/internal/publishing.md`](../../../docs/internal/publishing.md#the-release-train).

## Patch vs minor

The package is pre-1.0, so the minor number carries breaking and behaviour changes. **The Rust core is 1.0.0**, released first as candidates (`1.0.0-rc.N` on crates.io, `1.0.0rcN` on PyPI) and held there until the maintainer accepts the final 1.0.0; breaking changes may land between candidates. Never cut the final 1.0.0 without that decision. Cut a **minor** (`0.x+1.0`) when any shipped change does one of these:

- changes what input is accepted (schema or model shape, validation strictness);
- changes CLI output, JSON fields, or exit codes that scripts depend on;
- changes generated files that users must regenerate (`opentide setup ci`, schemas, docs);
- adds a command or user-visible feature.

Otherwise, for fixes that restore documented behaviour without changing those surfaces, cut a **patch** (`0.x.y+1`).

Precedents:
- **0.4.0**: fixes changed output that scripts depend on, and a security fix required users to regenerate CI (#244).
- **0.5.0**: `threat.impact` and `threat.leverage` became lists (#189).

State the rationale in the version's summary or in the GitHub Release body ("It is a minor because …").

## Required two-step flow

- **Step 0** — the version: `release.py bump X.Y.Z` merged, and a release candidate run green (for a release that changes what is built or how; optional for a docs-only patch).
- **Step 1** — notes PR, merge to `development`.
- **Step 1b** — CI green on that PR.
- **Step 2** — Run **Publish** on `development` (this tags, creates the GitHub Release and publishes everywhere). Works from a cloud session.
- **Step 3** — prove PyPI, crates.io, npm and the binaries.
- **Step 4** — group the shipped issues under the release tracking issue and close it.

Do not skip Step 1. The tag must sit on the merge commit that **already contains** the changelog, usage notes, GitHub notes file, and install pins.

---

### Step 0 — Bump the crates, and run a release candidate

The crates carry the product version: in a pull request to `development` (it can be the notes PR of Step 1, or come before it so that a candidate can run first), or to `integration/unified-core` for a candidate cut there before it merges:

```bash
python3 scripts/engine/release.py bump 1.0.0      # workspace version, internal pins, Cargo.lock
python3 scripts/engine/release.py lockstep 1.0.0  # what the release guard checks
```

The `Cargo.lock` diff is only the workspace crates' `version` lines; anything else means Cargo re-resolved: restore the lock and bump again.

**Release candidate** (for the Rust-core transition; it may be retired after). Once the bump is on the branch, Run **Publish** on `integration/unified-core` (or `development`) with `release_candidate: 1` (then 2, ...); the guard refuses a candidate from any other branch, and a release from anything but `development`. It publishes `v1.0.0-rc.N` as pre-releases:

| Where | What |
|-------|------|
| GitHub | A **pre-release** (never Latest) tagged `v1.0.0-rc.N`, with every asset (binaries, installers, engine assets, SBOMs, `SHA256SUMS`) and attestation |
| PyPI | `1.0.0rcN` on **pypi.org** (environment `pypi`, no TestPyPI): `pip install --pre opentide`, `uv pip install --prerelease=allow opentide`, or `opentide==1.0.0rc1` |
| crates.io | Every crate at `1.0.0-rc.N`, in dependency order (the workflow runs `release.py bump 1.0.0-rc.N` in its own checkout; the branch keeps `1.0.0`). **Yankable, never deletable**; the first candidate **claims the new crate names** |
| npm | **Nothing.** Test the npm packages from ci.yml's `packages` artifacts (`npm-<platform>`) |

Its notes quote `## [Unreleased]`. Every job must be green, `Smoke the registries` included. A candidate needs no notes PR; the guard (`release.py check-candidate`) refuses one whose version is not above the newest dated `CHANGELOG.md` heading. **GitHub dispatches `publish.yml` only once a file of that name is on the default branch, `development`:** to run a candidate from `integration/unified-core` before it merges, a `publish.yml` stub must be on `development` first (`docs/internal/publishing.md`, "Release candidates").

**Dry run.** `dry_run: true` builds and smoke-tests every artifact and publishes nothing (no tag, no release, no attestation): any branch, any time.

**A build to test, nothing published.** ci.yml's full set (`packages`, `build-packages.yml`) keeps the wheels (`wheels-<platform>`) and npm tarballs (`npm-<platform>`) of a development version for 14 days: `gh run download <run-id> -R opentidehq/opentide -n wheels-linux-x64`, then `uv pip install opentide-*.whl`; `npm install ./opentide-opentide-*.tgz`. With a Rust toolchain: `uv tool install "git+https://github.com/opentidehq/opentide@<ref>"`.

### Step 1 — Prepare notes PR (must merge to `development` first)

Create a `docs:` (or `chore:`) PR against `development`.

- **Cloud agents:** branch `cursor/prepare-0.x.y-…`, Conventional Commit, PR to `development`.
- **Local agents:** branch `docs/prepare-0.x.y` from `origin/development`, `gh pr create --base development`.

What the three notes files say, and how, is the [`release-notes`](../release-notes/SKILL.md) skill:
the parts of a version (summary, Upgrade, Breaking, Added, Changed, Deprecated, Removed, Fixed,
Security, in that order) and how to write each entry. This step is where they go.

#### 1. `CHANGELOG.md` (Keep a Changelog)

Move `[Unreleased]` into a dated version section. Keep an empty `[Unreleased]` heading above it.

- Keep a blank `## [Unreleased]` above the new version
- `## [0.x.y] — YYYY-MM-DD`, then its summary paragraph
- The entries the pull requests added, in their parts (`### Upgrade`, `### Breaking`, `### Added`, …), in the order of the release-notes skill. No `### Install`: the install commands are in the other two files

Footer compare links (bottom of `CHANGELOG.md`):

```markdown
[Unreleased]: https://github.com/opentidehq/opentide/compare/v0.x.y...HEAD
[0.x.y]: https://github.com/opentidehq/opentide/releases/tag/v0.x.y
```

Keep existing `[0.x.(y-1)]:` (etc.) rows.

#### 2. `docs/usage/releases.md`

Add a **new top section**: the page [opentide.org/releases](https://opentide.org/releases/) renders. Its shape is in the release-notes skill: heading, summary, **Install** (three lines), **Upgrade**, the change parts as bold lines, the CHANGELOG line with the version's anchor, **Links** (PyPI / GitHub Release / CHANGELOG).

#### 3. `.github/release-notes/v0.x.y.md`

GitHub Release body, in the order of the release-notes skill:

- Title + date + "Minor release on …" / "Patch release on …", then the summary
- `## Upgrade`: a fence with the install and upgrade commands, and a Before/Now table where behaviour changed
- `## Breaking`, `## Added`, `## Changed`, … (with issue links)
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
uv run python scripts/build/release.py check v0.x.y   # what the release guard checks
python3 scripts/engine/release.py lockstep 0.x.y      # the crates are at the version (Step 0)
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
| Unit matrix Python 3.10–3.14 | 3.11–3.13 run in CI's full set: Run workflow on `development` before a release if the last nightly is not green |
| lint | ruff + ty |
| CLI E2E | Do **not** treat a skipped job (because unit tests failed) as success |
| docs | In CI's full set: give the notes PR the `full-ci` label (then push) so it runs |
| CodeQL Analyze (python) | |
| CodeQL Analyze (actions) | |

CodeQL Analyze (actions) dying at "Uploading results" with no query findings is a CodeQL Action/runtime issue (v4 / Node 24), not a reason to skip the notes PR. Still wait for a green run or a known-infra skip that maintainers accept.

**Automerge:** `opentidehq/opentide` currently has `allow_auto_merge: false`. Do not enable it unless the user asked. Merge the notes PR only when required checks on the **head SHA** are success (`gh pr checks` — skipped CLI E2E is not success). Then create the GitHub Release.

---

### Step 2 — Release from `development` (this publishes everywhere)

**ONLY** after the notes PR is **merged to `development`** and `development` CI is green.

Run **Publish** on `development` with no inputs:

| Where | How |
|-------|-----|
| Cloud session (no `gh`) | GitHub MCP `actions_run_trigger`: `method: run_workflow`, `workflow_id: publish.yml`, `ref: development`, no inputs (a candidate: `ref: integration/unified-core`, `inputs: {release_candidate: "1"}`) |
| Browser | Actions → Publish → Run workflow → branch `development`, inputs empty |
| Local | `gh workflow run publish.yml --repo opentidehq/opentide --ref development` |

The run:

1. **Release guard** reads the version from the newest dated `CHANGELOG.md` heading, runs `scripts/build/release.py check v0.x.y` (changelog section and links, `.github/release-notes/v0.x.y.md`, top of `docs/usage/releases.md`, README pin) and `scripts/engine/release.py lockstep 0.x.y`. It refuses a tag or Release that already exists and a run from another branch.
2. **Checks**: every crate built from its package (`cargo package`), the licence scan.
3. **Builds**: the wheels, the sdist, the npm native packages and tarballs, the GitHub Release's assets (binaries, installers, engine assets, SBOMs, `SHA256SUMS`).
4. **Smoke tests**: `pip install` the wheel and `opentide --version` (Linux, macOS, Windows); a build from the sdist; the npm tarballs published to a throwaway local registry and `npm install @opentide/opentide` in a clean project, which must pick the host's native package, run `npx opentide --version`, load the SDK and type-check (`scripts/engine/npm-local-registry/test.mjs`; Linux, macOS, Windows); `cargo install opentide --features cli` from the crates' packages; the binary installers.
5. **Attestations** of every artifact, then **GitHub Release**: the tag `v0.x.y` on the built commit (`--target $GITHUB_SHA`) with the notes file as body, every asset attached. Latest by default.
6. **Verify the published assets**: `sha256sum -c`, the asset set, and each asset's attestation signed by `publish.yml` on `development`.
7. **Publish to PyPI**, **Publish to crates.io** (dependencies first), **Publish to npm**, in parallel; then **Smoke the registries** installs from each.

The Release comes from `GITHUB_TOKEN`, which starts no other workflow: one publish per version.

Find the run (REST; `gh run list` uses GraphQL, which cloud sessions cannot reach):

```bash
gh api "repos/opentidehq/opentide/actions/workflows/publish.yml/runs?per_page=1" \
  --jq '.workflow_runs[0] | "\(.id) \(.status) \(.conclusion) \(.head_sha)"'
```

**Resume a release that failed partway.** Never retag, never delete a published Release. Run **Publish** on `development` with `checkout_ref: v0.x.y` (cloud: `actions_run_trigger` with `inputs: {checkout_ref: v0.x.y}`; an App token without `actions: write`: the `repository_dispatch` below). It rebuilds from the tag, uploads nothing to its Release (consumers pinned those digests), verifies the published assets, and publishes only what each registry lacks (`skip-existing` on PyPI, crates already on crates.io and npm versions already there are skipped).

```bash
gh api repos/opentidehq/opentide/dispatches \
  -f event_type=publish \
  -f client_payload[checkout_ref]=v0.x.y
```

**Latest flag.** A release is created without `--latest`, so GitHub marks it **Latest**; a candidate is a pre-release with `--latest=false`. Cut versions in order. This bit 0.4.0, cut by hand with `--latest=false`: Releases kept showing 0.3.0 as Latest. Verify:

```bash
gh release list --repo opentidehq/opentide --limit 3   # new tag must show Latest
gh api repos/opentidehq/opentide/releases/latest --jq .tag_name   # REST, works in cloud sessions
```

Watch [publish.yml](https://github.com/opentidehq/opentide/actions/workflows/publish.yml). If the `pypi` environment has required reviewers, someone must approve. The PyPI job ends with **Verify PyPI lists every built file**, which fails unless PyPI lists every wheel and the sdist.

---

### Step 3 — Prove PyPI, crates.io, npm and the binaries

**Smoke the registries**, the run's last job, installs from each registry. Check by hand too. Wait for the publish workflow, then:

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

The other registries and the Release:

```bash
curl -s -A release-check https://crates.io/api/v1/crates/opentide | jq -r '.crate.max_version'   # 0.x.y
npm view @opentide/opentide dist-tags                                  # latest: 0.x.y
npx --yes @opentide/opentide@0.x.y --version
gh api repos/opentidehq/opentide/releases/tags/v0.x.y --jq '.tag_name, .prerelease, (.assets|length)'
python3 scripts/engine/release.py assets v0.x.y | wc -l                 # the same count
```

---

### Step 4 — Group the shipped issues

Every release gets a tracking issue. Examples: [#285](https://github.com/opentidehq/opentide/issues/285) and [#286](https://github.com/opentidehq/opentide/issues/286) for 0.4.0 / 0.5.0, and [#301](https://github.com/opentidehq/opentide/issues/301) for 0.6.0.

1. Create or reuse an issue titled `Release 0.x.y — …` with the `epic` label. Its body lists the scope, the bump rationale, and a PR → issue table.
2. Attach every shipped issue as a sub-issue. With the GitHub MCP, use `sub_issue_write`, which takes the issue's database `id`, not its number.
3. After Step 3, close shipped sub-issues that are still open, then close the tracking issue as completed. Link the GitHub Release and the PyPI page.

Milestones are optional; `setup-cli-v1` is the only precedent. The Cursor GitHub App token gets 403 on milestone creation, so a maintainer must create `0.x.y` first; agents can then assign issues to it.

## Failure table

| Symptom | Cause / fix |
|--------|-------------|
| Guard: `v0.x.y is already tagged` | That version is out. Merge the next version's notes PR; to finish publishing the existing tag, run with `checkout_ref=v0.x.y` |
| Guard: `CHANGELOG.md's newest version is …` / `… is missing` | The notes PR has not merged, or misses a piece (`release.py check` names it). Fix it on `development` and run again |
| Guard: `the workspace version in Cargo.toml is …, not 0.x.y` | Step 0: `release.py bump 0.x.y` in a pull request, merged |
| Guard: `… is not newer than …, the last release` (a candidate) | Bump the workspace past the last release first (Step 0) |
| Guard: `Run the release from development` | Run workflow was started on another branch. Pick `development` (a `dry_run` runs anywhere) |
| Guard: `Run a release candidate from integration/unified-core or development` | A candidate was started on another branch. Pick one of those two |
| Run workflow does not list Publish, or the API cannot find `publish.yml` | `publish.yml` is not on `development`, the default branch, yet: land the stub (`docs/internal/publishing.md`, "Release candidates") |
| A smoke test failed | Nothing was tagged or published. Fix on `development`, run again |
| A registry job failed after the **GitHub Release** job created the tag | Run workflow with `checkout_ref=v0.x.y` (cloud: `actions_run_trigger` with `inputs: {checkout_ref: v0.x.y}`). Do not delete the tag or the Release |
| `Verify the published assets` failed | It is the published assets that failed (sums, set, attestation): fix the cause, then resume with `checkout_ref`, or cut a patch release |
| 403 `invalid-publisher` on PyPI | OIDC fields: owner `opentidehq` (lowercase), workflow `publish.yml`, environment `pypi` (a candidate's too). Re-run; do not retag |
| crates.io: `trusted publishing tokens do not support creating new crates` with no `CARGO_REGISTRY_TOKEN` | A crate's first version needs the stored token (docs/internal/publishing.md, step 10). Add the secret, resume |
| npm: `E404` / `ENEEDAUTH` on publish | The package has no trusted publisher for `publish.yml`, or it expired (two days without a publish). Register it, resume |
| `502` / 5xx on PyPI upload, some files already there (0.4.0) | Resume with `checkout_ref=v0.x.y`; `skip-existing` uploads only the missing files. The step log prints the dispatch command |
| Verify PyPI lists every built file fails | Wait out the CDN delay (Step 3), then resume |
| New tag not shown as Latest | `gh release edit v0.x.y --repo opentidehq/opentide --latest` |
| Core Metadata 2.5 | Already pinned to `2.4` in pyproject sdist/wheel. `uvx twine check dist/*` before tag |

The registry jobs need `id-token: write` (already set on `pypi`, `crates`, `npm` and `attest`, and on no other job).

## Related

- [`docs/internal/publishing.md`](../../../docs/internal/publishing.md) — every name, owner and trusted publisher, the release train's decisions, the maintainer's setup (step 10)
- [`docs/internal/pypi-trusted-publishing.md`](../../../docs/internal/pypi-trusted-publishing.md) — PyPI's OIDC publisher fields
- [`docs/usage/releases.md`](../../../docs/usage/releases.md) — public release page
- [`CHANGELOG.md`](../../../CHANGELOG.md)
- [`release-notes`](../release-notes/SKILL.md) — what the notes say, and the shape of each file
- [`.github/release-notes/v0.22.0.md`](../../../.github/release-notes/v0.22.0.md) — a GitHub Release body
- [`docs-maintenance`](../docs-maintenance/SKILL.md) — Fumadocs pages in Step 1
- `AGENTS.md` — trunk, Conventional Commits, branch and PR workflow
