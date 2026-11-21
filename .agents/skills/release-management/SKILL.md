---
name: release-management
description: >-
  Cut opentide releases with the release train (publish.yml): changelog, install pins, the
  lockstep version, internal release candidates (a draft GitHub pre-release, no registry), then one Run workflow that tags and publishes the
  wheels, crates, npm packages and binaries with OIDC, and the follow-up review of the
  opentidehq/skills agent skills. Use when releasing, tagging v*, publishing to PyPI, crates.io
  or npm, or preparing 0.x.y notes.
---

# Release management — opentide

SOP for shipping a version of opentide. One version and one tag (`vX.Y.Z`) publish everything: the PyPI wheels and sdist, the crates (the `opentide` facade and the engine crates), the npm packages (`@opentide/opentide`, its native packages, the `opentide` alias, `@opentide/lsp-client`, `@opentide/lsp-worker`, `@opentide/wasi-host`), and a GitHub Release with the `opentide` and `opentide-lsp` binaries, their installers, the engine assets editors pin, the SBOMs and `SHA256SUMS` ([`publish.yml`](../../../.github/workflows/publish.yml), UC-5.5). The version is the Cargo workspace's (`[workspace.package]` in `Cargo.toml`), which `scripts/engine/release.py bump` sets: the crates carry it, and maturin builds the Python wheel at it (`bindings/python/` takes the workspace's; a candidate's `X.Y.ZrcN` is written in the workflow's checkout by `release.py pypi-version`); the npm packages get it from the workflow.

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
| Tag | `v0.x.y` (leading `v`); a release candidate `v1.0.0-rc.N` (the Rust-core transition: 1.0.0, held at candidates; `internal_candidate` is a draft GitHub pre-release, `release_candidate` a public one on GitHub, PyPI and crates.io: `1.0.0-rc.1` is out) |
| Release | **Run workflow** on `development`, no inputs → [`publish.yml`](../../../.github/workflows/publish.yml) checks, builds, smoke-tests, attests, creates the tag + GitHub Release, then publishes to PyPI, crates.io and npm. Nothing else publishes: no workflow runs on a `v*` tag or a Release made by hand |
| Version before the tag | Newest dated `CHANGELOG.md` heading: `uv run python scripts/build/release.py version` |
| Lockstep | The crates are at that version: `python3 scripts/engine/release.py lockstep 0.x.y` (the workspace version and every internal pin). The workflow writes it into the npm packages (`release.py npm-version`) and checks them (`lockstep --npm`) |
| Auth | OIDC trusted publishing on all three registries. PyPI environment `pypi`, for releases and candidates (no TestPyPI). Workflow filename `publish.yml` everywhere. `CARGO_REGISTRY_TOKEN` only for a crate's first version (`1.0.0-rc.1` used it for the eight new names, and every crate now trusts `publish.yml`: **delete** the secret, do not only revoke the token, and add one again only for a crate added later) |
| Engine tags | The engine's own `engine-vX.Y.Z` series (`engine-release.yml`) ended with the release train; its skill, `engine-release`, was removed |

## What a release publishes

| Where | What | Built by |
|-------|------|----------|
| PyPI | One `cp310-abi3` wheel per platform (manylinux_2_28 x86_64 and aarch64, macOS Intel and Apple silicon, Windows x64 and Arm64) and the sdist | maturin (`[tool.maturin]` in `pyproject.toml`) through PyO3/maturin-action in `build-packages.yml`, each wheel smoke-tested on its own OS; `maturin sdist` |
| crates.io | Every crate without `publish = false`, dependencies first: the engine crates, `opentide-schema`, `-schema-derive`, `-workspace`, `-compile`, `-connectors`, `-cli`, `-lsp`, and the facade `opentide` (`cargo install opentide --features cli`) | `scripts/engine/release.py publish` |
| npm | `@opentide/opentide` and its six native packages (napi-rs), the `opentide` alias, `@opentide/lsp-client`, `@opentide/lsp-worker`, `@opentide/wasi-host`, with provenance | `bindings/node/build.mjs` per target, `npm pack` |
| GitHub Release | `opentide-vX.Y.Z-<target>` and `opentide-lsp-vX.Y.Z-<target>` for six targets, `opentide-installer.sh` and `.ps1`, `highlights-vX.Y.Z.zip`, `opentide-wasm-web-vX.Y.Z.zip`, the WASI build, the licences, eight CycloneDX SBOMs, `SHA256SUMS` (`release.py assets vX.Y.Z` lists them) | `engine-release-build.yml` |

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

State the rationale in the GitHub Release body ("It is a minor because …"), never in the headline.

## Required two-step flow

- **Step 0** — the version: `release.py bump X.Y.Z` merged, and an internal candidate run green (for a release that changes what is built or how; optional for a docs-only patch).
- **Step 1** — notes PR, merge to `development`.
- **Step 1b** — CI green on that PR.
- **Step 2** — Run **Publish** on `development` (this tags, creates the GitHub Release and publishes everywhere). Works from a cloud session.
- **Step 3** — prove PyPI, crates.io, npm and the binaries.
- **Step 4** — group the shipped issues under the release tracking issue and close it.

Do not skip Step 1. The tag must sit on the merge commit that **already contains** the changelog, usage notes, GitHub notes file, and install pins.

---

### Step 0 — Bump the crates, and run an internal candidate

The crates carry the product version: in a pull request to `development` (it can be the notes PR of Step 1, or come before it so that a candidate can run first), or to `integration/unified-core` for a candidate cut there before it merges:

```bash
python3 scripts/engine/release.py bump 1.0.0      # workspace version, internal pins, Cargo.lock
python3 scripts/engine/release.py lockstep 1.0.0  # what the release guard checks
```

The `Cargo.lock` diff is only the workspace crates' `version` lines; anything else means Cargo re-resolved: restore the lock and bump again.

**Internal candidate.** Once the bump is on the branch, Run **Publish** on `integration/unified-core` (or `development`) with `internal_candidate: 1` (then 2, ...) and no other input. **Nothing reaches PyPI, crates.io or npm**, and no OIDC token is minted. The guard refuses another branch, `internal_candidate` combined with `release_candidate`, `dry_run` or `checkout_ref`, an existing tag, crates off the version (lockstep) and a version not above the last release (`release.py check-candidate`). Everything is built and smoke-tested as for a release; then the `internal-release` job (`contents: write` only) pushes the tag `v1.0.0-rc.N` on the commit built and creates a **draft** pre-release (never Latest), `1.0.0-rc.N (internal)`, with every binary and release asset (`SHA256SUMS`, SBOMs), every wheel, the sdist, every `.crate` and every npm tarball, plus `PACKAGES-SHA256SUMS` over those packages. `attest`, `release`, `verify-assets`, `pypi`, `crates`, `npm` and `smoke-registries` are skipped.

- Find it: Releases page, **Draft** at the top (write access only), or `gh release download v1.0.0-rc.N --dir rcN`.
- Promote it: edit the draft, **Publish release** (still a pre-release, still on no registry).
- Delete it: `gh release delete v1.0.0-rc.N --cleanup-tag --yes` (the draft and its tag), then rerun N or cut N+1.

**Public release candidate: enabled for 1.0.0-rc.N** (`public_candidates=true` in the guard; `false` refuses it again, a `dry_run` aside, and refuses to resume a `-rc` tag). `release_candidate: N` publishes `v1.0.0-rc.N` as pre-releases:

| Where | What |
|-------|------|
| GitHub | A **pre-release** (never Latest) tagged `v1.0.0-rc.N`, with every asset (binaries, installers, engine assets, SBOMs, `SHA256SUMS`) and attestation |
| PyPI | `1.0.0rcN` on **pypi.org** (environment `pypi`, no TestPyPI): `pip install --pre opentide`, `uv pip install --prerelease=allow opentide`, or `opentide==1.0.0rc1` |
| crates.io | Every crate at `1.0.0-rc.N`, in dependency order (the workflow runs `release.py bump 1.0.0-rc.N` in its own checkout; the branch keeps `1.0.0`). **Yankable, never deletable**; the first candidate **claims the new crate names** |
| npm | **Nothing.** Test the npm packages from ci.yml's `release` artifacts (`npm-packages`) |

Its notes are `.github/release-notes/v1.0.0-rc.N.md` when that file exists (a short summary: what changed, what breaks, how to upgrade; the granular entries stay in `CHANGELOG.md`), else they quote `## [Unreleased]`. Every job must be green, `Smoke the registries` included. A candidate needs no notes PR; the guard (`release.py check-candidate`) refuses one whose version is not above the newest dated `CHANGELOG.md` heading. **GitHub dispatches `publish.yml` only once a file of that name is on the default branch, `development`:** to run a candidate from `integration/unified-core` before it merges, a `publish.yml` stub must be on `development` first (`docs/internal/publishing.md`, "Release candidates"). The stub has no `repository_dispatch` trigger either: resume a candidate with a Run workflow **on `integration/unified-core`** (Step 2).

**Dry run.** `dry_run: true` builds and smoke-tests every artifact and publishes nothing (no tag, no release, no attestation): any branch, any time.

**A build to test, nothing published.** ci.yml's `release` job (`release-build.yml`; nightly, release PR, `scope: release`) keeps the wheels (`wheels-<platform>`) and npm tarballs (`npm-packages`) of a development version for 14 days: `gh run download <run-id> -R opentidehq/opentide -n wheels-linux-x64`, then `uv pip install opentide-*.whl`; `npm install ./2-package/opentide-opentide-*.tgz ./1-native/opentide-opentide-<platform>-*.tgz`. With a Rust toolchain: `uv tool install "git+https://github.com/opentidehq/opentide@<ref>"`.

### Step 1 — Prepare notes PR (must merge to `development` first)

Create a `docs:` (or `chore:`) PR against `development`.

- **Cloud agents:** branch `cursor/prepare-0.x.y-…`, Conventional Commit, PR to `development`.
- **Local agents:** branch `docs/prepare-0.x.y` from `origin/development`, `gh pr create --base development`.

What the three notes files say, and how, is the [`release-notes`](../release-notes/SKILL.md) skill:
the parts of a version (headline, Upgrade, Breaking, Added, Changed, Deprecated, Removed, Fixed,
Security, in that order) and how to write each entry. This step is where they go.

#### 1. `CHANGELOG.md` (Keep a Changelog)

Move `[Unreleased]` into a dated version section. Keep an empty `[Unreleased]` heading above it.

- Keep a blank `## [Unreleased]` above the new version
- `## [0.x.y] — YYYY-MM-DD`, then its headline paragraph (at most 25 words)
- The entries the pull requests added, in their parts (`### Upgrade`, `### Breaking`, `### Added`, …), in the order of the release-notes skill. No `### Install`: the install commands are in the other two files

Footer compare links (bottom of `CHANGELOG.md`):

```markdown
[Unreleased]: https://github.com/opentidehq/opentide/compare/v0.x.y...HEAD
[0.x.y]: https://github.com/opentidehq/opentide/releases/tag/v0.x.y
```

Keep existing `[0.x.(y-1)]:` (etc.) rows.

#### 2. `docs/usage/releases.md`

Add a **new top section**: the page [opentide.org/releases](https://opentide.org/releases/) renders. Its shape is in the release-notes skill: heading, headline, **Install** (three lines), **Upgrade**, the change parts as bold lines, the CHANGELOG line with the version's anchor, **Links** (PyPI / GitHub Release / CHANGELOG).

#### 3. `.github/release-notes/v0.x.y.md`

GitHub Release body, in the order of the release-notes skill:

- Title + date + "Minor release on …" / "Patch release on …", then the headline
- `## Upgrade`: a fence with the install and upgrade commands, and a Before/Now table where behaviour changed
- `## Breaking`, `## Added`, `## Changed`, … (with issue links)
- Verify (commands; expect `0.x.y`)
- Links (PyPI, GitHub Release, CHANGELOG, Usage → Releases)

#### 4. User-facing install pins

Search the repo for the old pin (`opentide==0.1.3` or whatever the previous version is). Update **every** hit to the new version. A release candidate changes none of the release pins: `README.md` (the PyPI page) keeps the newest stable pin in the prose below its install block, and while a candidate is current its first install command is `pip install --pre opentide` (no exact candidate pin: `tests/test_docs/test_readme_on_pypi.py` refuses one, and `--pre` needs no edit per candidate; an exact `opentide==1.0.0rcN` is a pre-release pin, which `scripts/build/release.py`'s `_PIN` and `tests/test_docs/test_docs_version_claims.py` do not read as a release pin); the pins move at the final release's notes PR, which also puts the stable pin back first in the README's install block. The pages that document the 1.0 API (`docs/index.md`, `docs/cli/index.md`, `docs/mcp/index.md`, `docs/mcp/installation.md`, `docs/sdk/installation.md`) do not pin the stable release while 1.0 is a candidate: 0.28.1 has no `opentide.Workspace`, so each shows `pip install --pre opentide` and the candidate's `opentide==1.0.0rcN`, linking `docs/usage/installation.md#release-candidates`. Each candidate moves their `rcN` with the installation page's (`tests/test_docs/test_docs_version_claims.py` checks that every `opentide==1.0.0rcN` in `docs/` agrees); the final release gives them the release pin. A candidate does update the candidate's own text: the **Release candidates** section of `docs/usage/installation.md` (the `1.0.0rcN` and `1.0.0-rc.N` pins, the tag in the GitHub Release URLs, the installer and `SHA256SUMS` commands) and the `=1.0.0-rc.N` pins in `docs/sdk/rust.md`'s Install section; the final release removes both, with the section's pointers from the PyPI install paragraph and the Rust page. `README.md`'s links stay absolute (`https://github.com/opentidehq/opentide/blob/development/...`): PyPI renders it away from the repository (`tests/test_docs/test_readme_on_pypi.py`). Known locations from 0.1.3:

| File | Notes |
|------|--------|
| `README.md` | The newest stable pin stays (the release check reads it); a candidate adds `pip install --pre opentide` as the first install command, the final release puts the stable pin first again |
| `docs/index.md` | A candidate: `--pre` in the Quick start, and the sentence after the "latest release" claim saying `pip install opentide` still installs 0.28.1, beside the claim, which stays the newest release. The final release: the claim and the pin name 1.0.0, and that sentence, the `--pre` command and the `release-candidates` link go |
| `docs/usage/index.md` | Card copy too |
| `docs/usage/installation.md` | pip and uv pins; the **Release candidates** section: updated by each candidate, removed by the final release |
| `docs/usage/quickstart.md` | |
| `docs/usage/why-opentide.md` | Latest-patch mention |
| `docs/usage/troubleshooting.md` | Pins **and** mention the new patch in the relevant bug sections |
| `docs/usage/workflows/agentic-setup.md` | |
| `docs/usage/workflows/ci-cd.md` | Hand-written pipeline examples and the callout above them |
| `docs/cli/index.md` | A candidate: `--pre` and the candidate's pin, linking the installation page's Release candidates, and the sentence "`pip install opentide` installs 0.28.1". The final release: the release pin, and that sentence, the `--pre` command and the link go (they have no pin, so only `test_a_page_of_the_1_0_api_installs_the_candidate` catches them) |
| `docs/mcp/index.md` | As `docs/cli/index.md`; its sentence is "… without `--pre` it installs 0.28.1" in the Quick start paragraph |
| `docs/mcp/installation.md` | As `docs/cli/index.md`; its sentence follows the PyPI install block |
| `docs/sdk/rust.md` | Install: the `=1.0.0-rc.N` pins of a candidate; the final release installs `opentide = "1"` and drops the candidate text |
| `docs/sdk/installation.md` | `dependencies = ["opentide==0.x.y"]` as well; a candidate: the candidate's pin in both blocks, as `docs/cli/index.md`, with its sentence that `pip install opentide` still installs 0.28.1 |

```bash
rg -n 'opentide==0\.[0-9]+\.[0-9]+' --glob '!CHANGELOG.md' --glob '!.github/release-notes/**'
```

Leave older historical sections in `CHANGELOG.md` / `docs/usage/releases.md` / old `.github/release-notes/` files alone.

The explorer pin is the other pin a release checks: `EXPLORER_RELEASE` and `EXPLORER_COMMIT` in
`crates/opentide-compile/src/ci/mod.rs` name the opentidehq/explorer release (tag and its commit)
that `setup ci --explorer-pages` builds the site from (#1693). When this release changes the bundle
`generate explorer` writes, or an explorer release reads a new one, bump both together, with
`docs/cli/setup.md`'s `--explorer-pages` row, and re-render the recorded pipelines
(`OPENTIDE_CI_RENDERED`, `crates/opentide-compile/tests/setup_ci.rs`) and the `setup ci`
snapshots.

#### 5. The version is the workspace's

The wheel's version is the Cargo workspace's (`bindings/python/` takes it; maturin writes it into
the wheel), so `scripts/engine/release.py bump X.Y.Z` in the notes PR sets the Python package's
version too. Never give `bindings/python/Cargo.toml` a version of its own: a candidate's
(`X.Y.ZrcN`) and a CI build's (`X.Y.Z.devN`) are written there by `release.py pypi-version` in the
workflow's checkout only.

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
| Unit matrix Python 3.10–3.14 | 3.10–3.13 run in CI's nightly set: Run workflow on `development` before a release if the last nightly is not green |
| lint | ruff + ty |
| CLI E2E | Do **not** treat a skipped job (because unit tests failed) as success |
| docs | ci.yml's `docs` job: on every pull request that changes `docs/`, and in a release pull request's checks |
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
| Cloud session (no `gh`) | GitHub MCP `actions_run_trigger`: `method: run_workflow`, `workflow_id: publish.yml`, `ref: development`, no inputs (an internal candidate: `ref: integration/unified-core`, `inputs: {internal_candidate: "1"}`) |
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

**Resume a release that failed partway.** Never retag, never delete a published Release. Run **Publish** with `checkout_ref: v0.x.y` (a candidate: `vX.Y.Z-rc.N`). It rebuilds from the tag, uploads nothing to its Release (consumers pinned those digests), verifies the published assets, and publishes only what each registry lacks (`skip-existing` on PyPI, crates already on crates.io and npm versions already there are skipped). **The ref matters:** a run uses the `publish.yml` of the ref it is dispatched on.

| When | Resume with |
|------|-------------|
| **While `integration/unified-core` has not merged** (`development`'s `publish.yml` is a stub with no `repository_dispatch`) | Run **on `integration/unified-core`**: `gh workflow run publish.yml --repo opentidehq/opentide --ref integration/unified-core -f checkout_ref=v1.0.0-rc.N`; cloud: `actions_run_trigger` with `method: run_workflow`, `workflow_id: publish.yml`, `ref: integration/unified-core`, `inputs: {checkout_ref: "v1.0.0-rc.N"}`. The `repository_dispatch` below does nothing here: GitHub runs it from the stub on `development` |
| **After the merge** | Run on `development` with `checkout_ref: v0.x.y` (cloud: `actions_run_trigger`, `ref: development`, `inputs: {checkout_ref: v0.x.y}`); an App token without `actions: write`: the `repository_dispatch` below |

```bash
# After the merge only: development's publish.yml has the repository_dispatch trigger.
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

---

### Step 5 — Bring the agent skills up to date

[opentidehq/skills](https://github.com/opentidehq/skills) is what `opentide setup skills` and the opentide Agent Plugin install, so a release the skills do not describe teaches agents the previous one. Its `coverage.json` maps every platform key to a skill and records the capabilities (`can_deploy`, `can_validate`, `can_query`) and the last release reviewed (`reviewed_against`); its daily CI check compares that with the latest PyPI release's `opentide --json info` and opens a *Review skills against opentide 0.x.y* issue when they differ.

After Step 3, read this release's `CHANGELOG.md` section and, in opentidehq/skills, follow [Keeping skills in step with opentide](https://github.com/opentidehq/skills/blob/main/AGENTS.md#keeping-skills-in-step-with-opentide):

1. A new platform needs a platform skill naming `configurations.<key>` before the release is announced as supported by the plugin.
2. Update the platform skills whose capabilities, rule types, languages or deploy behaviour changed, and any skill naming a renamed CLI command, flag or MCP tool.
3. Bump `reviewed_against` to `0.x.y` in `coverage.json`, even when nothing else changed, and run `./scripts/check-opentide-coverage.sh --engine` with this release installed.

Link that pull request from the tracking issue in Step 4.

## Failure table

| Symptom | Cause / fix |
|--------|-------------|
| Guard: `v0.x.y is already tagged` | That version is out. Merge the next version's notes PR; to finish publishing the existing tag, run with `checkout_ref=v0.x.y` |
| Guard: `CHANGELOG.md's newest version is …` / `… is missing` | The notes PR has not merged, or misses a piece (`release.py check` names it). Fix it on `development` and run again |
| Guard: `the workspace version in Cargo.toml is …, not 0.x.y` | Step 0: `release.py bump 0.x.y` in a pull request, merged |
| Guard: `… is not newer than …, the last release` (a candidate) | Bump the workspace past the last release first (Step 0) |
| Guard: `Run the release from development` | Run workflow was started on another branch. Pick `development` (a `dry_run` runs anywhere) |
| Guard: `Run a release candidate from integration/unified-core or development` / `Run an internal candidate from …` | A candidate was started on another branch. Pick one of those two |
| Guard: `public release candidates are disabled while the internal channel exists` | `public_candidates` is `false` in the guard (it is `true` for 1.0.0-rc.N). Use `internal_candidate: N` (or `release_candidate` with `dry_run`, as a rehearsal). A `checkout_ref=vX.Y.Z-rc.N` resume is refused for the same reason |
| Guard: `internal_candidate cannot be combined with …` | Pass `internal_candidate` alone |
| `internal-release`: `two assets are named …` | Two artifacts carry one file name; fix the build, rerun (delete the draft and tag first if they were created) |
| Run workflow does not list Publish, or the API cannot find `publish.yml` | `publish.yml` is not on `development`, the default branch, yet: land the stub (`docs/internal/publishing.md`, "Release candidates") |
| A smoke test failed | Nothing was tagged or published. Fix on `development`, run again |
| A registry job failed after the **GitHub Release** job created the tag | Run workflow with `checkout_ref=v0.x.y`, on `integration/unified-core` while `development`'s `publish.yml` is the stub, else on `development` (cloud: `actions_run_trigger` with `ref` and `inputs: {checkout_ref: v0.x.y}`). Do not delete the tag or the Release |
| `Verify the published assets` failed | It is the published assets that failed (sums, set, attestation): fix the cause, then resume with `checkout_ref`, or cut a patch release |
| 403 `invalid-publisher` on PyPI | OIDC fields: owner `opentidehq` (lowercase), workflow `publish.yml`, environment `pypi` (a candidate's too). Re-run; do not retag |
| crates.io: `trusted publishing tokens do not support creating new crates` with no `CARGO_REGISTRY_TOKEN` | A crate's first version needs the stored token (docs/internal/publishing.md, step 10). Add the secret, resume, then **delete** it again. The trust step runs only when the trusted login failed or a crate was created with the token; a failure there is a warning |
| crates.io: `::warning::Trusted publishing was not registered …` | The crates are published. Register `publish.yml` on the crates named in the log (crate settings, Trusted Publishing), or add a token with the `trusted-publishing` scope and resume |
| crates.io: `rate limited, retrying in …` | Normal for new crates: the job waits until the time crates.io names (capped at 30 minutes, 11 without one) and tries again, 12 times at most |
| npm: `E404` / `ENEEDAUTH` on publish | The package has no trusted publisher for `publish.yml`, or it expired (two days without a publish). Register it, resume |
| `502` / 5xx on PyPI upload, some files already there (0.4.0) | Resume with `checkout_ref=v0.x.y` on the ref that has the full `publish.yml` (`integration/unified-core` until it merges); `skip-existing` uploads only the missing files. The step log prints the command for the ref the run was on |
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
- [opentidehq/skills `AGENTS.md`](https://github.com/opentidehq/skills/blob/main/AGENTS.md#keeping-skills-in-step-with-opentide) — Step 5
- `AGENTS.md` — trunk, Conventional Commits, branch and PR workflow
