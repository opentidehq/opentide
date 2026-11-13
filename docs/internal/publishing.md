---
title: Publishing names and trusted publishers
description: Every name opentide publishes under on crates.io, npm and PyPI, who owns it, which workflow may publish it, and the steps a maintainer takes to set each one up.
---

# Publishing names and trusted publishers

opentide publishes, or will publish, under names on three registries. This page lists each name, who owns it, the workflow in this repository that may publish it with trusted publishing (OpenID Connect, no stored token), and the steps a maintainer takes to set it up. It is UC-0.1 ([#799](https://github.com/opentidehq/opentide/issues/799)) of the Unified Core epic ([#790](https://github.com/opentidehq/opentide/issues/790); plan in [#789](https://github.com/opentidehq/opentide/pull/789), decisions D-5 and D-6).

Since UC-5.5 ([#840](https://github.com/opentidehq/opentide/issues/840)) every name is published by one workflow, [`publish.yml`](../../.github/workflows/publish.yml), the release train: [The release train](#the-release-train) says what it publishes, the decisions it records, and what a maintainer sets up before its first release candidate.

The state under **today** was read from the registries' public APIs on **2026-11-07**; [Verify](#verify) has the commands. Only a maintainer can publish a placeholder, add an owner or register a publisher: [Maintainer steps](#maintainer-steps) lists each one with the check that proves it done, and [step 8](#8-record-the-result-on-this-page) brings these tables up to date afterwards.

## Names

### crates.io

| Name | Today | Owners today | Trusted publisher today | Trusted publisher required |
|------|-------|--------------|-------------------------|----------------------------|
| `opentide` | not published | none | none | `opentidehq/opentide`, `publish.yml`, registered at UC-5.5, the first workflow that publishes it ([step 10](#10-at-uc-55-publishyml)) |
| `opentide-core`, `opentide-highlight`, `opentide-syntax`, `opentide-kql`, `opentide-spl`, `opentide-esql`, `opentide-eql`, `opentide-kuery`, `opentide-lucene`, `opentide-falco`, `opentide-ecs`, `opentide-tide`, `opentide-analysis`, `opentide-lsp` (14 crates) | 0.11.0 | user `behemothsecurity` | `opentidehq/language-server`, `release.yml` (its `release.py trust` step registers it): crates.io records every 0.11.0 as published by trusted publishing from that repository | `opentidehq/opentide`, [the engine release workflow](#the-engine-release-workflow), once UC-0.3 has merged it into `development` ([step 9](#9-when-uc-03-has-merged-the-engine-release-workflow)); then `publish.yml` from UC-5.5 |
| `opentide-cql` | 0.12.0 | user `behemothsecurity` | none recorded: language-server 0.12.0 (2026-11-09) published its first version with a token, as a new crate's first version must be, so crates.io records no trusted publishing for it | the same as the 14 crates above; its publisher is added as theirs are ([step 9](#9-when-uc-03-has-merged-the-engine-release-workflow)) |
| `opentide-schema`, `opentide-schema-derive`, `opentide-workspace`, `opentide-compile`, `opentide-connectors`, `opentide-cli` (6 crates) | not published | none | none | `opentidehq/opentide`, `publish.yml`: the release train publishes them with the facade, which depends on them; each first version needs the stored token, as every new crate's does ([step 10](#10-at-uc-55-publishyml)) |

`opentide-wasm` is `publish = false` and has no crates.io name: it ships as the `opentide-wasm-web` zip. The plan's new crates (`opentide-schema`, `opentide-schema-derive`, `opentide-workspace`, `opentide-compile`, `opentide-connectors`, `opentide-cli`) are unclaimed: crates.io's [usage policy](https://crates.io/policies) does not allow a crate that exists only to hold a name, so they were published when they had content. The release train publishes them with the facade (UC-5.5): `cargo install opentide --features cli` needs them on crates.io. The test harnesses `opentide-compare` and `opentide-cassette` stay `publish = false`; the crates that use them name them as path dev-dependencies without a version, which cargo leaves out of a published manifest.

### npm

| Name | Today | Maintainers today | Trusted publisher required |
|------|-------|-------------------|----------------------------|
| `@opentide/opentide` | not published | none | `opentidehq/opentide`, `publish.yml` (UC-5.5, the first workflow that publishes it) |
| `opentide` | not published | none | `opentidehq/opentide`, `publish.yml` (UC-5.5) |
| `@opentide/lsp-client` | not published | none | `opentidehq/opentide`, the engine release workflow (UC-0.3; language-server [#191](https://github.com/opentidehq/language-server/issues/191)); then `publish.yml` (UC-5.5) |
| `@opentide/lsp-worker` | not published | none | the same |
| `@opentide/opentide-linux-x64-gnu`, `-linux-arm64-gnu`, `-darwin-x64`, `-darwin-arm64`, `-win32-x64-msvc`, `-win32-arm64-msvc` (D-6, UC-5.3: the six native packages; no musl) | not published | covered by the scope | `opentidehq/opentide`, `publish.yml` (UC-5.5); each needs a first publish by hand before it can have one ([step 10](#10-at-uc-55-publishyml)) |
| `@opentide/wasm` (D-6) | not published | covered by the scope | `opentidehq/opentide`, `publish.yml`, once a package of that name exists |
| `@opentide/explorer` (not this repository's) | 0.6.0 | `behemothsecurity` | `opentidehq/explorer`, its `publish.yml` (0.6.0 carries provenance from it); listed because the organisation's settings ([step 3](#3-npm-the-opentide-organisation)) apply to it too |

**The `opentide` organisation exists.** The registry lists one package in the scope, `@opentide/explorer` (created 2026-10-27, published from `opentidehq/explorer`), and only an organisation's members can create packages in its scope. The registry's public endpoints answer for `opentide` as they do for an organisation, not for a user: `GET https://registry.npmjs.org/-/org/opentide/user` returns `{}` (members are private) and `/-/org/opentide/team` asks for authentication, as for the organisation `babel`, while a user scope such as `behemothsecurity` returns `{"behemothsecurity":"owner"}` and `[]`. Its members are visible to members only.

### PyPI

| Name | Today | Owners today | Trusted publisher today | Trusted publisher required |
|------|-------|--------------|-------------------------|----------------------------|
| `opentide` | 0.23.0 | `behemoth` (Owner) | `opentidehq/opentide`, `publish-pypi.yml`, environment `pypi` (read from 0.23.0's provenance; set up as [PyPI trusted publishing](./pypi-trusted-publishing.md) describes) | `opentidehq/opentide`, `publish.yml`, environment `pypi`, which replaced `publish-pypi.yml` at UC-5.5, for releases and release candidates alike ([step 10](#10-at-uc-55-publishyml)) |

## Owners required

Every name has **at least two owners, each a person with two-factor authentication**, so that losing or compromising one account neither locks the project out nor hands it over. Today each registry has one account (`behemothsecurity` on crates.io and npm, `behemoth` on PyPI); who the second owner is, is a [decision](#decisions-for-the-maintainer).

| Registry | How a second person owns a name |
|----------|---------------------------------|
| crates.io | A named user owner on every crate (`cargo owner --add`). A GitHub team owner (`github:opentidehq:<team>`) can publish but cannot add or remove owners, so it does not count as the second owner. |
| npm | A second **owner** of the `opentide` organisation; both people in a team with read-write access to every package (new packages in the scope give the `developers` team read-write); the unscoped `opentide` also lists both as owners (`npm owner add`). |
| PyPI | A second collaborator with the **Owner** role on `opentide` (a Maintainer can upload but cannot manage collaborators). |

## Trusted publishers

Every name above, `@opentide/explorer` aside, is published by workflows in `opentidehq/opentide` only. Each registry matches the GitHub repository owner, the repository name and the workflow **file name** (not its path), and, when one is set, the GitHub environment of the publishing job.

### The engine release workflow

**Retired at UC-5.5:** `publish.yml` replaced `engine-release.yml` and `publish-pypi.yml`, and the engine's `engine-v*` tag series ended. What follows is how it was set up, kept for the publishers still registered to it ([step 10](#10-at-uc-55-publishyml) removes them).

language-server's `release.yml` publishes the engine crates, the engine assets and, once language-server #191 is done, `@opentide/lsp-client` and `@opentide/lsp-worker`. UC-0.3 ([#801](https://github.com/opentidehq/opentide/issues/801)) imports it into `.github/workflows/`, and UC-5.5 replaces it with `publish.yml`. #801 does not name the imported file. This page proposes **`engine-release.yml`** ([decision 2](#decisions-for-the-maintainer)), but the name UC-0.3 merges is the one to register. The registries compare that name exactly and do not stop you from saving a name no workflow has: crates.io only warns, and npm says nothing. So no publisher names the engine release workflow until it is on `development` under its final name.

| Registry | Names | Workflow | Environment | From |
|----------|-------|----------|-------------|------|
| crates.io | the 15 engine crates | the engine release workflow | none today; `crates-io` if [decided](#decisions-for-the-maintainer) | once UC-0.3 has merged it into `development`, before its first engine release ([step 9](#9-when-uc-03-has-merged-the-engine-release-workflow)) |
| crates.io | `opentide`, and the 15 engine crates from UC-5.5 | `publish.yml` | as above | UC-5.5, once `publish.yml` is on `development` ([step 10](#10-at-uc-55-publishyml)) |
| npm | `@opentide/lsp-client`, `@opentide/lsp-worker` | the engine release workflow | none today; `npm` if decided | within two days before the first engine release that publishes them ([step 9](#9-when-uc-03-has-merged-the-engine-release-workflow)) |
| npm | `@opentide/opentide`, `opentide`, and the lsp packages from UC-5.5 | `publish.yml` | as above | within two days before the first release that publishes them ([step 10](#10-at-uc-55-publishyml)) |
| PyPI | `opentide` | `publish-pypi.yml` | `pypi` | configured; it published 0.23.0 |
| PyPI | `opentide` | `publish.yml` | `pypi` | UC-5.5, when it renames `publish-pypi.yml` ([step 10](#10-at-uc-55-publishyml)) |

No publisher is registered before the workflow it names is on `development`. A publisher for a file that is not there yet has no legitimate use, and without an environment it trusts a file of that name on any branch, whoever pushed it. npm would also expire it.

What each registry requires, from its documentation (read 2026-11-07, [Sources](#sources)):

- **crates.io.** The crate must exist: the first publish needs an API token, and trusted publishing cannot create a crate. Only an owner with a verified email address adds a publisher. The form checks the workflow file on the repository's default branch (`development`): it shows **Workflow file found**, or the warning **Workflow file not found**, and saves the publisher either way. A crate takes up to five GitHub publishers, so a new one can be added before the old one is removed. A configuration does not expire. The crate's **Require trusted publishing for all new versions** setting rejects API tokens. It appears once the crate has a publisher.
- **npm.** The package must exist. The publishing job needs npm 11.5.1 or later on Node 22.14.0 or later, GitHub-hosted runners, `id-token: write`, and a `repository.url` in `package.json` that matches the repository exactly. The workflow file must exist in `.github/workflows/`, and every field is matched exactly, case included, but npm does not check them when a configuration is saved. **A configuration that has not completed a publish within two days expires** and has to be deleted and created again, so a package's publisher is registered only shortly before the workflow that publishes it runs. npm's documentation describes two setups, and which one applies depends on what the package's settings page offers. In one, a package takes up to ten configurations, which cannot be edited, only deleted and created again. In the other, it takes one, which can be edited. The CLI creates a configuration only for a package that has none (`npm trust` "will result in an error" otherwise). Publishes through trusted publishing carry provenance by default. When `workflow_dispatch` or `workflow_call` starts the publish, npm checks the name of the calling workflow.
- **PyPI.** `opentide` exists, so a new publisher is added to the project (Manage, Publishing). A *pending* publisher is only for creating a project that does not exist yet; it does not apply here. An environment is optional and strongly recommended. [PyPI trusted publishing](./pypi-trusted-publishing.md) covers how `publish-pypi.yml` releases with it today.

A trusted publisher with no environment trusts the workflow file on any branch: anyone who can push a branch with a workflow of that name can publish. An environment narrows that, but only as far as the refs it admits:

- GitHub matches an environment's deployment branch and tag rules against the run's `GITHUB_REF`: the ref the run is on, not who created it. A rule for the branch `development` refuses a run from any other branch.
- A tag rule admits a run on any commit with a matching tag. Anyone with write access can push a tag, the engine's `engine-v*` ([#801](https://github.com/opentidehq/opentide/issues/801)) included, on an unreviewed commit. A tag rule therefore needs a tag ruleset first, one that lets only the people who release create, move or delete those tags ([step 7](#7-github-environments-if-you-decide-on-them)).
- `development` itself has no branch protection and no active ruleset (`GET /repos/opentidehq/opentide/branches/development` reads `"protected":false`, and `/rules/branches/development` reads `[]`, on 2026-11-07). Anyone with write access can push a changed workflow to it and run it there. UC-0.3 adds branch protection with required checks (#801), which does not by itself require a pull request. Required reviewers on the environment, or pull requests required on `development`, close that gap.

[Decision 3](#decisions-for-the-maintainer) proposes an environment per registry.

## The release train

[`publish.yml`](../../.github/workflows/publish.yml) (UC-5.5, [#840](https://github.com/opentidehq/opentide/issues/840)) publishes one version of everything from one Run workflow on `development`, and creates the one tag, `vX.Y.Z`:

| Registry | What | How |
|----------|------|-----|
| PyPI (environment `pypi`) | One `cp310-abi3` wheel per platform (manylinux_2_28 x86_64 and aarch64, macOS Intel and Apple silicon, Windows x64 and Arm64), the sdist | cibuildwheel and `hatch_build.py`, `uv build --sdist`; `pypa/gh-action-pypi-publish` with OIDC (and its PEP 740 attestations) |
| crates.io | Every crate without `publish = false`, dependencies first, each pinned to the version: the engine crates, the six of the [new names](#cratesio), `opentide-lsp` and the facade `opentide` | `scripts/engine/release.py publish`, `cargo publish --no-verify` per crate, OIDC through `rust-lang/crates-io-auth-action` (a stored token only for a crate's first version) |
| npm | `@opentide/opentide`, its six native packages (napi-rs), the `opentide` alias, `@opentide/lsp-client`, `@opentide/lsp-worker` | `npm pack` of what the native jobs built ([`build-packages.yml`](../../.github/workflows/build-packages.yml), which builds the wheels too), `npm publish --provenance` with OIDC (npm 11.21.1) |
| GitHub Release | `opentide-vX.Y.Z-<target>` and `opentide-lsp-vX.Y.Z-<target>` (six targets), `opentide-installer.sh` and `opentide-installer.ps1` ([`publishing/installers/`](../../publishing/installers/)), `highlights-vX.Y.Z.zip`, `opentide-wasm-web-vX.Y.Z.zip`, `opentide-lsp-wasm32-wasip1.wasm`, `THIRD-PARTY-LICENSES.html`, `LICENSE`, `NOTICE`, `WASI-LIBC-LICENSES.txt`, seven CycloneDX SBOMs, `SHA256SUMS` | [`engine-release-build.yml`](../../.github/workflows/engine-release-build.yml), which ci.yml also runs as a dry run in its full set |

Every artifact (the Release's assets, the wheels and sdist, the `.crate` files, the npm tarballs) gets a GitHub artifact attestation (`actions/attest-build-provenance`) before anything is published, and the published assets are checked against `SHA256SUMS` and their attestations before any registry is touched. Each artifact is smoke-tested first the way a user installs it: `pip install` of a wheel on Linux, macOS and Windows, and of the sdist, built from source, each then run through [`scripts/build/smoke_package.py`](../../scripts/build/smoke_package.py) (`opentide --version`, the package's requirements against `pyproject.toml`, which since UC-6.2 are `pydantic` alone, `opentide --json validate` on the tide corpus, and the SDK: `Workspace.open`, `validate`, `run_json`, the models); every npm tarball published to a throwaway local registry, then `npm install @opentide/opentide` in a clean project ([The npm install test](#the-npm-install-test)); `cargo install opentide --features cli` from the crates' packages (`release.py crate-patch`, before crates.io has them); and the two installers against the built assets. After publishing, `Smoke the registries` installs from PyPI, crates.io and, for a release, npm.

**Inputs.** None: a release, of the newest dated `CHANGELOG.md` version, once its notes PR merged, from `development` only. `release_candidate: N`: see [Release candidates](#release-candidates-the-rust-core-transition). `dry_run: true`: build and smoke-test everything, publish nothing (no tag, no release, no attestation, no upload), from any branch. `checkout_ref: vX.Y.Z` (or `vX.Y.Z-rc.N`): resume a release whose publishing failed partway (also `repository_dispatch` event `publish`, for GitHub App tokens).

### Release candidates (the Rust-core transition)

For the Rust-core transition ([#790](https://github.com/opentidehq/opentide/issues/790)), and possibly retired after it, `release_candidate: N` publishes `vX.Y.Z-rc.N` of the workspace version as pre-releases, so the Rust-only package can be installed from the real registries before `integration/unified-core` merges into `development`. The Rust core ships as **1.0.0**, held at candidates (`v1.0.0-rc.1`, `-rc.2`, ...; `1.0.0rc1` on PyPI) until the maintainer accepts the final 1.0.0; breaking changes may land between candidates:

| Where | What a candidate publishes |
|-------|----------------------------|
| Branch | Run on `integration/unified-core` (or `development`); a release runs on `development` only, and the guard refuses anything else |
| GitHub | The tag `vX.Y.Z-rc.N` and a **pre-release** (never Latest) with every asset: the binaries, the installers, the engine assets, the SBOMs, `SHA256SUMS`, and the attestations, signed by `publish.yml` on the branch it ran from |
| PyPI | `X.Y.ZrcN`, a pre-release on **pypi.org** (environment `pypi`, the same trusted publisher as a release; no TestPyPI). pip and uv skip it unless asked: `pip install --pre opentide`, `uv pip install --prerelease=allow opentide`, or the exact version (`opentide==1.0.0rc1`) |
| crates.io | Every crate at `X.Y.Z-rc.N`, a SemVer pre-release, in dependency order: the workflow runs `release.py bump X.Y.Z-rc.N` in its own checkout (the branch keeps `X.Y.Z`) before it packages and publishes. Cargo skips a pre-release unless it is asked for (`cargo install opentide --version 1.0.0-rc.1 --features cli`). **A crates.io version can be yanked, never deleted**, and the first candidate **claims every new crate name** (`opentide-schema`, `-schema-derive`, `-workspace`, `-compile`, `-connectors`, `-cli`) |
| npm | **Nothing.** The npm tarballs are built and smoke-tested as for a release, and ci.yml's `packages` artifacts carry them to test ([Testing a build without publishing](#testing-a-build-without-publishing)) |

The guard runs `scripts/build/release.py check-candidate`, which refuses a candidate whose version is not above the newest dated `CHANGELOG.md` heading, and every smoke test passes before anything is attested or published. A candidate's GitHub notes quote `## [Unreleased]`.

**Run workflow needs `publish.yml` on the default branch.** GitHub runs a `workflow_dispatch` workflow only once a file of that name is on the default branch, `development`: until then the Actions page does not list it, and the API (`gh workflow run`, the GitHub MCP `actions_run_trigger`) does not find it. A run uses the workflow file of the ref it is dispatched on, so the smallest way to run a candidate from `integration/unified-core` before it merges is to land a `publish.yml` stub on `development` first: `workflow_dispatch` with the same three inputs, `permissions: {}`, and one job that fails (it never publishes; `development`'s own release still goes through `publish-pypi.yml` until the integration merge replaces the stub with this file). The PR that adds this file says what the stub holds.

### Testing a build without publishing

ci.yml's full set (nightly, every push to `development` and `integration/unified-core`, Run workflow, and a pull request labelled `full-ci`) runs [`build-packages.yml`](../../.github/workflows/build-packages.yml), the build `publish.yml` uses, as its `packages` job, at a development version of the workspace's (PyPI `X.Y.Z.devN`, npm `X.Y.Z-dev.N`, N the run number), and keeps the result for 14 days as the run's artifacts:

| Artifact | Holds |
|----------|-------|
| `wheels-linux-x64`, `wheels-linux-arm64`, `wheels-macos-x64`, `wheels-macos-arm64`, `wheels-windows-x64`, `wheels-windows-arm64` | One `cp310-abi3` wheel (Python 3.10 and later) |
| `npm-linux-x64-gnu`, `npm-linux-arm64-gnu`, `npm-darwin-x64`, `npm-darwin-arm64`, `npm-win32-x64-msvc`, `npm-win32-arm64-msvc` | `@opentide/opentide` and that platform's native package |

```bash
# A run of ci.yml that ran the full set: Actions, CI, the run's page (its id is in the URL)
gh run download <run-id> -R opentidehq/opentide -n wheels-linux-x64
uv venv && uv pip install opentide-*.whl        # or: python -m pip install opentide-*.whl
.venv/bin/opentide --version

gh run download <run-id> -R opentidehq/opentide -n npm-linux-x64-gnu
npm install ./opentide-opentide-*.tgz           # the package and its native package
npx opentide --version
```

npm resolves the native package from the local tarball; it may print a warning for the other platforms' native packages, which are optional and not on npm at that version. With a Rust toolchain (1.85 or later), any commit also installs from source, with no artifact at all: `uv tool install "git+https://github.com/opentidehq/opentide@<ref>"` (a branch, tag or commit).

**Lockstep version.** The facade, the internal crates, the wheel and the npm packages carry one version, the product's. `scripts/engine/release.py bump X.Y.Z` sets the workspace version and every internal pin in the release's pull request; `release.py lockstep X.Y.Z` (in the guard) refuses a release whose crates are at another version; the workflow writes the version into every npm package (`release.py npm-version`, the tree keeps a placeholder) and checks them (`lockstep --npm`); the wheels build at the tag's version. The binaries report the release's version (`OPENTIDE_VERSION`), a candidate's included.

**Decisions** recorded here:

1. **The engine's tag series ended.** `engine-release.yml` retired into `publish.yml`, and there are no more `engine-vX.Y.Z` tags: the assets keep their names with the product's `vX.Y.Z` (`highlights-v1.0.0.zip`), which vscode-extension's pins and `scripts/engine/check-vscode-extension.mjs` accept. `crates/CHANGELOG.md` holds the engine's releases before the train; later changes go in `CHANGELOG.md`.
2. **No musl.** The maintainer decided against musl builds: no musllinux wheel (`*-musllinux_*` in cibuildwheel's `skip`), no `*-unknown-linux-musl` binary, no `linux-*-musl` npm package. On Alpine, `pip install opentide` builds from the sdist, and the installers say so.
3. **cibuildwheel and `hatch_build.py`, not maturin.** The wheels keep the build the repository already uses, which compiles the same abi3 extension maturin would; moving to maturin would change the build backend of the sdist too, for no artifact the release lacks.
4. **Free-threaded CPython (3.14t): the sdist.** A free-threaded interpreter has no stable ABI, so a `cp314t` wheel would be one more build per platform for one interpreter. It installs from the sdist, which builds wherever a Rust toolchain is installed, as before.
5. **No release-plz, cargo-release or cargo-dist.** `scripts/engine/release.py publish` already publishes the crates in dependency order, resumes, and waits out crates.io's rate limit for new crates. The binaries come from the existing per-target build, with two installers of our own (POSIX shell and PowerShell) that check each binary against `SHA256SUMS` before installing it; cargo-dist would have brought its own generated workflow.
6. **No `release: published` trigger, no tag trigger.** A tag pushed or a Release created by hand publishes nothing; `publish.yml` creates both with `GITHUB_TOKEN`, which starts no other workflow. A failed run is resumed with `checkout_ref`.
7. **The opentide command line is scanned as a product.** The oracle licence scan (`scripts/engine/license-scan.sh`) refuses the engine's oracles in every asset. The `opentide` binaries, the opentide-cli crate and `@opentide/opentide` carry opentide's own package data, as the wheel always has: its `platform_sdk` explain page (still shipped, though the Rust `doctor` has no such check since UC-6.2) names `splunklib`, the Python module of the Splunk client, so they are scanned with `--product`, which allows that name and no other. Since UC-6.2 the wheel depends on `pydantic` alone, so its SBOM is scanned with the rest of the product's assets.
8. **Linux binaries and npm native packages are built on `ubuntu-latest`** (as language-server's were), so they need that runner's glibc or newer; the wheels are manylinux_2_28. Building them against an older glibc (a manylinux container, or napi-rs's cross toolchain) is a follow-up.
9. **npm: the standard napi-rs layout, `@opentide/opentide-<platform>`** ([ADR 0006](./adr/0006-npm-packages.md#amendment-2026-11-12-the-package-layout-and-names), amended). `@opentide/opentide` carries the loader napi-rs generates, `index.d.ts` and the `opentide` bin, and lists the six native packages under `optionalDependencies`; each native package declares its `os` and `cpu` (and `libc: ["glibc"]` on Linux) and holds one `opentide.<platform>.node` and `LICENSE`. The names are napi-rs's default, not ADR 0006's first `@opentide/<platform>`: a bare platform name says nothing inside the organisation's scope, and napi-rs generates these (the loader, `bindings/node/npm/`), so nothing is renamed by hand.
10. **No WebAssembly fallback** (no `@opentide/opentide-wasm32-wasi`). napi-rs's WASI build runs under WASI preview 1, which under Node.js and napi-rs has no outbound sockets, so `query`, `validate query --live` and `deploy` could not reach a tenant. On a platform without a native package, loading fails with the loader's error. Revisit when napi-rs supports WASI 0.2 or 0.3. `@opentide/wasm`, the browser build, is a separate package.

### The npm install test

[`scripts/engine/npm-local-registry/test.mjs`](../../scripts/engine/npm-local-registry/test.mjs) installs the npm packages the way a user does, before any registry has them. It publishes every tarball to a throwaway local registry (Verdaccio 6.11.1, started with no uplink, listening on the loopback interface only, its storage in a temporary folder), then in a clean project, with its own npm cache and configuration, runs `npm install @opentide/opentide` and checks that:

- npm installed exactly the host's native package, at the release's version, with its addon and `LICENSE`;
- `npx opentide --version` prints the release's version;
- the SDK loads from `require` and from `import` with the loader's version check on (`NAPI_RS_ENFORCE_VERSION_CHECK=1`), from the native addon, and `runJson(['commands'])` returns the command tree;
- `tsc --noEmit` (strict, `nodenext`) resolves the package's types, a deliberate type error included;
- the registry serves each native package's `os`, `cpu` and `libc`, and each tarball is at the release's version, with no musl or WebAssembly package;
- the same install through the `opentide` alias: the same native package, its bin, its SDK.

Verdaccio and TypeScript come from the test's own [`package-lock.json`](../../scripts/engine/npm-local-registry/package-lock.json) (`npm ci --ignore-scripts`, from the default registry, into the work folder). Nothing is published anywhere else, and the work folder is deleted afterwards (`--keep` leaves it).

It runs in `publish.yml`'s `smoke-npm`, on Linux, macOS and Windows, against the tarballs `build-packages.yml`'s `npm-pack` built, before `attest` and so before anything is published; and in ci.yml's full set (`npm-install`), on linux-x64-gnu only: the tree's packages at the workspace version, the other five native packages packed as stand-ins without an addon, so that npm still has to choose. To run it locally (Node.js 22 or later), from the repository root:

```bash
cd bindings/node && npm ci && cd ../..
version="$(python3 scripts/engine/release.py version)"
python3 scripts/engine/release.py npm-version "$version"     # rewrites the npm manifests: revert them afterwards
(cd bindings/node && OPENTIDE_VERSION="$version" node build.mjs --profile develop)
node scripts/engine/npm-local-registry/test.mjs --version "$version" --pack "$(mktemp -d)"
git checkout -- bindings/node packages/lsp-client/package.json packages/lsp-worker/package.json
```

## The placeholders

| Path | Publishes | Contents |
|------|-----------|----------|
| [`publishing/placeholders/crates/opentide/`](../../publishing/placeholders/crates/opentide/) | `opentide` 0.0.0 on crates.io | `Cargo.toml` (EUPL-1.2, repository, homepage, its own `[workspace]`), `Cargo.lock`, `src/lib.rs` (a crate doc comment and `#![forbid(unsafe_code)]`, no API), `README.md`, `LICENSE` |
| [`publishing/placeholders/npm/opentide-scoped/`](../../publishing/placeholders/npm/opentide-scoped/) | `@opentide/opentide@0.0.0` on npm | `package.json` (EUPL-1.2, repository, `publishConfig` with public access and provenance), `README.md`, `LICENSE`; no code |
| [`publishing/placeholders/npm/opentide/`](../../publishing/placeholders/npm/opentide/) | `opentide@0.0.0` on npm | the same, for the alias |

Each README says the name is reserved and points at the PyPI package.

**Why `publishing/placeholders/`.** UC-0.2 imports language-server in a parallel pull request: `crates/` with a root `Cargo.toml` that lists its members, `packages/` with the npm packages that `check-npm-packs.mjs` checks, `grammars/` and `data/catalogs/`. A placeholder in `crates/` or `packages/` would have to join those lists, and both pull requests would edit them. Here, each placeholder stands alone: the crate is its own Cargo workspace, so it builds and publishes whatever workspace the repository root holds, and the npm packages have no dependencies and no scripts. They are temporary: the facade crate (UC-5.1) and `@opentide/opentide` (UC-5.3) replace them, and the dry run then publishes `-p opentide` and the real package. Until then each points at this repository, where that code is being written, which is what crates.io's policy on reserved names asks of a placeholder. The facade crate is `crates/opentide` (UC-5.1, #836) with `publish = false`: the engine crates it wraps (`opentide-schema`, `opentide-workspace`, `opentide-compile`, `opentide-cli`) are not on crates.io yet, so the crate placeholder holds the name until they are and the facade's `publish = false` goes.

Each placeholder carries a copy of the repository's `LICENSE`: the EUPL asks for a copy of the licence with every copy of the work, and neither cargo nor npm packs a file from outside the package's directory. `tests/test_package/test_publishing_placeholders.py` keeps the copies' text identical to `LICENSE` and the manifests consistent with this page. The crate's `target/` is ignored in the root `.gitignore`, the only one hatchling reads, so an sdist built after a local dry run leaves it out.

## Dry run

[`.github/workflows/publish-dry-run.yml`](../../.github/workflows/publish-dry-run.yml) rehearses every publish on pull requests that change what is published (the placeholders, the workflow, `pyproject.toml`, `hatch_build.py`, `bindings/python/`, and from UC-0.2 `crates/`, the root `Cargo.toml`, `Cargo.lock` and `rust-toolchain.toml`; `README.md`, `LICENSE`, `CHANGELOG.md` and `scripts/build/release.py`), on pushes to `development` that change them, and on **Run workflow**.

`CHANGELOG.md` is in the filter because a release notes pull request changes the version the next release builds, and that pull request is the one whose rehearsal matters most. The filter cannot tell it from an `[Unreleased]` entry, so the file about doubles how often the PyPI job runs, at about nine minutes a run: 102 of the 161 first-parent commits on `development` from 2026-10-07 to 2026-11-07 would have run it, against 52 without the file. Without it in the `pull_request` paths, a new version is first built by the run after the merge ([decision 7](#decisions-for-the-maintainer)).

| Job | Does |
|-----|------|
| `crate` | `cargo fmt`, `cargo clippy -D warnings` and `cargo doc` (warnings denied) on the placeholder, then `cargo package --list` and `cargo publish --dry-run --locked`. A version crates.io already has is a warning in a dry run, so the job stays green after the placeholder is published. |
| `npm` | npm 11.21.1 on Node 24, checked to be 11.5.1 or later; `npm pack --dry-run` must pack exactly `package.json`, `README.md` and `LICENSE`; then `npm publish --dry-run`. npm refuses a version it already has even in a dry run, so once a placeholder is on npm the job says so in a notice and checks the pack only. |
| `pypi` | The artifacts `publish.yml` uploads, built the same way ([`build-packages.yml`](../../.github/workflows/build-packages.yml)): `cibuildwheel==4.3.5` (Linux x86_64: manylinux_2_28, no musllinux) and `uv build --sdist`, at the version the release guard reads from `CHANGELOG.md`, then `twine check` and the publish job's own checks (one release version, neither a dev nor a local one, `cp310-abi3` wheels, one sdist). |

Nothing in it can publish: the token is read-only (`contents: read`), no job may mint the OIDC token all three registries' trusted publishing needs (no `id-token: write`), no expression reads a secret, the only triggers are `pull_request`, `push` and `workflow_dispatch`, and every `cargo publish` and `npm publish` command has `--dry-run`, and nothing that undoes it, however it is spelled (npm also runs `npm pu` to `npm publis` as a publish, and takes options before the command). `tests/test_ci/test_publish_dry_run_workflow.py` fails if that changes.

**What it leaves out.** The release guard's checks on the state of the repository: `release.py check`, the version not being tagged yet, and `check_engine_pin.py --release`. Between releases, the newest version in `CHANGELOG.md` is already tagged, and `development` may pin the engine to a git revision. Those checks would therefore fail most pull requests without saying anything about the packages. `publish-pypi.yml` still runs them before it publishes.

**maturin.** Issue #799 names `maturin build`. opentide's wheel is built by hatchling with `hatch_build.py` and cibuildwheel, and the release train (UC-5.5) kept that build ([The release train](#the-release-train), decision 3), so the dry run builds the artifact a release builds. `publish.yml`'s own `dry_run` input rehearses everything else.

The same commands run locally from a clean checkout:

```bash
cargo publish --dry-run --locked --manifest-path publishing/placeholders/crates/opentide/Cargo.toml
(cd publishing/placeholders/npm/opentide-scoped && npx --yes npm@11.21.1 publish --dry-run)
(cd publishing/placeholders/npm/opentide && npx --yes npm@11.21.1 publish --dry-run)
SETUPTOOLS_SCM_PRETEND_VERSION="$(python3 scripts/build/release.py version)" uv build
uvx twine check dist/*
```

## Maintainer steps

Steps 1 to 8 can be done now. Steps 9 and 10 wait for the workflows that publish, because of the rule above: no publisher before its workflow is on `development`.

Work from a clean checkout of `development` that contains this page (`git status --porcelain` prints nothing), so that what you publish is what was reviewed. Every account you use needs two-factor authentication: on crates.io that is your GitHub account's, npm and PyPI require their own. Never paste a token into a shell command line, a file in the repository, an issue or a pull request.

### 1. crates.io: publish the `opentide` placeholder

1. Sign in at [crates.io](https://crates.io) with GitHub. On [Account Settings](https://crates.io/settings/profile), add and verify an email address: publishing and adding trusted publishers need one.
2. On [API Tokens](https://crates.io/settings/tokens/new), create a token: **Name** `opentide-uc-0.1`, **Expiration** 7 days, **Scopes** `publish-new` and `change-owners`, **Crates** pattern `opentide*` (it matches `opentide` and the `opentide-*` crates of step 2). Copy it; it is shown once.
3. From the repository root:

   ```bash
   cargo login                     # paste the token at the prompt; cargo keeps it in ~/.cargo/credentials.toml
   cargo publish --locked --manifest-path publishing/placeholders/crates/opentide/Cargo.toml
   ```

4. **Verify:** the owners endpoint lists you (crates.io answers 403 to a request without a User-Agent):

   ```bash
   curl -s -A "opentide-maintainer (https://github.com/opentidehq/opentide)" https://crates.io/api/v1/crates/opentide/owners | jq -r '.users[].login'
   ```

   Expected: your GitHub login. Before this step it prints nothing, and the raw answer is `{"errors":[{"detail":"crate `opentide` does not exist"}]}`.

`opentide` gets no trusted publisher now: the first workflow that publishes it is `publish.yml`, in UC-5.5 ([step 10](#10-at-uc-55-publishyml)). Until then its two owners are the only ones who can publish it, and no token is left behind.

### 2. crates.io: a second owner on every crate

1. **Before you start**, the second person signs in to [crates.io](https://crates.io) once with GitHub. crates.io invites only a login that has signed in before, and answers any other with `could not find user with login`.
2. With the token of step 1 still logged in:

   ```bash
   for crate in opentide opentide-core opentide-highlight opentide-syntax opentide-kql opentide-spl \
       opentide-esql opentide-eql opentide-kuery opentide-lucene opentide-falco opentide-cql \
       opentide-ecs opentide-tide opentide-analysis opentide-lsp; do
     cargo owner --add <second-github-login> "$crate" || { echo "stopped at $crate"; break; }
   done
   ```

   Each crate prints `Owner Crates.io user <login> has been invited to be an owner of crate <crate>`. The loop stops at the first error and stays logged in. Fix the cause and run it again: a crate that already has the invitation prints `already has a pending invitation` and the loop goes on.
3. Once all 16 crates have printed that, run `cargo logout` and revoke the token on [API Tokens](https://crates.io/settings/tokens).
4. The second owner accepts each invitation at [Pending invites](https://crates.io/me/pending-invites).
5. **Verify:** every crate lists two people.

   ```bash
   for crate in opentide opentide-core opentide-highlight opentide-syntax opentide-kql opentide-spl \
       opentide-esql opentide-eql opentide-kuery opentide-lucene opentide-falco opentide-cql \
       opentide-ecs opentide-tide opentide-analysis opentide-lsp; do
     printf '%s: ' "$crate"
     curl -s -A "opentide-maintainer (https://github.com/opentidehq/opentide)" "https://crates.io/api/v1/crates/$crate/owners" \
       | jq -r '[.users[] | select(.kind == "user") | .login] | join(" ")'
     sleep 1
   done
   ```

   Expected: two logins on every line. Today each line is `behemothsecurity`, and `opentide` is empty.

### 3. npm: the `opentide` organisation

1. Sign in on [npmjs.com](https://www.npmjs.com/login) and open `https://www.npmjs.com/settings/opentide/members`. The organisation exists ([npm](#npm)); if npm says you have no access to it, a member has to invite you first. `behemothsecurity` is one: it published `@opentide/explorer` into the scope.
2. **Invite Members**: the second person's npm username, team `developers`, **Invite**. Once they accept, click **owner** in their row, so that the organisation has two owners.
3. Before the next click, read the members page's two-factor authentication column. Enforcing 2FA removes every member who does not use it from the organisation, and with it their access to every package in the scope, `@opentide/explorer` included. Then **Enable 2FA Enforcement**, and confirm.
4. **Verify:** on the members page, both people have the role **Owner**. Step 4 checks the same from the command line, once you are signed in there.

### 4. npm: publish the two placeholders

Sign in from the command line first, even if you think you already are. `npm publish` publishes as whichever account the npm configuration holds, an old token in `~/.npmrc` included, and the unscoped `opentide` belongs to the account that publishes it first. From the repository root:

```bash
npm install --global npm@11.21.1        # 11.5.1 or later
npm login                               # in the browser, with two-factor authentication; stay signed in for step 5
npm whoami                              # must print your own npm username
npm org ls opentide                     # step 3, from the command line
```

Expected: `npm whoami` prints your npm username, and `npm org ls opentide` prints one line per member, `<username> - owner` for both people. If `npm whoami` prints another username, run `npm logout` and `npm login`, and check again; do not publish until it prints yours. Signed out, `npm whoami` fails with `ENEEDAUTH`, and `npm org ls` prints nothing and still exits 0, which looks like an empty organisation.

Then publish:

```bash
cd publishing/placeholders/npm/opentide-scoped
npm publish --provenance=false          # npm asks for the second factor
cd ../opentide
npm publish --provenance=false
```

`--provenance=false`: provenance is signed in CI only (GitHub Actions or GitLab), and npm refuses a publish from a workstation when `publishConfig` asks for provenance. The flag overrides `publishConfig` for this one publish; every later version comes from CI with provenance. `publishConfig` already makes the scoped package public.

Then on each package's page, **Settings**, **Publishing access**: **Require two-factor authentication and disallow tokens**, **Update Package Settings**.

**Verify:** the issue's commands.

```bash
npm view @opentide/opentide name
npm view opentide name
```

Expected: `@opentide/opentide`, then `opentide`. Today both fail with `npm error code E404`.

### 5. npm: owners of both packages

Still signed in from step 4:

```bash
npm owner add <second-npm-user> opentide
npm access grant read-write opentide:developers opentide
npm owner ls opentide
npm access list collaborators @opentide/opentide
npm access list collaborators opentide
npm logout
```

`@opentide/opentide` is read-write for the `developers` team as soon as it is created. **Verify:** `npm owner ls opentide` lists both people, and each `npm access list collaborators` lists both as `read-write`.

### 6. PyPI: a second owner

1. [Your projects](https://pypi.org/manage/projects/), `opentide`, **Manage**, **Collaborators**: the second person's PyPI username, role **Owner**, **Invite**. They accept from the email or from **Pending invitations** on their **Your projects** page.
2. **Verify:**

   ```bash
   curl -s https://pypi.org/pypi/opentide/json | jq -c '.ownership.roles'
   ```

   Expected: two `Owner` roles. Today: `[{"role":"Owner","user":"behemoth"}]`.

The publisher, `publish-pypi.yml` with environment `pypi`, is already in place; `publish.yml` replaces it in [step 10](#10-at-uc-55-publishyml).

### 7. GitHub environments, if you decide on them

Create each environment before any workflow names it: a workflow that names a missing environment creates it with no protection rules.

1. Repository **Settings**, **Environments**, **New environment**: name `crates-io` (then `npm`), **Configure environment**.
2. **Deployment branches and tags**: **Selected branches and tags**; **Add deployment branch or tag rule**, **Ref type** Branch, name pattern `development`. That is the only rule a workflow needs when it publishes from **Run workflow** on `development`, as `publish.yml` will ([#840](https://github.com/opentidehq/opentide/issues/840)).
3. **Required reviewers** ([decision 3](#decisions-for-the-maintainer)): select it, enter the owners, select **Prevent self-review**, then **Save protection rules**. A publishing job then waits until one of them approves it, and the person who started the run cannot approve it. By default, though, an administrator of the repository can bypass these rules and start a waiting job without any approval (**Start all waiting jobs**). So also deselect **Allow administrators to bypass configured protection rules**, then **Save protection rules**: only then does no release start without a second person's approval, administrators' included. While `development` is unprotected ([Trusted publishers](#trusted-publishers)), reviewers are what stop a workflow change pushed to `development` from publishing unseen.
4. **Tags.** #801 prefixes engine tags `engine-v0.x.y`, so that they do not collide with opentide's `v*`. language-server's `release.yml` releases either from a pushed tag or from **Run workflow** on its default branch. On **Run workflow**, its `release` job creates the tag with `GITHUB_TOKEN` (`gh release create`), before the jobs that publish to crates.io and npm. Choose one of the two ways to release ([decision 3](#decisions-for-the-maintainer)), not both: protecting the tags, which the second needs, closes the first.

   - **Run workflow on `development`**, the default. The run's `GITHUB_REF` is the branch, so the rule of 7.2 admits it, and the environment refuses a run on a pushed tag. Add no tag rule and no tag ruleset.
   - **Tags pushed by the people who release.** A tag rule admits any commit with a matching tag, so protect the tags first. **Settings**, **Rulesets**, **New ruleset**, **New tag ruleset**. Give it a name and set **Enforcement status** to Active. Under **Bypass list**, **Add bypass**: Repository admin, or a team of the people who release (not the write role, which every writer has). Under **Target tags**, **Add a target**, **Include by pattern**: `engine-v*`. Under **Tag protections**: **Restrict creations**, **Restrict updates** and **Restrict deletions**. Then **Create**. Only then add the environment rule: **Ref type** Tag, `engine-v*`.

     The ruleset applies to every actor not on its bypass list, workflows included. From then on, **Run workflow** can no longer release: `GITHUB_TOKEN` may not create the tag, so the `release` job fails, before any job publishes to crates.io or npm. Do not add GitHub Actions to the bypass list to bring it back: any workflow with `contents: write` could then create `engine-v*` tags again, which undoes the protection. Engine releases go only through tags that someone on the bypass list pushes. Try that path with a release candidate tag, as #801 asks for anyway.

   The same applies to `v*`, opentide's release tags, for a workflow that publishes on them. `publish.yml` will not: it runs from **Run workflow** on `development`. `publish-pypi.yml` does, through `release: published`, so the `pypi` environment admits a tag if it has rules at all. This page could not read them ([decision 3](#decisions-for-the-maintainer)).
5. Name the environment in the registry's publisher configuration and on the publishing job (`environment: crates-io`), in the same change: a publisher with an environment rejects a job without one.

### 8. Record the result on this page

After steps 1 to 6, and again after each of steps 9 and 10, open a pull request that updates [Names](#names): the owners, the trusted publishers and the date they were read (the **today** of this page). Run [Verify](#verify) and the checks of the steps you did, and put their output in the pull request. Until then these tables describe 2026-11-07.

### 9. When UC-0.3 has merged the engine release workflow

Once the engine release workflow is on `development`, under the name you decided ([decision 2](#decisions-for-the-maintainer)), and before its first engine release:

**crates.io, each of the 15 engine crates:**

1. Open `https://crates.io/crates/<crate>/settings`, section **Trusted Publishing**, click **Add**.
2. **Publisher** GitHub; **Repository owner** `opentidehq`; **Repository name** `opentide`; **Workflow filename** the workflow's file name (the name only, with `.yml`); **Environment name** empty, or `crates-io` if you created it in step 7. Under the filename, crates.io must say **Workflow file found**. **Workflow file not found** means a typo or a file that is not on `development`: crates.io saves the publisher anyway, so correct it before you click **Add**.
3. Keep language-server's `release.yml` publisher until the switch is proven: a crate takes five.
4. After the first engine release from this repository has published the crates, delete the `opentidehq/language-server` publisher on each crate and tick **Require trusted publishing for all new versions**. Do this before language-server is archived (UC-6.3).

The `release.py trust` step that UC-0.3 imports from language-server does 1 and 2 through the crates.io API when the publishing job has a token with the `trusted-publishing` scope. It takes the workflow's file name on its command line (`release.py trust release.yml` in language-server), which UC-0.3 changes with the file's name, and it registers no environment.

**Verify:** a release's versions record the repository that published them.

```bash
curl -s -A "opentide-maintainer (https://github.com/opentidehq/opentide)" "https://crates.io/api/v1/crates/opentide-lsp/versions?per_page=1" \
  | jq -c '.versions[0] | {num, trustpub_data}'
```

Expected after the switch: `"repository":"opentidehq/opentide"`. Today: `{"num":"0.11.0","trustpub_data":{"provider":"github","repository":"opentidehq/language-server",...}}`. The registered publishers themselves are readable by an owner only (`GET https://crates.io/api/v1/trusted_publishing/github_configs?crate=<crate>` with a token that has the `trusted-publishing` scope), or on each crate's settings page.

**npm, `@opentide/lsp-client` and `@opentide/lsp-worker`:** npm registers publishers for existing packages only (language-server #191), so publish each once by hand first, as in step 4. Then, within two days before the first engine release that publishes them (the repository variable `NPM_PUBLISH=true`):

1. On the package's page, **Settings**, **Trusted publishing** (**Trusted Publisher**, **Select your publisher**): **GitHub Actions**.
2. **Organization or user** `opentidehq`; **Repository** `opentide`; **Workflow filename** the workflow's file name (the name only, with `.yml`); **Environment name** empty, or `npm` if you created it in step 7; **Allowed actions**: `npm publish`. Save.
3. Or the same from the command line (npm 11.15.0 or later, two-factor authentication). It works here because the package has no configuration yet: `npm trust github` refuses to add one to a package that already has one.

   ```bash
   npm trust github @opentide/lsp-client --repo opentidehq/opentide --file <workflow-file.yml> --allow-publish
   npm trust list @opentide/lsp-client
   ```

**Verify:** `npm trust list <package>` shows the workflow; after the release, `npm view <package>@<version> dist.attestations` shows the provenance attestation.

Then record it (step 8).

### 10. At UC-5.5: `publish.yml`

UC-5.5 ([#840](https://github.com/opentidehq/opentide/issues/840)) publishes everything from [`publish.yml`](../../.github/workflows/publish.yml), which replaced `publish-pypi.yml` and `engine-release.yml`. The pull request that adds it targets `integration/unified-core`, which merges into `development`; a release candidate can run from `integration/unified-core` before that, once a `publish.yml` stub is on `development` ([Release candidates](#release-candidates-the-rust-core-transition)). Before the first release candidate:

1. **PyPI:** on [pypi.org](https://pypi.org/manage/project/opentide/settings/publishing/), `opentide`, **Manage**, **Publishing**, GitHub: **Owner** `opentidehq`, **Repository name** `opentide`, **Workflow name** `publish.yml`, **Environment name** `pypi`, **Add**. A candidate publishes to PyPI too, as a pre-release, with this publisher: there is no TestPyPI publisher. Remove the `publish-pypi.yml` publisher after the first release from `publish.yml`.
2. **The `publish.yml` stub on `development`**, for a candidate from `integration/unified-core` before it merges ([Release candidates](#release-candidates-the-rust-core-transition)).
3. **GitHub environment `pypi`:** **Settings**, **Environments**, `pypi`: if it limits deployment branches, allow `integration/unified-core` besides `development` while candidates run from there ([step 7](#7-github-environments-if-you-decide-on-them)), with required reviewers if [decided](#decisions-for-the-maintainer).
4. **crates.io:** the six new crates (`opentide-schema`, `opentide-schema-derive`, `opentide-workspace`, `opentide-compile`, `opentide-connectors`, `opentide-cli`) cannot use trusted publishing for their first version. Store a token as the repository secret `CARGO_REGISTRY_TOKEN` (**Settings**, **Secrets and variables**, **Actions**): on [API Tokens](https://crates.io/settings/tokens/new), **Scopes** `publish-new`, `publish-update` and `trusted-publishing`, **Crates** pattern `opentide*`, an expiry that covers the first release. That release publishes each new crate with it and then registers `publish.yml` as the trusted publisher of every crate (`release.py trust publish.yml`). Or register it yourself first, for `opentide` (its first publisher: the name's placeholder 0.0.0 is there) and the 15 engine crates, as in step 9 with **Workflow filename** `publish.yml`. After that first publish: remove the engine release workflow's publishers, tick **Require trusted publishing for all new versions** on every crate, and revoke the token. A release candidate publishes every crate at `X.Y.Z-rc.N`, so the first candidate needs the token, claims the six new names, and registers the trusted publisher; a crates.io version can be yanked, never deleted.
5. **npm**, before the first release (a candidate publishes nothing to npm): trusted publishing needs the package to exist, and a configuration expires unless it publishes within two days, so within two days before the release:
   - Publish each of the six native packages once by hand, as in step 4, so that it exists: `@opentide/opentide-linux-x64-gnu`, `-linux-arm64-gnu`, `-darwin-x64`, `-darwin-arm64`, `-win32-x64-msvc` and `-win32-arm64-msvc`. From the repository root, signed in (`npm whoami`):

     ```bash
     for dir in bindings/node/npm/*/; do (cd "$dir" && npm publish --provenance=false --access public); done
     ```

     Each publishes `0.0.0` with its manifest only, which nothing installs: `@opentide/opentide` depends on the release's version. `@opentide/opentide` and `opentide` exist from step 4; `@opentide/lsp-client` and `@opentide/lsp-worker` need the same first publish if step 9 has not happened (`cd packages/lsp-client && npm publish --provenance=false --access public`, and `lsp-worker`).
   - Register `publish.yml` on all ten packages: on each package's page, **Settings**, **Trusted publishing**, GitHub Actions, **Organization or user** `opentidehq`, **Repository** `opentide`, **Workflow filename** `publish.yml`, no environment, **Allowed actions** `npm publish`. Or `npm trust github <package> --repo opentidehq/opentide --file publish.yml --allow-publish` for each package that has no configuration yet (the CLI refuses a second). Replace the engine release workflow's configuration on the two lsp packages as described in the first version of this step: delete it (`npm trust revoke`) if the page allows only one.
   - A release candidate publishes none of them: test its npm packages from ci.yml's artifacts ([Testing a build without publishing](#testing-a-build-without-publishing)).
6. **The workspace version:** `python3 scripts/engine/release.py bump X.Y.Z` in a pull request to the branch the candidate runs from, X.Y.Z the next product version (above CHANGELOG.md's newest), and merge it: a candidate is of the workspace version (`release.py lockstep`). Then run the candidate: Run workflow on `integration/unified-core` with `release_candidate` `1` ([Release candidates](#release-candidates-the-rust-core-transition)).
7. **Verify** PyPI's publisher from a release's provenance:

   ```bash
   curl -s -H 'Accept: application/vnd.pypi.integrity.v1+json' \
     https://pypi.org/integrity/opentide/0.23.0/opentide-0.23.0.tar.gz/provenance \
     | jq -c '[.attestation_bundles[].publisher]'
   ```

   Expected for the first release from `publish.yml` (put its version and file name in the URL): `"workflow":"publish.yml"`. Today, for 0.23.0: `[{"environment":"pypi","kind":"GitHub","repository":"opentidehq/opentide","workflow":"publish-pypi.yml"}]`.

Then record it (step 8).

## Verify

The issue's commands, and their output on 2026-11-07, which shows steps 1 and 4 still to do:

```bash
curl -s https://crates.io/api/v1/crates/opentide/owners
npm view @opentide/opentide name
npm view opentide name
```

```text
(crates.io, without a User-Agent: HTTP 403 and an empty body. With one, as in step 1:)
{"errors":[{"detail":"crate `opentide` does not exist"}]}

npm error code E404
npm error 404 Not Found - GET https://registry.npmjs.org/@opentide%2fopentide - Not found

npm error code E404
npm error 404 Not Found - GET https://registry.npmjs.org/opentide - Not found
```

After steps 1 to 6: the owners endpoint lists two logins, and the two `npm view` commands print `@opentide/opentide` and `opentide`.

## Decisions for the maintainer

1. **Second owners.** Who is the second person on crates.io, on npm (organisation owner) and on PyPI?
2. **The engine release workflow's file name.** #801 says language-server's `release.yml` is imported, not under which name. This page proposes `engine-release.yml`, so that it cannot be mistaken for opentide's own release (`publish-pypi.yml`, then `publish.yml`). Whatever the name, record it on #801 so that UC-0.3 merges it under that name, and register publishers only once it is on `development` (step 9).
3. **GitHub environments.** `crates-io` and `npm`, each limited to the branch `development` ([step 7](#7-github-environments-if-you-decide-on-them))? They must exist before the engine release workflow (UC-0.3) names them, and the publisher configurations must name them too. Three choices go with them:
   - **Required reviewers** on each environment, including `pypi`, whose settings this page could not read.
   - **A ruleset on `development`** that requires pull requests. Today anyone with write access can push to `development` directly, and a branch rule then admits that push.
   - **How engine releases start:** **Run workflow** on `development`, or `engine-v*` tags that the people who release push; one or the other. #801 says the engine "keeps publishing from tags". Pushed tags need a tag rule, and a tag ruleset before it; once that ruleset is active, **Run workflow** can no longer create its tag (step 7.4). **Run workflow** needs neither.
4. **maturin.** Decided at UC-5.5: the release train keeps cibuildwheel, hatchling and `hatch_build.py` ([The release train](#the-release-train), decision 3).
5. **Acceptance criterion 2 of #799.** It asks for trusted publishing on crates.io (every crate), npm (both packages) and PyPI. In UC-0.1, only PyPI's can be in place: the workflows that will publish the other names (the engine release workflow, `publish.yml`) do not exist yet, and an npm publisher expires within two days. Either amend the criterion to "every name's publisher is recorded on this page and is registered before the first workflow that publishes it runs", and move the registrations (steps 9 and 10) into #801 and #840 so that #799 closes after steps 1 to 8. Or keep #799 open until UC-5.5. #840 depends on #799, though, so the second choice blocks UC-5.5 on itself.
6. **The plan's other crate names.** Publish `opentide-schema` and the other new crates only when they have content (crates.io's policy on name reservation), or reserve them now?
7. **`CHANGELOG.md` as a pull request trigger.** Keep it, so that the release notes pull request rehearses the version it sets, or drop it from the `pull_request` paths (it stays on `push`) to halve the PyPI job's runs ([Dry run](#dry-run))?

## Sources

Read on 2026-11-07, from each documentation site's published source:

- crates.io: [Trusted Publishing](https://crates.io/docs/trusted-publishing), [usage policies](https://crates.io/policies), the crate settings, new trusted publisher and API token pages, the workflow file check (`svelte/src/lib/components/WorkflowVerification.svelte`), and the owner invitation (`src/controllers/krate/owners.rs`) (`rust-lang/crates.io` at `35c0e87`); [`rust-lang/crates-io-auth-action`](https://github.com/rust-lang/crates-io-auth-action).
- Cargo: [Publishing on crates.io](https://doc.rust-lang.org/cargo/reference/publishing.html), [`cargo owner`](https://doc.rust-lang.org/cargo/commands/cargo-owner.html) (`rust-lang/cargo` at `c07ac2c`), and what `cargo owner --add` prints (`src/ops/registry/cargo_owner.rs` at `c82e769`).
- npm (`npm/documentation` at `b5bd802`): [Trusted publishing](https://docs.npmjs.com/trusted-publishers), [Staged publishing](https://docs.npmjs.com/staged-publishing), [Creating an organization](https://docs.npmjs.com/creating-an-organization), [Adding members](https://docs.npmjs.com/adding-members-to-your-organization), [Organization roles](https://docs.npmjs.com/organization-roles-and-permissions), [Managing permissions](https://docs.npmjs.com/managing-organization-permissions), [Requiring 2FA in an organization](https://docs.npmjs.com/requiring-two-factor-authentication-in-your-organization), [About the developers team](https://docs.npmjs.com/about-developers-team), [Team access to packages](https://docs.npmjs.com/managing-team-access-to-organization-packages), [Requiring 2FA to publish](https://docs.npmjs.com/requiring-2fa-for-package-publishing-and-settings-modification), [`npm trust`](https://docs.npmjs.com/cli/v11/commands/npm-trust), [`npm owner`](https://docs.npmjs.com/cli/v11/commands/npm-owner), [`npm access`](https://docs.npmjs.com/cli/v11/commands/npm-access), [`npm publish`](https://docs.npmjs.com/cli/v11/commands/npm-publish).
- PyPI (`pypi/warehouse` at `a7d67c0`): [Adding a Trusted Publisher to an existing project](https://docs.pypi.org/trusted-publishers/adding-a-publisher/), [Managing project collaborators](https://docs.pypi.org/project-management/managing-collaborators/).
- GitHub (`github/docs` at `8cd1075`): [Managing environments for deployment](https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/manage-environments), [Deployments and environments](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments) (deployment rules match `GITHUB_REF`; administrators bypass protection rules by default), [Reviewing deployments](https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/review-deployments) (bypassing them), [Creating rulesets for a repository](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/creating-rulesets-for-a-repository), [Available rules for rulesets](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets). The state of `development` from the REST API's [branch](https://docs.github.com/en/rest/branches/branches#get-a-branch) and [rules for a branch](https://docs.github.com/en/rest/repos/rules#get-rules-for-a-branch) endpoints.

The npm CLI's behaviour behind the dry-run job (a dry run checks the registry for the version; a workstation publish with provenance fails) was read from npm 11.21.1's `lib/commands/publish.js` and `libnpmpublish`, and what it runs as a publish from `deref` in `lib/utils/cmd-list.js` and from `nopt`, which parses its options (one or two dashes, abbreviations, `--no-`, `--dry-run false`); `npm trust`'s one configuration per package from its `docs/content/commands/npm-trust.md`, and `npm org ls` signed out (no output, exit 0) by running it. The npm organisation's existence was read from the registry's `/-/org/<scope>/user` and `/-/org/<scope>/team` endpoints, compared for `opentide`, the organisation `babel` and the users `behemothsecurity`, `sindresorhus` and `isaacs`.
