---
title: Publishing names and trusted publishers
description: Every name opentide publishes under on crates.io, npm and PyPI, who owns it, which workflow may publish it, and the steps a maintainer takes to set each one up.
---

# Publishing names and trusted publishers

opentide publishes, or will publish, under names on three registries. This page lists each name, who owns it, the workflow in this repository that may publish it with trusted publishing (OpenID Connect, no stored token), and the steps a maintainer takes to set it up. It is UC-0.1 ([#799](https://github.com/opentidehq/opentide/issues/799)) of the Unified Core epic ([#790](https://github.com/opentidehq/opentide/issues/790); plan in [#789](https://github.com/opentidehq/opentide/pull/789), decisions D-5 and D-6).

The state under **today** was read from the registries' public APIs on **2026-11-07**; [Verify](#verify) has the commands. Only a maintainer can publish a placeholder, add an owner or register a publisher: [Maintainer steps](#maintainer-steps) lists each one with the check that proves it done.

## Names

### crates.io

| Name | Today | Owners today | Trusted publisher today | Trusted publisher required |
|------|-------|--------------|-------------------------|----------------------------|
| `opentide` | not published | none | none | `opentidehq/opentide`, `engine-release.yml`, until UC-5.5; then `publish.yml` |
| `opentide-core`, `opentide-highlight`, `opentide-syntax`, `opentide-kql`, `opentide-spl`, `opentide-esql`, `opentide-eql`, `opentide-kuery`, `opentide-lucene`, `opentide-falco`, `opentide-ecs`, `opentide-tide`, `opentide-analysis`, `opentide-lsp` (14 crates) | 0.11.0 | user `behemothsecurity` | `opentidehq/language-server`, `release.yml`: crates.io records every 0.11.0 as published by trusted publishing from that repository | `opentidehq/opentide`, `engine-release.yml`, once UC-0.3 has put it on `development`; then `publish.yml` from UC-5.5 |

`opentide-wasm` is `publish = false` in language-server and has no crates.io name. The plan's new crates (`opentide-schema`, `opentide-schema-derive`, `opentide-workspace`, `opentide-compile`, `opentide-connectors`, `opentide-cli`) are unclaimed. crates.io's [usage policy](https://crates.io/policies) does not allow a crate that exists only to hold a name for a prolonged period, without functionality or development activity, so they are published when they have content (see [Decisions](#decisions-for-the-maintainer)).

### npm

| Name | Today | Maintainers today | Trusted publisher required |
|------|-------|-------------------|----------------------------|
| `@opentide/opentide` | not published | none | `opentidehq/opentide`, `publish.yml` (UC-5.5, the first workflow that publishes it) |
| `opentide` | not published | none | `opentidehq/opentide`, `publish.yml` (UC-5.5) |
| `@opentide/lsp-client` | not published | none | `opentidehq/opentide`, `engine-release.yml` (UC-0.3; language-server [#191](https://github.com/opentidehq/language-server/issues/191)) |
| `@opentide/lsp-worker` | not published | none | `opentidehq/opentide`, `engine-release.yml` (UC-0.3) |
| `@opentide/wasm`, `@opentide/<platform>` (D-6, UC-5.3) | not published | covered by the scope | `opentidehq/opentide`, `publish.yml` (UC-5.5) |

The **`@opentide` scope is already claimed**: the registry lists one package in it, `@opentide/explorer` (created 2026-10-27, maintainer `behemothsecurity`, published with provenance from `opentidehq/explorer`'s `publish.yml`). Only the members of an organisation can create packages in its scope, so `opentide` is almost certainly an npm organisation with `behemothsecurity` as a member; its members are visible only to them. Step 4 confirms it.

### PyPI

| Name | Today | Owners today | Trusted publisher today | Trusted publisher required |
|------|-------|--------------|-------------------------|----------------------------|
| `opentide` | 0.23.0 | `behemoth` (Owner) | `opentidehq/opentide`, `publish-pypi.yml`, environment `pypi` (read from 0.23.0's provenance) | the same until UC-5.5 renames the workflow `publish.yml` |

## Owners required

Every name has **at least two owners, each a person with two-factor authentication**, so that losing or compromising one account neither locks the project out nor hands it over. Today each registry has one account (`behemothsecurity` on crates.io and npm, `behemoth` on PyPI); who the second owner is, is a [decision](#decisions-for-the-maintainer).

| Registry | How a second person owns a name |
|----------|---------------------------------|
| crates.io | A named user owner on every crate (`cargo owner --add`). A GitHub team owner (`github:opentidehq:<team>`) can publish but cannot add or remove owners, so it does not count as the second owner. |
| npm | A second **owner** of the `opentide` organisation; both people in a team with read-write access to every package (new packages in the scope give the `developers` team read-write); the unscoped `opentide` also lists both as owners (`npm owner add`). |
| PyPI | A second collaborator with the **Owner** role on `opentide` (a Maintainer can upload but cannot manage collaborators). |

## Trusted publishers

Only workflows in `opentidehq/opentide` publish. Each registry matches the GitHub repository owner, the repository name and the workflow **file name** (not its path), and, when one is set, the GitHub environment of the publishing job.

| Registry | Names | Workflow | Environment | From |
|----------|-------|----------|-------------|------|
| crates.io | `opentide` and the 14 engine crates | `engine-release.yml` | none today; `crates-io` if [decided](#decisions-for-the-maintainer) | `opentide`: once its placeholder is published. Engine crates: once `engine-release.yml` is on `development` (UC-0.3) |
| crates.io | every crate | `publish.yml` | as above | UC-5.5, which replaces `engine-release.yml` |
| npm | `@opentide/lsp-client`, `@opentide/lsp-worker` | `engine-release.yml` | none today; `npm` if decided | within two days before the first engine release that publishes them (UC-0.3) |
| npm | `@opentide/opentide`, `opentide` | `publish.yml` | as above | within two days before the first release that publishes them (UC-5.5) |
| PyPI | `opentide` | `publish-pypi.yml` | `pypi` | configured; it published 0.23.0 |
| PyPI | `opentide` | `publish.yml` | `pypi` | UC-5.5, when it renames `publish-pypi.yml` |

What each registry requires, from its documentation (read 2026-11-07, [Sources](#sources)):

- **crates.io.** The crate must exist: the first publish needs an API token, and trusted publishing cannot create a crate. Only an owner with a verified email address adds a publisher. A crate takes up to five GitHub publishers, so a new one can be added before the old one is removed. A configuration does not expire. Once trusted publishing works, the crate's **Require trusted publishing for all new versions** setting rejects API tokens.
- **npm.** The package must exist. The publishing job needs npm 11.5.1 or later on Node 22.14.0 or later, GitHub-hosted runners, `id-token: write`, and a `repository.url` in `package.json` that matches the repository exactly. npm does not check a configuration when it is saved, and **a configuration that has not completed a publish within two days expires** and has to be deleted and created again, so a package's publisher is registered only shortly before the workflow that publishes it runs. Publishes through trusted publishing carry provenance by default. A configuration cannot be edited, only deleted and created again. When `workflow_dispatch` or `workflow_call` starts the publish, npm checks the name of the calling workflow.
- **PyPI.** `opentide` exists, so a new publisher is added to the project (Manage, Publishing). A *pending* publisher is only for creating a project that does not exist yet; it does not apply here. An environment is optional and strongly recommended.

A trusted publisher with no environment trusts the workflow file on any branch: anyone who can push a branch with a workflow of that name can publish. An environment whose deployment rules allow only `development` and release tags closes that gap; [Decisions](#decisions-for-the-maintainer) proposes one per registry.

## The placeholders

| Path | Publishes | Contents |
|------|-----------|----------|
| [`publishing/placeholders/crates/opentide/`](../../publishing/placeholders/crates/opentide/) | `opentide` 0.0.0 on crates.io | `Cargo.toml` (EUPL-1.2, repository, homepage, its own `[workspace]`), `Cargo.lock`, `src/lib.rs` (a crate doc comment and `#![forbid(unsafe_code)]`, no API), `README.md`, `LICENSE` |
| [`publishing/placeholders/npm/opentide-scoped/`](../../publishing/placeholders/npm/opentide-scoped/) | `@opentide/opentide@0.0.0` on npm | `package.json` (EUPL-1.2, repository, `publishConfig` with public access and provenance), `README.md`, `LICENSE`; no code |
| [`publishing/placeholders/npm/opentide/`](../../publishing/placeholders/npm/opentide/) | `opentide@0.0.0` on npm | the same, for the alias |

Each README says the name is reserved and points at the PyPI package.

**Why `publishing/placeholders/`.** UC-0.2 imports language-server in a parallel pull request: `crates/` with a root `Cargo.toml` that lists its members, `packages/` with the npm packages that `check-npm-packs.mjs` checks, `grammars/` and `data/catalogs/`. A placeholder in `crates/` or `packages/` would have to join those lists, and both pull requests would edit them. Here, each placeholder stands alone: the crate is its own Cargo workspace, so it builds and publishes whatever workspace the repository root holds, and the npm packages have no dependencies and no scripts. They are temporary: the facade crate (UC-5.1) and `@opentide/opentide` (UC-5.3) replace them, and the dry run then publishes `-p opentide` and the real package. Until then each points at this repository, where that code is being written, which is what crates.io's policy on reserved names asks of a placeholder.

Each placeholder carries a copy of the repository's `LICENSE`: the EUPL asks for a copy of the licence with every copy of the work, and neither cargo nor npm packs a file from outside the package's directory. `tests/test_package/test_publishing_placeholders.py` keeps the copies identical to `LICENSE` and the manifests consistent with this page.

## Dry run

[`.github/workflows/publish-dry-run.yml`](../../.github/workflows/publish-dry-run.yml) rehearses every publish on pull requests that change what is published (the placeholders, the workflow, `pyproject.toml`, `hatch_build.py`, `analysis/`, `README.md`, `LICENSE`, `scripts/build/release.py`), on pushes to `development` that change them, and on **Run workflow**.

| Job | Does |
|-----|------|
| `crate` | `cargo fmt`, `cargo clippy -D warnings` and `cargo doc` (warnings denied) on the placeholder, then `cargo package --list` and `cargo publish --dry-run --locked`. A version crates.io already has is a warning in a dry run, so the job stays green after the placeholder is published. |
| `npm` | npm 11.21.1 on Node 24, checked to be 11.5.1 or later; `npm pack --dry-run` must pack exactly `package.json`, `README.md` and `LICENSE`; then `npm publish --dry-run`. npm refuses a version it already has even in a dry run, so once a placeholder is on npm the job says so in a notice and checks the pack only. |
| `pypi` | The artifacts `publish-pypi.yml` uploads, built the same way: `cibuildwheel==4.3.5` (Linux x86_64: manylinux and musllinux) and `uv build --sdist`, at the version the release guard reads from `CHANGELOG.md`, then `twine check` and the publish job's own checks (one version, `cp310-abi3` wheels, one sdist). |

Nothing in it can publish: the token is read-only (`contents: read`), no job may mint the OIDC token all three registries' trusted publishing needs (no `id-token: write`), no secret is read, and every publish command has `--dry-run`. `tests/test_ci/test_publish_dry_run_workflow.py` fails if that changes.

**maturin.** Issue #799 names `maturin build`. opentide's wheel is built by hatchling with `hatch_build.py` today, and maturin arrives with the release train (UC-5.5), so the dry run builds the artifact a release builds now. When UC-5.5 moves the wheel to maturin, this job moves with it.

The same commands run locally from a clean checkout:

```bash
cargo publish --dry-run --locked --manifest-path publishing/placeholders/crates/opentide/Cargo.toml
(cd publishing/placeholders/npm/opentide-scoped && npx --yes npm@11.21.1 publish --dry-run)
(cd publishing/placeholders/npm/opentide && npx --yes npm@11.21.1 publish --dry-run)
SETUPTOOLS_SCM_PRETEND_VERSION="$(python3 scripts/build/release.py version)" uv build
uvx twine check dist/*
```

## Maintainer steps

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

### 2. crates.io: a second owner on every crate

1. With the token of step 1 still logged in:

   ```bash
   for crate in opentide opentide-core opentide-highlight opentide-syntax opentide-kql opentide-spl \
       opentide-esql opentide-eql opentide-kuery opentide-lucene opentide-falco opentide-ecs \
       opentide-tide opentide-analysis opentide-lsp; do
     cargo owner --add <second-github-login> "$crate"
   done
   cargo logout
   ```

2. The second owner must have signed in to crates.io once, then accepts each invitation at [Pending invites](https://crates.io/me/pending-invites).
3. Revoke the token on [API Tokens](https://crates.io/settings/tokens).
4. **Verify:** every crate lists two people.

   ```bash
   for crate in opentide opentide-core opentide-highlight opentide-syntax opentide-kql opentide-spl \
       opentide-esql opentide-eql opentide-kuery opentide-lucene opentide-falco opentide-ecs \
       opentide-tide opentide-analysis opentide-lsp; do
     printf '%s: ' "$crate"
     curl -s -A "opentide-maintainer (https://github.com/opentidehq/opentide)" "https://crates.io/api/v1/crates/$crate/owners" \
       | jq -r '[.users[] | select(.kind == "user") | .login] | join(" ")'
     sleep 1
   done
   ```

   Expected: two logins on every line. Today each line is `behemothsecurity`, and `opentide` is empty.

### 3. crates.io: trusted publishing

For **`opentide`**, now:

1. Open [the crate's settings](https://crates.io/crates/opentide/settings), section **Trusted Publishing**, click **Add**.
2. **Publisher** GitHub; **Repository owner** `opentidehq`; **Repository name** `opentide`; **Workflow filename** `engine-release.yml`; **Environment name** empty, or the environment you decided on. Click **Add**.
3. After the first version published by that workflow, tick **Require trusted publishing for all new versions**.

For **the 14 engine crates**, once UC-0.3 has merged `.github/workflows/engine-release.yml` into `development` and before its first engine release:

1. Add the same publisher to each crate, as above (`https://crates.io/crates/<crate>/settings`). Keep language-server's `release.yml` publisher until the switch is proven: a crate takes five.
2. After the first engine release from this repository has published the crates, delete the `opentidehq/language-server` publisher on each crate and tick **Require trusted publishing for all new versions**. Do this before language-server is archived (UC-6.3).

The `release.py trust` step that UC-0.3 imports from language-server does step 1 through the crates.io API when the publishing job has a token with the `trusted-publishing` scope; it registers no environment.

**Verify:** a release's versions record the repository that published them.

```bash
curl -s -A "opentide-maintainer (https://github.com/opentidehq/opentide)" https://crates.io/api/v1/crates/opentide-lsp/versions?per_page=1 \
  | jq -c '.versions[0] | {num, trustpub_data}'
```

Expected after the switch: `"repository":"opentidehq/opentide"`. Today: `{"num":"0.11.0","trustpub_data":{"provider":"github","repository":"opentidehq/language-server",...}}`. The registered publishers themselves are readable by an owner only (`GET https://crates.io/api/v1/trusted_publishing/github_configs?crate=<crate>` with a token that has the `trusted-publishing` scope), or on each crate's settings page.

### 4. npm: the `opentide` organisation

1. Sign in on [npmjs.com](https://www.npmjs.com/login). Open `https://www.npmjs.com/settings/opentide/members`.
   - If the page lists the members, the organisation exists: go on.
   - If npm has no organisation `opentide`, the scope belongs to a user account, and an organisation cannot take a name a user holds: [convert that account](https://docs.npmjs.com/converting-your-user-account-to-an-organization). Creating it from scratch: profile picture, **Add an Organization**, **Name** `opentide`, the free **Unlimited public packages** plan, **Create**.
2. **Members**, **Invite Members**: the second person's npm username, team `developers`, **Invite**. Once they accept, click **owner** in their row, so that the organisation has two owners.
3. **Members**, **Enable 2FA Enforcement**, and confirm.
4. **Verify:** `npm org ls opentide` (signed in as a member) lists both people with the role `owner`.

### 5. npm: publish the two placeholders

```bash
npm install --global npm@11.21.1        # 11.5.1 or later
npm login                               # in the browser, with two-factor authentication
cd publishing/placeholders/npm/opentide-scoped
npm publish --provenance=false          # npm asks for the second factor
cd ../opentide
npm publish --provenance=false
npm logout
```

`--provenance=false`: provenance is signed in CI only (GitHub Actions or GitLab), and npm refuses a publish from a workstation when `publishConfig` asks for provenance. The flag overrides `publishConfig` for this one publish; every later version comes from CI with provenance. `publishConfig` already makes the scoped package public.

Then on each package's page, **Settings**, **Publishing access**: **Require two-factor authentication and disallow tokens**, **Update Package Settings**.

**Verify:** the issue's commands.

```bash
npm view @opentide/opentide name
npm view opentide name
```

Expected: `@opentide/opentide`, then `opentide`. Today both fail with `npm error code E404`.

### 6. npm: owners of both packages

```bash
npm owner add <second-npm-user> opentide
npm access grant read-write opentide:developers opentide
npm access list collaborators @opentide/opentide
npm access list collaborators opentide
```

`@opentide/opentide` is read-write for the `developers` team as soon as it is created. **Verify:** each `npm access list collaborators` lists both people as `read-write`, and `npm owner ls opentide` lists both.

### 7. npm: trusted publishing, when the publishing workflow exists

A configuration that has not published within two days expires, so register each one shortly before the workflow publishes:

| Packages | Workflow | When |
|----------|----------|------|
| `@opentide/lsp-client`, `@opentide/lsp-worker` | `engine-release.yml` | UC-0.3: after a first publish by hand (npm registers publishers for existing packages only; language-server #191), before the first engine release with the repository variable `NPM_PUBLISH=true` |
| `@opentide/opentide`, `opentide` | `publish.yml` | UC-5.5, before its first release |

1. On the package's page, **Settings**, **Trusted publishing** (**Trusted Publisher**, **Select your publisher**): **GitHub Actions**.
2. **Organization or user** `opentidehq`; **Repository** `opentide`; **Workflow filename** the file above (name only, with `.yml`); **Environment name** empty, or the environment you decided on; **Allowed actions**: `npm publish`. Save.
3. The same from the command line (npm 11.15.0 or later, two-factor authentication):

   ```bash
   npm trust github @opentide/opentide --repo opentidehq/opentide --file publish.yml --allow-publish
   npm trust list @opentide/opentide
   ```

**Verify:** `npm trust list <package>` shows the workflow; after the release, `npm view <package>@<version> dist.attestations` shows the provenance attestation.

### 8. PyPI

1. Second owner: [Your projects](https://pypi.org/manage/projects/), `opentide`, **Manage**, **Collaborators**: the second person's PyPI username, role **Owner**, **Invite**. They accept from the email or from **Pending invitations** on their **Your projects** page.
2. Trusted publisher: nothing to do until UC-5.5. Then, before the first release from `publish.yml`: **Manage**, **Publishing**, GitHub: **Owner** `opentidehq`, **Repository name** `opentide`, **Workflow name** `publish.yml`, **Environment name** `pypi`, **Add**. Remove the `publish-pypi.yml` publisher after that release.
3. **Verify** the owners and the publisher:

   ```bash
   curl -s https://pypi.org/pypi/opentide/json | jq -c '.ownership.roles'
   curl -s -H 'Accept: application/vnd.pypi.integrity.v1+json' \
     https://pypi.org/integrity/opentide/0.23.0/opentide-0.23.0.tar.gz/provenance \
     | jq -c '[.attestation_bundles[].publisher]'
   ```

   Expected: two `Owner` roles. Today: `[{"role":"Owner","user":"behemoth"}]`, and the publisher `[{"environment":"pypi","kind":"GitHub","repository":"opentidehq/opentide","workflow":"publish-pypi.yml"}]`.

### 9. GitHub environments, if you decide on them

Create each environment before any workflow names it: a workflow that names a missing environment creates it with no protection rules.

1. Repository **Settings**, **Environments**, **New environment**: name `crates-io` (then `npm`), **Configure environment**.
2. **Deployment branches and tags**: **Selected branches and tags**; **Add deployment branch or tag rule**: branch `development`; tag `engine-v*` (and `v*` for `publish.yml`). Optionally **Required reviewers**.
3. Name the environment in the registry's publisher configuration and on the publishing job (`environment: crates-io`), in the same change: a publisher with an environment rejects a job without one.

## Verify

The issue's commands, and their output on 2026-11-07, which shows steps 1 and 5 still to do:

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
2. **GitHub environments.** `crates-io` and `npm`, restricted to `development` and the release tags, as `pypi` is for PyPI? They must exist before `engine-release.yml` (UC-0.3) names them, and the publisher configurations must name them too.
3. **maturin.** The dry run builds the wheel the way a release does today (cibuildwheel, hatchling, `hatch_build.py`). Is that the acceptable reading of the issue's `maturin build` until UC-5.5?
4. **npm trusted publishing timing.** npm expires a publisher that has not published within two days, and nothing in this repository publishes `@opentide/opentide` or `opentide` before UC-5.5. Accept that their publishers are registered with UC-5.5 (step 7) rather than in UC-0.1?
5. **The plan's other crate names.** Publish `opentide-schema` and the other new crates only when they have content (crates.io's policy on name reservation), or reserve them now?

## Sources

Read on 2026-11-07, from each documentation site's published source:

- crates.io: [Trusted Publishing](https://crates.io/docs/trusted-publishing), [usage policies](https://crates.io/policies), the crate settings and API token pages (`rust-lang/crates.io` at `35c0e87`); [`rust-lang/crates-io-auth-action`](https://github.com/rust-lang/crates-io-auth-action).
- Cargo: [Publishing on crates.io](https://doc.rust-lang.org/cargo/reference/publishing.html), [`cargo owner`](https://doc.rust-lang.org/cargo/commands/cargo-owner.html) (`rust-lang/cargo` at `c07ac2c`).
- npm (`npm/documentation` at `b5bd802`): [Trusted publishing](https://docs.npmjs.com/trusted-publishers), [Staged publishing](https://docs.npmjs.com/staged-publishing), [Creating an organization](https://docs.npmjs.com/creating-an-organization), [Adding members](https://docs.npmjs.com/adding-members-to-your-organization), [Organization roles](https://docs.npmjs.com/organization-roles-and-permissions), [Managing permissions](https://docs.npmjs.com/managing-organization-permissions), [Requiring 2FA in an organization](https://docs.npmjs.com/requiring-two-factor-authentication-in-your-organization), [About the developers team](https://docs.npmjs.com/about-developers-team), [Team access to packages](https://docs.npmjs.com/managing-team-access-to-organization-packages), [Requiring 2FA to publish](https://docs.npmjs.com/requiring-2fa-for-package-publishing-and-settings-modification), [`npm trust`](https://docs.npmjs.com/cli/v11/commands/npm-trust), [`npm owner`](https://docs.npmjs.com/cli/v11/commands/npm-owner), [`npm access`](https://docs.npmjs.com/cli/v11/commands/npm-access), [`npm publish`](https://docs.npmjs.com/cli/v11/commands/npm-publish).
- PyPI (`pypi/warehouse` at `a7d67c0`): [Adding a Trusted Publisher to an existing project](https://docs.pypi.org/trusted-publishers/adding-a-publisher/), [Managing project collaborators](https://docs.pypi.org/project-management/managing-collaborators/).
- GitHub: [Managing environments for deployment](https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/manage-environments).

The npm CLI's behaviour behind the dry-run job (a dry run checks the registry for the version; a workstation publish with provenance fails) was read from npm 11.21.1's `lib/commands/publish.js` and `libnpmpublish`.
