# opentide 1.0.0-rc.1 from the registries: end-to-end report (2026-11-20)

Scope: opentide `1.0.0-rc.1` as a new user gets it: PyPI `1.0.0rc1`, crates.io `1.0.0-rc.1`, the GitHub
pre-release `v1.0.0-rc.1`. Nothing was installed or built from the repository checkout, which was read for
docs and fixtures only. Product code was not changed, nothing was published, no issue or PR was filed.

**Result: no blocker and no major bug.** Every install path works, the documented tutorial passes literally,
and the tenant behaviour the release notes promise (`unchanged`, renamed Splunk rule cleanup, `not_attempted`
with a non-zero exit, `doctor --live`) was reproduced on local Docker tenants. Seven findings: three minor, four
docs. All were reproduced at least twice before being written down.

## Environment and method

- Linux x86_64 (4 cores, glibc), Python 3.10.20, 3.11.15, 3.12.13, 3.13.14, 3.14.6 (uv-managed), Rust 1.99.1,
  Docker 29.10 (daemon started by hand in the sandbox), Node 22.
- Every venv, workspace and build lived outside the repo, in the session scratchpad.
- Tenants (all local, Docker): Elasticsearch + Kibana 8.19.0 (`mirror.gcr.io/library/elasticsearch`, `.../kibana`),
  Splunk Enterprise 10.6.2.5 (`mirror.gcr.io/splunk/splunk:latest`, no Enterprise Security app, so the tenant sets
  `enterprise_security = false`), Graylog 6.3.15 with MongoDB 7.0 and OpenSearch 2 (`mirror.gcr.io`). No SaaS
  tenant was contacted. The Bitdefender variables were not read and its host was not contacted: Bitdefender was
  exercised offline only (validate, dry-run payload).
- Sandbox limits that are not product findings: `gh release view` needs GraphQL, which the sandbox refuses, so
  the release was read with `gh api repos/.../releases/tags/v1.0.0-rc.1`; `codeload.github.com` and
  `api.github.com/repos/opentidehq/skills` answer 403, so `setup skills` fell back to the packaged skill copy
  (with an accurate warning); `pypi.org/project/...` HTML is behind a bot challenge, so the PyPI page was checked
  through `/pypi/opentide/1.0.0rc1/json` and PyPI's own `readme_renderer`; `crates.io` HTML pages are a
  JavaScript app, so they were checked through the API.

## 1. Coverage table

Legend: pass / fail (bug id) / not run (reason).

### 1.1 PyPI

| Step | Result |
|------|--------|
| `pip install --pre opentide`, fresh venv, Python 3.10 / 3.11 / 3.12 / 3.13 / 3.14 | pass x5 |
| `pip install opentide==1.0.0rc1`, same five | pass x5 |
| `opentide --version` prints `opentide 1.0.0rc1` (all 10 venvs) | pass |
| `pip show opentide` lists no dependencies (`Requires:` empty, 10 venvs) | pass |
| `pip install "opentide[plugins]==1.0.0rc1"` adds pydantic | pass (pydantic 2.14.4, pydantic-core 2.50.5; checked on 3.12) |
| `python -c "import opentide; print(opentide.__version__)"` | pass, `1.0.0rc1` x10 |
| Wheel is the `cp310-abi3` one for this platform | pass, `Tag: cp310-abi3-manylinux_2_28_x86_64`; `py.typed` and `_native.abi3.so` present |
| `uv tool install opentide==1.0.0rc1` | pass |
| `pipx install --pip-args=--pre opentide` | pass (pipx 1.18.19, installed from PyPI into a scratch venv) |
| Extra: upgrade 0.28.1 to rc1 in place; `uv pip install --prerelease=allow opentide`; no musllinux wheel | pass (upgrade works; `--prerelease=allow` works; musl: `No matching distribution found`, as documented) |
| Extra: `uv tool install opentide` without `--pre` | pass (resolves 0.28.1, as pre-release rules require) |

### 1.2 sdist

| Step | Result |
|------|--------|
| `pip install --no-binary opentide opentide==1.0.0rc1` (needs Rust), timed | pass. **12 m 27 s** wall (user 21 m 38 s) on 4 cores, Python 3.13, Rust 1.99.1; built `opentide-1.0.0rc1-cp310-abi3-linux_x86_64.whl`; `opentide --version` and `validate` work. A few light commands ran alongside, so treat the time as an upper bound |

### 1.3 crates.io

| Step | Result |
|------|--------|
| `cargo install opentide --version 1.0.0-rc.1 --features cli --locked`, then `opentide --version` | pass. 7 m 15 s; prints `opentide 1.0.0-rc.1` |
| Same command as the release body writes it, without `--locked` | pass. 5 m 37 s (shared target dir with the run above, so deps were warm) |
| `cargo install opentide-lsp --version 1.0.0-rc.1 --locked` (has a bin) | pass. 2 m 20 s; speaks LSP on stdio (diagnostics returned); reports `1.0.0-rc.1` |
| Fresh crate with `opentide = "=1.0.0-rc.1"`, program that opens a workspace and validates it | pass, with a caveat: default features report `engine_unavailable` on every workspace (RC1-6); with `features = ["queries"]` it prints `failed: false` |
| crates.io metadata, the 25 crates at rc.1 | pass: description, repository, license `EUPL-1.2`, `rust-version` 1.95, not yanked, readme present. Cosmetic: README says "nine platforms" (RC1-5). `opentide-syntax` is not part of rc.1 (last version 0.16.1; retired crate, not a defect) |
| docs.rs | pass: all 25 rc.1 crates have `doc_status: true`; `opentide`, `Workspace` and `opentide_lsp` pages render |

### 1.4 GitHub release

| Step | Result |
|------|--------|
| Download linux x86_64 assets (`opentide-v1.0.0-rc.1-x86_64-unknown-linux-gnu`, the `opentide-lsp` one, both installers, `SHA256SUMS`, `highlights`, `LICENSE`, `NOTICE`) | pass (via curl; all 30 assets are present, not a draft, `prerelease: true`) |
| `sha256sum --check SHA256SUMS` | pass: 8 of 8 downloaded files `OK` (22 other listed files not downloaded) |
| `gh attestation verify <binary> -R opentidehq/opentide` | pass, exit 0 (`gh` prints nothing on a non-TTY; `--format json` shows `publish.yml@refs/heads/integration/unified-core`, SLSA provenance v1) |
| Run `opentide-installer.sh`, then `opentide --version` and `opentide-lsp --version` | pass for install (both binaries installed after checking SHA256SUMS); **fail RC1-2**: `opentide-lsp --version` prints `opentide-lsp 1.0.0`, not the candidate |
| `docs/usage/installation.md` documents the installer | fail (RC1-4): it does not; the installer is in `docs/cli/lsp.md` and `docs/usage/migration/language-server.md` only |
| aarch64 / macOS / Windows assets and installers | not run (Linux x86_64 only) |
| `cargo binstall opentide-lsp` | not run (`cargo-binstall` not installed); the published crate's `[package.metadata.binstall]` matches the release asset names |

### 1.5 npm

| Step | Result |
|------|--------|
| `@opentide/opentide` is NOT published | pass: `npm view` gives E404 for `@opentide/opentide`, `opentide`, `@opentide/lsp-client`, `@opentide/lsp-worker`, `@opentide/wasi-host` and the linux-x64 native package |
| Docs do not promise it for rc.1 | pass: `docs/sdk/typescript.md` says "The packages are not on npm yet", the release body says "npm ... ships with the final 1.0.0" |

### 2. End to end with the PyPI install (pip-installed `opentide` 1.0.0rc1, Python 3.13)

| Step | Result |
|------|--------|
| `docs/usage/tutorial.md`, steps 1-10, followed literally (YAML blocks extracted from the page) | pass: every output matches the page (`setup`, `generate` 21 files, `validate --strict`, `lint --strict`, `--json validate`, the dangling-reference code frame and exit 1, `info`, `info --technique T1059 coverage`, `validate query`, the dry-run plan text, `generate docs` 7 files) |
| `docs/usage/repository-setup.md`: one-shot `setup --yes ... --ci github`; `setup env`, `hooks`, `mcp --cursor`, `mcp --claude-code`, `skills --generic`, `skills discover` | pass (skills: packaged copy used because the sandbox blocks the catalogue download, see Environment). The interactive wizard was not run |
| `setup --org` | pass: `organisation.toml` written; `new` copies it into `metadata.organisation` |
| `new` threat, objective and rule on all 13 platforms | pass: one rule with 13 blocks, 31 placeholders, `validate --strict` passes (4 objects) |
| `validate --strict` | pass |
| `lint` / `lint --strict` | pass: 61 `placeholder` warnings, exit 0; `--strict` exit 1, as documented |
| `generate` | pass: 37 files, 6 phases |
| coverage | pass as `opentide info coverage --technique T1548` (`Coverage for T1548: 1 rule (0 own, 1 inherited)`). There is no top-level `opentide coverage`; the docs only document `info coverage` |
| `generate docs` | pass |
| 13-platform dry-run payloads | pass: Sentinel, Defender, SentinelOne, CrowdStrike, HarfangLab, Carbon Black, Sysdig, Elastic, Splunk from the repo's `deploy-tenants` golden fixture (9 plans, no failures); Graylog, Elastic and Splunk live; Bitdefender, Exabeam and Google SecOps from hand-edited scaffolds (payload shown for each) |
| Offline query engines via MCP `validate_query`, good and bad query per platform | pass: CQL, YARA (HarfangLab and Bitdefender), YARA-L, Exabeam, Graylog Lucene, SPL, Kibana KQL, Falco all accept the good query and report a coded error on the bad one |
| `setup ci github` and `setup ci gitlab` (and `azure`) pin `opentide==1.0.0rc1`; pip installs that pin | pass: `OPENTIDE_VERSION: "1.0.0rc1"` (GitLab `1.0.0rc1`), `pip install "opentide==$OPENTIDE_VERSION"`; the same spelling installs in a fresh venv. The commands the GitHub pipeline runs (`validate/lint --strict --format sarif --output`, `generate`, `generate inflight`, `inflight prune`, `generate docs --output docs`, `deploy --dry-run`) were run locally and work. Running the pipelines on GitHub/GitLab: not run (SaaS); GitLab CI lint: not run |
| MCP, `opentide mcp start` over stdio | pass: `initialize` (protocol 2025-06-18, server `opentide 1.0.0rc1`), 10 tools, 6 resources, `search`, `validate_rule`, `validation_report`, `validate_query`, `deploy_rule` with `dry_run: true`, clean exit on stdin close, stdout carries only JSON-RPC |
| LSP, `opentide lsp start`, plus the release `opentide-lsp --stdio` and the cargo-built one | pass x3: `initialize`, `didOpen` of a rule with `wher`, `publishDiagnostics` with `kql_unknown_operator` at 26:8, `shutdown`/`exit` 0 (version string: RC1-2) |
| Python SDK `opentide.Workspace`: open, validate, lint, `rules()`, `deploy_plan`, `from_files`, error codes | pass on 3.10, 3.11, 3.12, 3.13 and 3.14 |
| `doctor` | pass (exit 0; a `lsp_catalog` warning appears when a workspace is shared between pip and binary installs, RC1-3) |
| `doctor --live` | pass: right credentials, all three tenants `reached with its credentials`, exit 0; wrong credential, `could not be reached (authentication_failed)` for that tenant, exit 1; unset variable, `1 of 1 variables unset`, exit 0 |

### 2.1 Local Docker tenants

| Step | Elastic 8.19 | Splunk | Graylog 6.3 |
|------|--------------|--------|-------------|
| Deploy | pass: `created`, rule tagged `opentide` | pass: `deployed`, `search` as written, `alert.managedBy` empty | pass: `created` |
| Deploy again | pass: `unchanged` | pass: `unchanged` | `updated` (the release notes claim `unchanged` for Elastic and Splunk only) |
| Rename a rule | not run (only Splunk is specified) | pass: `warning: Splunk renamed search deleted · name: Local Splunk Rule`; REST list shows only `Local Splunk Rule Renamed` | not run |
| Wrong credential | pass: `skipped ... not attempted: tenant elastic-local failed`, `1 not attempted`, exit 1 | pass: same, exit 1 (HTTP 401) | pass: same, exit 1 (`graylog_tenant_unauthenticated`) |
| `opentide query` | pass: ES\|QL 3 rows; Kibana KQL 1 row (documented "alerts a rule preview raised") | pass: `makeresults` 3 rows; `--rule` 0 rows (no data) | pass: 3 rows via GELF messages |
| `doctor --live` | pass ok / fail wrong key | pass ok / fail wrong token | pass ok / fail wrong token |

The other 10 platforms were not run live: they need SaaS tenants.

### 3. The release itself

| Step | Result |
|------|--------|
| Release body commands (`pip install --pre opentide`, `pip install opentide==1.0.0rc1`, `cargo install opentide --version 1.0.0-rc.1 --features cli`) | pass, exactly as written. The `1.0.0rc1` from pip claim holds |
| Body claims, checked: ~20 ms start; 1,100-object workspace in 0.43 s; `unchanged`; `not attempted` and non-zero exit; `doctor --live` never fails on missing credentials; YAML 1.2 and typed fields (`enabled: yes`, `created: 20260101` fail; `"42"` in an integer field fails); `filename_mismatch` rename; `setup --name ""` exit 2; `query` outside a workspace exit 1; `deploy/query/info/validate query` with a repeated `--platform` exit 2; Splunk SPL as written, `alert.managedBy` empty; Elastic tag `opentide`; `opentide[plugins]` and `opentide.plugins.PlatformPlugin`; `tui` and `serve` exist; no musl wheel | pass. Measured: `opentide --version` 24 ms (pip) / 2 ms (binary), `opentide info` 28 ms; 1,100 objects validate in 0.32-0.38 s (pip) and 0.26-0.31 s (binary) wall |
| Body wording: "a repeated `--platform` is a usage error (exit 2)" | docs nit, RC1-7 |
| Body link `CHANGELOG.md#unreleased` on the `integration/unified-core` branch | pass today (HTTP 200); nit in RC1-7 |
| PyPI page: description renders; metadata | partly: renders (`readme_renderer` ok); license `EUPL-1.2`, `Requires-Python >=3.10`, classifiers 3.10-3.14, `Typing :: Typed`, six project URLs all pass (all URLs answer 200). The description itself is stale and has dead links: RC1-1 |
| crates.io pages, docs.rs | pass (see 1.3) |

## 2. Bugs

No blockers and no majors. Ids are in the order found.

### RC1-1 — docs — The PyPI page of 1.0.0rc1 tells people to install 0.28.1 and has dead links and a broken badge

- **Reproduction**
  ```bash
  curl -s https://pypi.org/pypi/opentide/1.0.0rc1/json | python3 -c "import sys,json; d=json.load(sys.stdin)['info']['description']; print([l for l in d.splitlines() if 'pip install' in l])"
  ```
  and render the same text with PyPI's renderer (`pip install 'readme_renderer[md]'`, `readme_renderer.markdown.render`).
- **Expected:** the project page of a release candidate shows an install command for that candidate (or for the current
  release without implying it is the page's version), and its links resolve on PyPI.
- **Actual:**
  - `['pip install opentide==0.28.1']`, on the page of `1.0.0rc1`.
  - Four relative links, which PyPI does not resolve: `CHANGELOG.md`, `docs/`, `AGENTS.md`,
    `.agents/skills/docs-maintenance/SKILL.md`.
  - The coverage badge URL answers 404
    (`https://raw.githubusercontent.com/opentidehq/opentide/python-coverage-comment-action-data/badge.svg`);
    `git ls-remote origin python-coverage-comment-action-data` returns no ref, so the branch is gone.
- **Location:** `README.md` lines 4 (badge), 13 (pin), 18, 31 and 33 (relative links) in the repo (it is the PyPI readme). The same `0.28.1`
  pin is in `docs/mcp/index.md:14` and `docs/sdk/installation.md:12,16`.

### RC1-2 — minor — `opentide-lsp` reports `1.0.0` in the wheel and the GitHub binaries, `1.0.0-rc.1` from crates.io

- **Reproduction** (any of these):
  ```bash
  bash opentide-installer.sh            # release v1.0.0-rc.1
  opentide --version                    # opentide 1.0.0-rc.1
  opentide-lsp --version                # opentide-lsp 1.0.0
  cargo install opentide-lsp --version 1.0.0-rc.1 --locked && opentide-lsp --version   # opentide-lsp 1.0.0-rc.1
  pip install opentide==1.0.0rc1 && opentide doctor | grep analysis_engine
  ```
- **Expected:** every component of the candidate names the candidate; `docs/cli/lsp.md` says the binary "has the
  version of the opentide release it ships with".
- **Actual:**
  - GitHub binary: `opentide-lsp 1.0.0`; LSP `initialize` answers `serverInfo: {'name': 'opentide-lsp', 'version': '1.0.0'}`
    from the release binary and from `opentide lsp start` in the wheel.
  - `opentide doctor` (pip): `✓ The analysis engine (language server 1.0.0) loads · analysis_engine`.
  - The cargo-built binary answers `1.0.0-rc.1`. The sdist build log compiles `opentide-workspace v1.0.0
    (.../crates/opentide-workspace)`, while `cargo install` compiles `opentide-lsp v1.0.0-rc.1`, so the wheel and the
    binaries are built from a workspace that was not bumped to the candidate version, and crates.io's was.
- **Location:** `crates/opentide-lsp/src/lib.rs:30` (`VERSION = env!("CARGO_PKG_VERSION")`) and
  `[workspace.package] version = "1.0.0"` in `Cargo.toml:44`; the candidate bump happens in `publish.yml`'s own
  checkout (`scripts/engine/release.py bump`), apparently not for the wheel and binary jobs.

### RC1-3 — minor — `doctor` warns that a catalog is "from opentide 1.0.0rc1, not 1.0.0-rc.1" (same release, two spellings)

- **Reproduction**
  ```bash
  # workspace generated by the pip install (1.0.0rc1)
  opentide generate schemas
  # checked by the release / cargo binary (1.0.0-rc.1)
  opentide-binary doctor
  # and the other way round: regenerate with the binary, run doctor with pip
  ```
- **Expected:** one release, one verdict (`✓ Language-server catalog compiled into opentide ...`).
- **Actual:**
  ```text
  ! The language-server catalog committed in .opentide/lsp/catalogs/generated is from opentide 1.0.0rc1, not 1.0.0-rc.1 · lsp_catalog
    → opentide generate schemas
  ```
  and, after following the hint with the binary, `... is from opentide 1.0.0-rc.1, not 1.0.0rc1` from pip. Exit stays 0.
  A team where CI uses `pip install opentide==1.0.0rc1` and a developer uses `cargo install` or the installer
  can never make `doctor` clean on both. The same split shows in `doctor`'s `opentide_latest` line
  (`No newer release on PyPI than 1.0.0-rc.1`).
- **Location:** `crates/opentide-cli/src/commands/doctor.rs:760-820` (`fn lsp_catalog`, message at 813-814): the
  versions are compared as strings, not as PEP 440 / semver equivalents.

### RC1-4 — docs — No user doc describes installing the candidate, the binaries or the installer; the docs still say 0.28.1 and "not on crates.io"

- **Reproduction:** `grep -rn -E '1\.0\.0rc1|1\.0\.0-rc\.1|--pre\b' docs` finds the candidate only under `docs/internal/`;
  read `docs/usage/installation.md`, `docs/sdk/rust.md`.
- **Expected:** `docs/usage/installation.md` (the page the task points at) covers PyPI including `--pre`, the
  GitHub Release binaries and `opentide-installer.sh`; `docs/sdk/rust.md` says the crate is on crates.io.
- **Actual:**
  - `docs/usage/installation.md:43`: "The latest release is **0.28.1** (13 November 2026)"; `:52` and `:61` pin 0.28.1;
    no section on `opentide-installer.sh` / release binaries. The installer is described only in
    `docs/cli/lsp.md:196` and `docs/usage/migration/language-server.md:15`.
  - `docs/sdk/rust.md:12-19`: "The crate builds from this repository while the engine crates it wraps are not yet on
    crates.io" with `opentide = { git = ... }` and `cargo install --git ...`, "Once it is published, `cargo add opentide`
    will do". All 25 crates are on crates.io at `1.0.0-rc.1` (and `cargo add opentide` needs `--pre`-style handling, since
    a candidate is not selected by `opentide = "1"`).
  - The release body's install block is therefore the only place the candidate's install commands appear.
- **Note:** the repo checkout is at `5de5eb9e` (after the release merge), so this is what the docs site builds from.

### RC1-5 — docs — The `opentide` crate README (on crates.io and docs.rs) says "nine platforms"

- **Reproduction:** `curl -sL https://crates.io/api/v1/crates/opentide/1.0.0-rc.1/readme | grep -o 'nine platforms'`.
- **Expected:** thirteen (`PLATFORMS` in `crates/opentide-schema/src/platforms.rs`; `AGENTS.md`: "All 13 deploy").
- **Actual:** "plan a deploy to the nine platforms opentide deploys to".
- **Location:** `crates/opentide/README.md`, line 3.

### RC1-6 — minor — A first Rust program with default features and default `ValidateOptions` fails on every workspace

- **Reproduction**
  ```toml
  [dependencies]
  opentide = "=1.0.0-rc.1"
  ```
  ```rust
  let ws = Workspace::open(&path, &Options::default())?;
  let validation = ws.validate(&ValidateOptions::default());   // then print findings and validation.failed
  ```
  run on the tutorial workspace, which `opentide validate --strict` passes.
- **Expected:** a valid workspace validates, or the install section says which feature a validating program needs.
- **Actual:**
  ```text
  rules: 1
  engine_unavailable: The opentide analysis engine does not load: this build of the opentide crate has no query engines (its `queries` feature is off)
  failed: true
  ```
  Adding `features = ["queries"]` gives `failed: false`. This is documented in the feature table ("Without `queries`,
  a queries check is never skipped"), but the README and `docs/sdk/rust.md` examples all pass `QueriesMode::Off`, and
  the install section never says the default build cannot validate queries.
- **Location:** `docs/sdk/rust.md` (Features table, Open a workspace, Validate a workspace); crate defaults in
  `crates/opentide/Cargo.toml` (`default = ["schema", "workspace", "compile"]`).

### RC1-7 — docs (nit) — Release body wording: repeated `--platform`, and a changelog link to a temporary branch

- **Reproduction:** read the "Exit codes" bullet of the release body, then run
  `opentide setup --yes --name N --platform sentinel --platform sentinel --path ./x` (exit 0, scaffolds `sentinel`) and
  `opentide deploy --dry-run --all --platform elastic --platform splunk` (exit 2:
  `error: the argument '--platform <PLATFORM>' cannot be used multiple times`).
- **Expected:** the body says which commands refuse a repeated `--platform`.
- **Actual:** the bullet reads "An empty `setup --name` or a repeated `--platform` is a usage error (exit 2)", next to
  `setup`; `setup --platform` is repeatable by design (the 13-platform scaffold needs it). The change applies to
  `deploy`, `deploy metadata`, `query`, `info` and `validate query` (`CHANGELOG.md:112`).
  Also, "Full list" links to `.../blob/integration/unified-core/CHANGELOG.md#unreleased`; it resolves today and will
  break when that branch is deleted after the merge.
- **Location:** `.github/release-notes/v1.0.0-rc.1.md` (the body's source, per `release-management`).

## 3. Checked and found not to be bugs

- `tenant: ***` in warning and error lines: documented (`docs/cli/deploy.md:317`, tenant names and hosts are
  redacted from log lines; the JSON document names them).
- `metadata.version: "1"` passes `validate`: the model is `str | int` by design. A real integer field
  (Graylog `event_limit: "42"`) fails.
- `uv tool install opentide` without `--pre` installs 0.28.1: standard pre-release resolution.
- Graylog second deploy says `updated`, not `unchanged`: the release notes promise `unchanged` for Elastic and Splunk only.
- `validate_query` on a full Falco rule file fails: the Sysdig query is a condition expression; my input was wrong.
- A Rust compile error in my first program (`validation.failed()`): `failed` is a field, as the crate README shows.
- `--skip-unconfigured` does not skip a platform with no tenant when another platform has one: documented in
  `docs/usage/workflows/ci-cd.md:78`.

## 4. Not run

- Windows, macOS and aarch64 installs; the interactive `setup` wizard; `cargo binstall`; the npm packages (not published).
- SaaS tenants (Sentinel, Defender, SentinelOne, CrowdStrike, HarfangLab, Carbon Black, Sysdig, Bitdefender,
  Exabeam, Google SecOps): dry-run payloads only, plus offline query checks.
- The generated pipelines on GitHub Actions and GitLab (SaaS); GitLab CI lint.
- Elastic: the Kibana image is 8.19.0 (the `mirror.gcr.io/library` tag), not the latest 8.19 patch.
