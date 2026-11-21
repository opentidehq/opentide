# opentide 1.0.0-rc.2 from the registries: end-to-end report (2026-11-21)

Scope: opentide `1.0.0-rc.2` as a user gets it: PyPI `1.0.0rc2` (6 wheels and an sdist), crates.io `1.0.0-rc.2`
(25 crates), the GitHub pre-release `v1.0.0-rc.2` (30 assets), published by `publish.yml` run 44858380732. The
tag `v1.0.0-rc.2` and `origin/integration/unified-core` are the same commit (`cff956f97`). Nothing was installed or
built from the repository checkout (it was read for docs, fixtures and suspected line numbers). Product code was not
changed, nothing was published, no tag, release, issue or PR was created. The rc.1 report is
`docs/internal/e2e-rc1-registries-2026-11-20.md` on `origin/test/e2e-rc1-registries`.

**Result: no blocker, no major.** Every install path works, the tutorial and repository setup pass literally,
and the tenant behaviour the release notes promise reproduced on the local Docker tenants. Of the seven rc.1
findings, **RC1-2, RC1-3, RC1-4, RC1-5 and RC1-6 are fixed**; **RC1-1 is fixed in part** (links are absolute and
resolve; the coverage badge is still a 404 and the first install command is still `0.28.1`); **RC1-7 is unchanged**
(wrong wording stays in the release body; the changelog link is fixed). Four new or carried findings: one minor, three docs.

## Environment and method

- Linux x86_64 (4 cores, glibc, 15 GB), Python 3.10.20, 3.11.18, 3.12.3, 3.13.18, 3.14.6, Rust 1.97.0, Docker 29.10
  (daemon started by hand), `gh` through the agent proxy.
- Every venv, workspace and build lived outside the repo, in the session scratchpad. Home was redirected to a
  scratch directory for the documented installer run.
- Tenants (all local, Docker, nothing else contacted): Elasticsearch 8.19.0 + Kibana 8.19.0 (security on, API key),
  Splunk Enterprise 10.6.2.5 (no Enterprise Security app: `enterprise_security = false`), Graylog 6.3.15 with
  MongoDB 7.0 and OpenSearch 2 (token of a created user). Images from `mirror.gcr.io`.
- **Bitdefender:** its variables were not read and its host was not contacted. It was exercised offline only: the
  `new rule` scaffold with a Bitdefender block, `validate`, and one `validate_query` call (YARA, local engine).
  No Bitdefender dry-run payload and no deploy were run.
- Sandbox limits that are not product findings: `pypi.org/project/...` HTML is behind a bot challenge, so the PyPI
  page was read through `/pypi/opentide/1.0.0rc2/json` and PyPI's own `readme_renderer`; `crates.io` needs a
  `User-Agent` on its API; `github.com/opentidehq/website` and `.../actions/workflows/ci.yml` answer 403 through the
  proxy (`gh api repos/opentidehq/opentide/actions/workflows/ci.yml` says `active`); `codeload.github.com` is
  blocked, so `setup skills` fell back to the packaged copy, with an accurate warning.
- All timings below were taken with up to three Cargo builds and the Docker stacks running together on 4 cores
  (load average 7 to 11): treat them as upper bounds.

## 1. Coverage table

Legend: pass / fail (finding id) / not run (reason).

### 1.1 PyPI, uv, pipx

| Step | Result |
|------|--------|
| `pip install --pre opentide`, fresh venv, Python 3.10 / 3.11 / 3.12 / 3.13 / 3.14 | pass x5 (`Successfully installed opentide-1.0.0rc2`) |
| `pip install opentide==1.0.0rc2`, same five | pass x5 |
| `opentide --version` is `opentide 1.0.0rc2`; `opentide.__version__` is `1.0.0rc2` (10 venvs) | pass |
| `pip show opentide`: `Requires:` empty (10 venvs) | pass |
| Wheel: `opentide-1.0.0rc2-cp310-abi3-manylinux_2_28_x86_64.whl`; `_native.abi3.so`, `py.typed`, `_native/*.pyi` present; no `opentide-lsp` script in `bin/` (the server is inside the wheel) | pass |
| PyPI has 6 wheels (manylinux x86_64 and aarch64, macOS x86_64 and arm64, Windows x64 and arm64) and the sdist | pass |
| `uv tool install 'opentide==1.0.0rc2'`; `uv tool install --force --prerelease=allow opentide`; `opentide --version` | pass |
| `pipx install --pip-args=--pre opentide` (pipx from PyPI, scratch `PIPX_HOME`) | pass, `opentide 1.0.0rc2` |
| `uv pip install --prerelease=allow opentide` (the documented line) | pass, `opentide==1.0.0rc2` |
| `pip install opentide` and `uv pip install opentide` without `--pre` | pass, resolve `0.28.1`, as `docs/usage/installation.md` says |
| `pip install "opentide[plugins]"` | not run (rc.1: pass) |

### 1.2 sdist

| Step | Result |
|------|--------|
| `pip install --no-binary opentide opentide==1.0.0rc2 -v`, Python 3.13, Rust 1.97.0, timed | pass. **18 m 29 s** wall (1109 s), contended. Built `opentide-1.0.0rc2-cp310-abi3-linux_x86_64.whl`. `opentide --version` is `opentide 1.0.0rc2`; `doctor` reports `analysis_engine (language server 1.0.0-rc.2)`; LSP `serverInfo.version` is `1.0.0-rc.2`; MCP `engine` is `1.0.0-rc.2`. Note: the build log compiles the library crates as `v1.0.0` and `opentide-native v1.0.0-rc.2`, yet the wheel reports the candidate everywhere: the version comes from `bindings/python`, so this is not a defect (it was the rc.1 symptom, where the binaries did report `1.0.0`) |

### 1.3 crates.io

| Step | Result |
|------|--------|
| `cargo install opentide --version 1.0.0-rc.2 --features cli --locked`, then `opentide --version` | pass. 10 m 55 s (contended); `opentide 1.0.0-rc.2`; `doctor` `analysis_engine (language server 1.0.0-rc.2)` |
| Same without `--locked`, as the release body writes it | pass. 9 m 25 s (565 s, contended; separate target dir); `opentide 1.0.0-rc.2` |
| `cargo install opentide-lsp --version 1.0.0-rc.2 --locked` | pass. 2 m 18 s (deps warm); `opentide-lsp 1.0.0-rc.2`; LSP `initialize`: `serverInfo.version` `1.0.0-rc.2`, diagnostic `kql_unknown_operator` at 26:8 |
| Fresh crate, `cargo add opentide@=1.0.0-rc.2 --features queries` (docs/sdk/rust.md), builds, validates the tutorial workspace | pass: `rules: 1`, `failed: false` |
| Fresh crate, `opentide = "=1.0.0-rc.2"` with DEFAULT features, `ValidateOptions::default()` (RC1-6) | **pass**: tutorial workspace `failed: false`; the 13-platform scaffold `failed: false`; the three-tenant workspace `failed: false` with its one warning; a copy with `wher` in the KQL: `kql_unknown_operator: unknown tabular operator 'wher'`, `failed: true`, exit 1 (the queries check really runs) |
| crates.io metadata, the 25 crates at `1.0.0-rc.2` (the 25 publishable workspace crates, by name) | pass: all present, not yanked, license `EUPL-1.2`, `rust-version` 1.95, description and repository set, readme present. Bins: `opentide` (crate `opentide`), `opentide-cli`, `opentide-lsp` |
| `opentide` crate README says "thirteen platforms" (RC1-5) | **pass**: "plan a deploy to the thirteen platforms opentide deploys to"; "nine" is gone |
| docs.rs | pass: `status.json` has `doc_status: true` for all 25 crates at rc.2; `opentide`, `Workspace`, `opentide_lsp` and the features page answer 200 |

### 1.4 GitHub release

| Step | Result |
|------|--------|
| Release: `name` 1.0.0-rc.2, `draft: false`, `prerelease: true`, 30 assets | pass |
| Downloaded linux x86_64 `opentide` and `opentide-lsp`, both installers' `.sh`, `SHA256SUMS`, `highlights` zip, `LICENSE`, `NOTICE` | pass |
| `sha256sum --check --ignore-missing SHA256SUMS` (29 lines = 29 other assets) | pass: 6 of 6 downloaded files `OK` (the other 23 not downloaded) |
| `gh attestation verify <binary> -R opentidehq/opentide` for `opentide` and `opentide-lsp` | pass, exit 0 and no output on a non-TTY, as documented; `--format json`: `publish.yml@refs/heads/integration/unified-core`. A file with one byte appended: `HTTP 404: Not Found` for its digest, exit 1 |
| `opentide-v1.0.0-rc.2-x86_64-unknown-linux-gnu --version`; `opentide-lsp-... --version` | pass: `opentide 1.0.0-rc.2`, `opentide-lsp 1.0.0-rc.2` |
| `curl ... | sh` of `opentide-installer.sh` (into `OPENTIDE_INSTALL_DIR`), and the page's two-step form (`curl -O`, `sh opentide-installer.sh`, into `~/.local/bin`) | pass: both binaries installed after the SHA256SUMS check; `opentide 1.0.0-rc.2`, `opentide-lsp 1.0.0-rc.2` |
| `opentide-installer.ps1`, aarch64, macOS and Windows assets | not run (Linux x86_64 only) |
| `cargo binstall opentide-lsp` | not run (`cargo-binstall` not installed) |

### 1.5 npm

Not published for the candidate, as documented (release body: "npm ... ships with the final 1.0.0"). Not re-queried:
`npm` was not run (rc.1: E404 for every package).

### 2. End to end (pip install, Python 3.13 unless noted)

| Step | Result |
|------|--------|
| `docs/usage/tutorial.md`: the three YAML files extracted from the page and steps 1-10 followed literally | pass: `generate` 21 files, `validate --strict` `✓ 3 objects valid · 1 query`, `lint --strict` `✓ 3 files clean`, the `--json validate` shape, the dangling-reference code frame (`invalid_ref`, 17:18) and exit 1 character for character, `info`, `info --technique T1059 coverage` (own 1, inherited 0), `validate query --platform sentinel` `✓ 1 query valid`, the dry-run plan text, `generate docs` 7 files |
| `docs/usage/repository-setup.md`: one-shot `setup --yes ... --ci github`; `setup platforms`, `ci github`, `env`, `hooks`, `mcp --cursor`, `mcp --claude-code`, `skills discover`, `skills --yes --generic` | pass (skills: packaged copy, accurate warning). The interactive wizard was not run |
| `setup ci github`, `gitlab`, `azure` pin the candidate | **pass**: `OPENTIDE_VERSION: "1.0.0rc2"` (GitHub line 21, Azure line 30), `OPENTIDE_VERSION: 1.0.0rc2` (GitLab line 22), every install is `pip install "opentide==$OPENTIDE_VERSION"`; no `0.28` or `rc1` left in the three files |
| `new` threat, objective and a rule with all 13 `--platform` | pass: 13 blocks, 31 placeholders (9 + 12 + 31 = 52 lint findings), `validate` and `validate --strict` pass (3 objects) |
| `lint` / `lint --strict` | pass: 52 `placeholder` findings, exit 0; `--strict` exit 1, as documented |
| `generate` | pass: 36 files, 6 phases |
| `info` coverage | pass: `opentide info --technique T1548 coverage` is `Coverage for T1548: 0 rules` (no top-level `coverage`; the docs only document `info coverage`). `opentide --json info`: 13 platforms; `can_deploy` 13, `can_validate` 9 (sentinel, defender, splunk, sentinel_one, carbon_black, elastic, graylog, exabeam, google_secops), `can_query` 11 (all but sysdig and bitdefender): the table in `AGENTS.md` |
| `generate docs` | pass (7 files) |
| Dry-run payloads | pass: Sentinel, Defender, Splunk, SentinelOne, CrowdStrike, HarfangLab, Carbon Black, Elastic, Sysdig from the repo's `deploy-tenants` golden fixture (9 plans, `ok`); Exabeam and Google SecOps from hand-written rules (`api_request` shown for each); Graylog, Elastic and Splunk live. Bitdefender not run |
| MCP, `opentide mcp start` over stdio (pip) | pass: `initialize` (protocol 2025-06-18, server `opentide 1.0.0rc2`), 10 tools, 6 resources, `search`, `validation_report`, `validate_query` for 12 platforms (good query passes and `engine.engine` is `1.0.0-rc.2`; a typo gives `kql_unknown_operator`), clean exit on stdin close, stdout carries only JSON-RPC. My Google SecOps query lacked a section and failed with `yaral_section_missing`: my input, not a defect |
| LSP: `opentide lsp start` (pip 3.10, 3.13, 3.14; sdist wheel), the GitHub binary's `lsp start` and `opentide-lsp --stdio`, the installer's `opentide-lsp`, the cargo-built `opentide-lsp` | pass x8: `initialize`, `didOpen` of a rule with `wher`, `publishDiagnostics` `kql_unknown_operator` at 26:8, `shutdown`/`exit` 0; `serverInfo` is `{'name': 'opentide-lsp', 'version': '1.0.0-rc.2'}` in all eight |
| Python SDK `opentide.Workspace` (open, validate, lint, `rules()`, `info`, `coverage`, `deploy_plan`, `from_files`, `usage_invalid_value`, `usage_invalid_choice`, `run_json`) | pass on 3.10, 3.11, 3.12, 3.13, 3.14 |
| `doctor` in a workspace | pass (exit 0 with warnings for the scaffold only) |
| Release body claims | pass: `opentide --version` 23 ms (pip, median of 15) and 2 ms (binary); 1,100 rules validate in 0.32-0.39 s wall (pip) and 0.29 s (binary), `✓ 1100 objects valid · 1100 queries · 0.3s`; a repeated `--platform` is exit 2 on `deploy` (see RC2-4) |

### 2.1 Local Docker tenants

| Step | Elastic 8.19.0 | Splunk 10.6.2.5 | Graylog 6.3.15 |
|------|----------------|-----------------|----------------|
| Deploy | pass: `created`; rule tagged `["opentide"]` | pass: `deployed`; `search` as written; `alert.managedBy` empty | pass: `created` (warning `graylog_unknown_field` for my invented `image_lc`: correct) |
| Deploy again | pass: `unchanged`, exit 0 | pass: `unchanged`, exit 0 | `updated` (the notes promise `unchanged` for Elastic and Splunk only) |
| Rename a rule | not run (only Splunk is specified) | pass: `warning: Splunk renamed search deleted · name: Splunk Local Rule`; REST list then holds only `Splunk Local Rule Renamed` | not run |
| Wrong credential | pass: `skipped ... not attempted: tenant elastic-local failed`, `1 not attempted`, exit 1 (HTTP 401) | pass: same, exit 1 (HTTP 401) | pass: same, exit 1 (`graylog_tenant_unauthenticated`) |
| `opentide query` | ES\|QL 1 row; Kibana KQL **1 row with matching data, `0 rows` with none, and a `404` failure on a Kibana that has no preview alerts index yet (RC2-3)**; `--rule` same | `makeresults` 3 rows; `--rule` 0 rows (no data) | 3 rows via GELF messages |
| `doctor --live` | pass: `reached with its credentials` / wrong key `could not be reached (authentication_failed)`, exit 1 | pass; unset `SPLUNK_TOKEN`: `1 of 1 variables unset`, `not reached, credentials not set`, exit 0 | pass ok / wrong token exit 1 |
| `validate query --live` | pass: `✓ 1 query valid on 1 tenant` | pass | not run |

The other 10 platforms were not run live: they need SaaS tenants.

## 3. rc.1 findings, checked explicitly

| Id | rc.1 finding | rc.2 verdict |
|----|--------------|--------------|
| RC1-2 | `opentide-lsp` says `1.0.0` | **Fixed.** `opentide-lsp --version` is `opentide-lsp 1.0.0-rc.2` from the GitHub binary, the installer and `cargo install opentide-lsp --version 1.0.0-rc.2 --locked`; the wheel has no separate binary, and its `opentide lsp start` (pip 3.10, 3.13, 3.14, and the sdist-built wheel) answers `serverInfo.version` `1.0.0-rc.2`; the GitHub binary's `opentide lsp start` too. `opentide --version` per channel: pip, uv tool, pipx, sdist `1.0.0rc2`; GitHub binary, installer, `cargo install` (locked and not) `1.0.0-rc.2`. `opentide doctor` `analysis_engine`: `language server 1.0.0-rc.2` on every one of those (pip 3.10-3.14, uv tool, binary, installer, both cargo builds, sdist wheel) |
| RC1-3 | `doctor` `lsp_catalog` warning when pip and a binary share a workspace | **Fixed.** In one workspace: pip `generate schemas`, then the GitHub binary's `doctor`: `✓ Language-server catalog compiled into opentide 1.0.0-rc.2 · lsp_catalog`; binary `generate schemas`, then pip's `doctor`: `... compiled into opentide 1.0.0rc2`; installer, uv tool, both cargo builds and the sdist wheel the same way. No `!` line, exit 0 |
| RC1-6 | default features: `engine_unavailable` | **Fixed** (section 1.3). `crates/opentide/Cargo.toml:73` has `queries` in `default` |
| RC1-4 | install docs for the candidate | **Fixed.** Every command of `docs/usage/installation.md` "Release candidates" and `docs/sdk/rust.md` Install ran as written: `pip install --pre opentide`, `pip install 'opentide==1.0.0rc2'`, `uv pip install --prerelease=allow opentide`, `pipx install --pip-args=--pre opentide`, `uv tool install 'opentide==1.0.0rc2'`, both `cargo install` lines with `--locked`, `cargo add opentide@=1.0.0-rc.2 --features queries`, the `Cargo.toml` line, the installer block, the `BASE=...; curl; sha256sum --check --ignore-missing; gh attestation verify` block. Every claim of the section held (installer checks `SHA256SUMS`; `gh` exit 0 and silent; `pip install opentide` stays on 0.28.1). Wording of the `sha256sum --check` sentence: it also names files already in the directory |
| RC1-1 | PyPI page | **Partly fixed**: the four relative links are absolute and all resolve (200, `readme_renderer` ok; the `github.com/.../actions/workflows/ci.yml` and `.../website` links answer 403 through the proxy only). Still wrong: the coverage badge (RC2-1) and the install block (RC2-2) |
| RC1-5 | crate README "nine platforms" | **Fixed** ("thirteen") |
| RC1-7 | release body wording | **Not fixed** (RC2-4 below); the changelog link now points at the tag (`.../blob/v1.0.0-rc.2/CHANGELOG.md#unreleased`, 200, and `## [Unreleased]` is at line 7 of that file) |

## 4. Findings

No blockers and no majors. Ids are in the order found.

### RC2-1 — docs — The PyPI page of 1.0.0rc2 still embeds a coverage badge that is a 404

- **Reproduction**
  ```bash
  curl -sSL -o /dev/null -w '%{http_code}\n' \
    https://raw.githubusercontent.com/opentidehq/opentide/python-coverage-comment-action-data/badge.svg
  git ls-remote origin python-coverage-comment-action-data | wc -l
  ```
- **Expected:** every image on the project page loads (RC1-1 asked for "no broken badge").
- **Actual:** `404`, and `0` (the branch that held the badge no longer exists). On PyPI the badge renders as a broken
  image on line 4 of the description.
- **Location:** `README.md:4` (it is the PyPI readme, `pyproject.toml` `readme = "README.md"`). Carried over from RC1-1.

### RC2-2 — docs — The first install command on the PyPI page of 1.0.0rc2 installs 0.28.1

- **Reproduction**
  ```bash
  curl -s https://pypi.org/pypi/opentide/1.0.0rc2/json | python3 -c \
    "import sys,json; d=json.load(sys.stdin)['info']['description']; print([l for l in d.splitlines() if 'pip install' in l])"
  ```
- **Expected:** the page of a candidate shows how to install that candidate, or says in the same place that the block installs the previous stable release.
- **Actual:** `['pip install opentide==0.28.1', 'The Rust core is released as **1.0.0 release candidates** first (...): ... `pip install --pre opentide` ...']`
  (the second item is the paragraph below the block, which does name `pip install --pre opentide` and says the pin above is the newest stable release).
  The block itself, with `export OPENTIDE_REPO_ROOT=...; opentide validate`, installs 0.28.1, which has none of the
  1.0 behaviour the release notes describe. This is the documented choice
  (`.agents/skills/release-management/SKILL.md:161`: "`README.md` keeps the newest stable pin"), so it is a wording
  issue, not a regression from rc.1 (the paragraph naming `--pre` is new).
- **Location:** `README.md:13` and `README.md:18`.

### RC2-3 — minor — `opentide query` on Elastic fails with HTTP 404 instead of `0 rows` until the preview alerts index exists

- **Reproduction** (fresh Elasticsearch + Kibana 8.19.0, API key tenant, the workspace of section 2.1; reproduced three times, the third after deleting the index again)
  ```bash
  # no preview has raised an alert yet, so .preview.alerts-security.alerts-default does not exist
  opentide query --platform elastic --language kuery 'process.name: "nomatch.exe"'
  echo "exit=$?"
  # then index one matching document into logs-e2e and query for it: 1 row; the same nomatch query: `0 rows`, exit 0
  # delete the index: `curl -u ... -X DELETE .../.internal.preview.alerts-security.alerts-default-000001`, the 404 is back
  ```
- **Expected:** `elastic-local  0 rows` and exit 0, as the same query gives once the index exists. `docs/cli/query.md:157` says
  an Elastic `kuery` query "writes its preview alerts to `.preview.alerts-security.alerts-<space>`, as a preview in Kibana does".
- **Actual:**
  ```text
  error: 1 of 1 queries failed on 1 elastic tenant: elastic-local: Elastic refused the preview alerts query on elastic-local (HTTP 404)
    note: no such index [.preview.alerts-security.alerts-default]
  exit=1
  ```
  `--json`: `"status":"failed","error":"Elastic refused the preview alerts query on elastic-local (HTTP 404)"`. The same happens
  with `--rule <uuid>` for a KQL rule. The index appears the first time a preview raises an alert; a first KQL query on a
  tenant with no matching events (a new Kibana, or a rule written before data arrives) reports a tenant failure rather than zero rows.
  Not checked whether rc.1 behaves the same (its report ran with data present).
- **Location:** `crates/opentide-connectors/src/elastic.rs:2209-2224` (the `_search` on `/.preview.alerts-security.alerts-<space>`
  and `body(&found, tenant, "preview alerts")?`): an `index_not_found_exception` there is an empty result.

### RC2-4 — docs — Release body: a repeated `--platform` is listed next to `setup`, where it is allowed (unchanged from RC1-7)

- **Reproduction**
  ```bash
  opentide setup --yes --name N --platform sentinel --platform defender_for_endpoint --path ./x   # exit 0, two platforms
  opentide deploy --dry-run --all --platform elastic --platform splunk                              # exit 2
  # error: the argument '--platform <PLATFORM>' cannot be used multiple times
  ```
- **Expected:** the Breaking bullet names the commands that refuse it (`deploy`, `deploy metadata`, `query`, `info`, `validate query`; `CHANGELOG.md:112`), or splits it from the `setup --name` case.
- **Actual:** the live release body reads "An empty `setup --name` or a repeated `--platform` is a usage error (exit 2)." Taken with
  `setup`, it says the opposite of what `setup --platform` does (it is repeatable by design: the 13-platform scaffold needs it).
- **Location:** `.github/release-notes/v1.0.0-rc.2.md:48` (the body's source; the body is that file plus the intro line `scripts/build/release.py:176` adds).

### RC2-5 — docs — The SDK, MCP and CLI install pages pin 0.28.1, and the Python SDK pages document an API 0.28.1 does not have

- **Reproduction**
  ```bash
  uv venv v && uv pip install --python v/bin/python 'opentide==0.28.1'
  v/bin/python -c "from opentide import Workspace"
  # ImportError: cannot import name 'Workspace' from 'opentide'
  ```
  then read `docs/sdk/installation.md:12,16`, which pins `0.28.1` and sits beside `docs/sdk/workspace.md` (`Workspace.open`, `validate`, `deploy_plan`).
- **Expected:** a page for an API that exists only from 1.0 does not tell a reader to install a version without it, or says
  "from 1.0.0rc2 (`pip install --pre opentide`)".
- **Actual:** `docs/sdk/installation.md:12,16`, `docs/mcp/index.md:14`, `docs/mcp/installation.md:13`,
  `docs/cli/index.md:12`, `docs/index.md:24` all pin `opentide==0.28.1`. `docs/usage/installation.md` (the page that says
  which is which) was updated; these were not. By the release process the pins move at the final release; the SDK page is the one where it misleads.
- **Location:** the five files above (the same set RC1-1 listed under "Location").

## 5. Checked and found not to be bugs

- Graylog's second deploy says `updated`, not `unchanged`: the notes promise `unchanged` for Elastic and Splunk only.
- `deploy --json` is one JSON document on stdout; the extra lines I saw first were stderr, merged by my own `2>&1`.
- `gh attestation verify` prints nothing and exits 0 on success: documented.
- `tenant: ***` in warning and error lines: documented (`docs/cli/deploy.md`).
- `validate --strict` fails on `graylog_all_streams` for a Graylog rule with no `streams`: a warning by design.
- `opentide-cli` (a crate with a bin of the same name) is on crates.io: the same as rc.1.
- `deploy --dry-run` of a scaffold with status `DESIGN` is `Skipped: No rule has a status PREVIEW deploys`: documented.
- My Google SecOps `validate_query` input failed with `yaral_section_missing` (no `events:`): my input.

## 6. Not run

- Windows, macOS and aarch64 installs, `opentide-installer.ps1`, the WASI/wasm/node assets (`opentide-lsp-wasm32-wasip1.wasm`, `opentide-wasm-web`, the `*.cdx.json` SBOMs, `THIRD-PARTY-LICENSES.html`), and the 23 `SHA256SUMS` entries I did not download.
- `cargo binstall`; the npm packages (not published); Python 3.14t / musl / the Alpine sdist path; `pip install "opentide[plugins]"`.
- The interactive `setup` wizard; `setup skills` with the real catalogue (the download is blocked here).
- Every SaaS tenant (Sentinel, Defender, SentinelOne, CrowdStrike, HarfangLab, Carbon Black, Sysdig, Bitdefender, Exabeam, Google SecOps): dry-run payloads and offline checks only, except Bitdefender (scaffold, validate and one local `validate_query` only; no dry-run, no deploy, no variable read).
- The generated pipelines on GitHub Actions, GitLab and Azure (SaaS); GitLab CI lint.
- Elastic: renaming a rule and the `unchanged` of Graylog (not specified); Splunk with the Enterprise Security app (`enterprise_security = true`); Kibana's own version string (the image tag is 8.19.0; its status endpoint did not return one to my probe).
- docs.rs: status and page reachability were checked, not a visual render of each of the 25 crates.
- The PyPI and crates.io HTML pages (bot challenge / JavaScript app): checked through their APIs and the renderer.
