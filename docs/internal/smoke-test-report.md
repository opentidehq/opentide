---
title: Smoke test report, 1.0.0-rc.1 candidate
description: The pre-RC smoke test of integration/unified-core at d11702e9c, built from source and used as a new user would, then deployed to local Elastic, Graylog, Splunk and Falco tenants - the coverage matrix, every finding with its issue and fix, the go/no-go and what a person still has to check by hand.
---

# Smoke test report: `integration/unified-core` at `d11702e9c`

This report records the product **as a new user found it** at `d11702e9c`
(`Merge pull request #1622`), before any fix. Fixes land in their own PRs, linked from the
findings. [`smoke-test.md`](smoke-test.md) is the checklist this run started from; this run went beyond it.

## Summary
- **Verdict: no-go for 1.0.0-rc.1 at `d11702e9c`.** Three blockers, listed in [Go / no-go](#go--no-go), must land first.
- **81 unique findings** (92 reports, with duplicates across areas merged): **3 blockers, 13 majors, 53 minor, 12 docs**.
  - They are filed as 17 grouped issues, [#1653](https://github.com/opentidehq/opentide/issues/1653) to [#1671](https://github.com/opentidehq/opentide/issues/1671), each with a checklist and reproductions.
  - The version blocker is the existing [#1623](https://github.com/opentidehq/opentide/issues/1623).
- **Coverage:** 716 cells across five areas.
  - 564 pass and 115 fail.
  - 26 need a tenant (SaaS-only platforms, live paths and Sysdig).
  - 11 were not run, each with its reason.
- **What works well:**
  - Install from the wheel, startup in milliseconds, `info` and `doctor`.
  - Offline validation of all 12 offline languages: every one of 26 realistic rules across the 13 platforms passes `validate --strict` and `lint --strict`.
  - No panic, hang or backtrace on bad input (20 MB files, 10k-deep nesting, binary junk, CRLF, paths with spaces).
  - 3,120 rules validate in 0.84 s at 141 MB peak.
  - MCP and LSP over stdio; the wheel and the release binary give identical answers (149 MCP calls, 0 differences).
  - Node in CJS and ESM; the WASM worker.
  - Real deploys to Elastic 8.19 and 9.5: create, fire, update in place, disable and delete all pass.
- **What does not:** the generated CI deploy path.
  - The production job deploys promoted rules to no tenant and reports success.
  - The pipelines never pass the tenants' credentials.
  - The version the build reports (0.12.0) makes every generated pipeline install an old Python release.
  - Graylog deploys silently drop their stream and notification aliases.

## How it was run

- **Source:** `opentidehq/opentide` `integration/unified-core` at `d11702e9c054539e8386b6375904fcf7e2adbf61`. Nothing was published: no registry, tag or release.
- **Builds, from the tip:**
  - `uvx maturin==1.16.0 build --locked --release` → `opentide-0.12.0-cp310-abi3-manylinux_2_39_x86_64.whl` (12 min 54 s on 4 CPUs).
  - `cargo build --locked --release` for `opentide` and `opentide-lsp`.
  - The npm local-registry test from `smoke-test.md` section 0 (PASS on linux-x64-gnu).
  - `scripts/engine/build-wasm.sh browser`: all three smoke lines print.
- **Install:** each area installed the wheel into its own clean virtualenv and worked in a fresh directory outside the repository. No area used the source tree or its `.venv`.
- **Machine and tools:**
  - Linux, 4 CPUs, 15 GB RAM; Python 3.13, Rust 1.99.1, Node 22, Docker 29.
  - actionlint 1.7.7, glint 0.5.1, gitlab-ci-verify 2.11.8 (`--no-lint-api`), act 0.2.82, Neovim 0.9.5.
- **Areas, run in parallel by separate agents** (per the orchestration skill), each with its own directory and coverage table:
  - **A:** install, a new repository, CI generation, the docs walk-through and the contributor loop.
  - **B:** authoring and validation on all 13 platforms, plus the non-functional checks.
  - **C:** MCP, the language server, editors and WASM.
  - **D:** build outputs, dry-run payloads and the SDKs.
  - **E:** Phase 2 against local tenants.
  - A container restart killed every area mid-run. Each area resumed from its transcript and **re-ran every bug's reproduction before reporting it**.
- **External services:**
  - Only the local Docker tenants were contacted.
  - The environment provided Bitdefender GravityZone credentials. The user chose not to touch that tenant, so Bitdefender is "needs tenant".
  - `setup skills` tried to reach `api.github.com` and got a 403 from the sandbox proxy (its fallback works).

### Phase 2 tenants
| Image | Image id / digest | Created |
|---|---|---|
| `docker.elastic.co/elasticsearch/elasticsearch:8.19.25` | `sha256:5bfdf4313b9bc05c0d46fe219d6e67710eb0c7654ed6c275167bdf9beefc56f0` | 2026-11-05 |
| `docker.elastic.co/kibana/kibana:8.19.25` | `sha256:c6750ac07387a705f0bcb5b351ef2192cf8a66c16ad0080f701dc4181a91480c` | 2026-11-05 |
| `docker.elastic.co/elasticsearch/elasticsearch:9.5.6` | `sha256:79b4f1de4c15e6eca824723086a51e5934406d614d410cc11be77748cafac537` | 2026-10 |
| `docker.elastic.co/kibana/kibana:9.5.6` | `sha256:c7ed45da5c3cfea020fc6c99ce027f4d21d19dab330379c5115d5eb95f6ecebc` | 2026-10-29 |
| `mirror.gcr.io/graylog/graylog:6.3` | `sha256:f6764f035c993692ac310f0b0e86714f56cbee18cbf498dc40d9bbf032b29953` | 2026-11-18 |
| `mirror.gcr.io/mongo:7.0` | `sha256:884c055bff8b7144ca44830d01826facd3083b33c4dea44b94a1476c62de3c32` | 2026-11-11 |
| `mirror.gcr.io/opensearchproject/opensearch:2` | `sha256:d89333b6bd4a13b9a95aef7f373c0a6e73440f59bc0d8d1460f9b347289ed0ef` | 2026-11-15 |
| `mirror.gcr.io/splunk/splunk:latest` | `sha256:2a7cf9d2e8a2226773a9fac95b5e0e2cc8752496abfb134a21bdf8f67c9ee44d` | 2026-10-19 |
| `mirror.gcr.io/falcosecurity/falco:latest` | `sha256:1562a643953f938e02f47319b5214d93a235f11f646d60e9b8a516fd5a64698e` | 2026-10-29 |

Each digest is the image's only RepoDigest, so the id and the digest are the same.

The exact product versions, read from the products' APIs:

- **Elasticsearch 8.19.25** (build `104cb865…`) with **Kibana 8.19.25**, Basic licence. Security was on, HTTP without TLS, and `xpack.encryptedSavedObjects.encryptionKey` was set.
- **Elasticsearch 9.5.6** (build `fd1e8011…`) with **Kibana 9.5.6**, Basic licence.
- **Graylog 6.3.15+3ad654f**, with **OpenSearch 2.19.7** (security plugin off) and **MongoDB 7.0.48**.
- **Splunk Enterprise 10.6.1.1** (build `b2ae2962645c`), Trial licence, no Enterprise Security.
- **Falco 0.45.2**, with the bundled `falco_rules.yaml` and the container plugin.

The API credentials were:

- Elastic: an API key granted to a user whose role has `siemV2:all` on 8.19, or `siemV5`, `securitySolutionRulesV4` and `securitySolutionAlertsV1` on 9.5, plus index privileges on `smoke-*` and the alert indices.
- Graylog: the access token of a dedicated `Admin` user. The input was GELF UDP.
- Splunk: a JWT token for `admin`.

Seed data:

- Elastic: ECS process events in `smoke-endpoint`.
- Graylog: GELF messages, routed to a custom stream `endpoint`.
- Splunk: JSON events in `index=smoke sourcetype=smoke:process`.
## Coverage matrix

Each cell is **pass**, **fail** (with its finding, linked to its issue), **needs tenant**, or **not run** (with the reason). Each area's matrix appears in full below.

| Area | Scope | Pass | Fail | Needs tenant | Not run | Findings |
|---|---|---:|---:|---:|---:|---:|
| A | Install, new repository, CI generation, docs walk-through, contributor loop | 128 | 30 | 1 | 4 | 16 |
| B | Authoring and validation on 13 platforms, non-functional | 107 | 18 | 1 | 1 | 21 |
| C | MCP server, language server, editors, WASM | 172 | 25 | 3 | 4 | 17 |
| D | Build outputs, dry-run payloads, live paths without a tenant, SDKs | 118 | 32 | 16 | 1 | 17 |
| E | Phase 2: Elastic 8.19/9.5, Graylog 6.3, Splunk 10.6, Falco | 39 | 10 | 5 | 1 | 21 |
| | **Total** | **564** | **115** | **26** | **11** | **92** |

### Area A: Install, new repository, CI generation, docs walk-through, contributor loop

Cells: pass / fail (bug id) / needs tenant / not run (reason).

#### 1.1 Install and version

| Item | Result |
|---|---|
| Clean venv + `pip install <wheel>` (no Python dependencies pulled, `Requires:` empty) | pass |
| `opentide --version`, `-V`, `--json --version`, `python -m opentide --version` | pass (the version itself: fail [A1](https://github.com/opentidehq/opentide/issues/1623)) |
| `opentide --version extra` (extra argument silently ignored, exit 0) | pass (note N6) |
| `opentide info`: 13 platforms, capabilities match AGENTS.md table (validate missing for crowdstrike, harfanglab, sysdig, bitdefender; query missing for sysdig, bitdefender) | pass |
| `opentide --json info`: one JSON document, `platforms[].can_deploy/can_validate/can_query` match the registry | pass |
| `opentide doctor` outside a workspace (exit 1, `workspace` fail, fixes printed) | pass |
| `opentide --json doctor` outside / inside a workspace (one document; exit 1 / 0) | pass |
| doctor `opentide_latest` (reads pypi.org) | fail ([A1](https://github.com/opentidehq/opentide/issues/1623): "opentide 0.28.1 is available; 0.12.0 is installed") |
| doctor `proxy` check: good proxy, `--proxy notaurl`, `OPENTIDE_PROXY=ftp://x`, `--proxy http://127.0.0.1:9` | pass |
| doctor `credentials` check (tenant with `$VAR` setup values unset) | pass |
| Release binary vs wheel: `--help`, `--json commands` (sorted, minus duration), `info`, `--json info`, `commands`, `validate`, `--json validate`, `explain`, `--json doctor`, `setup ci github --plan`, `deploy --dry-run`, `explain nope` | pass (identical except timings) |
| PyPI summary / package metadata | fail ([A15](https://github.com/opentidehq/opentide/issues/1671)) |
| Version 0.12.0 vs docs' "current" 0.28.1 / CHANGELOG "1.0.0rc1" | fail ([A1](https://github.com/opentidehq/opentide/issues/1623)) |
| Wheel on Ubuntu 22.04 (act-22.04 image) | not run as a product test: the smoke wheel is a local manylinux_2_39 build; release CI builds manylinux_2_28 |

#### 1.2 Global options (docs/cli/global-options.md), commands, explain

| Item | Result |
|---|---|
| `--repo` before the command | pass |
| `--repo` after the command (usage error, exit 2, as documented) | pass |
| `--repo /nonexist` (human and `--json`: exit 2, `usage_invalid_value`) | pass |
| `OPENTIDE_REPO_ROOT` valid | pass |
| `OPENTIDE_REPO_ROOT` nonexistent | fail ([A10](https://github.com/opentidehq/opentide/issues/1659)) |
| `--json` before / after the command; stdout is one document | pass |
| `OPENTIDE_OUTPUT=json`, `OPENTIDE_JSON_INDENT=2`, `OPENTIDE_LOG_JSON=1` | pass |
| `--no-color` before/after, `NO_COLOR`, `FORCE_COLOR=1` (outside agent mode) | pass |
| Plain text "never wrapped" when redirected (global-options.md "Output") | fail ([A13](https://github.com/opentidehq/opentide/issues/1665)) |
| `--debug`, `OPENTIDE_DEBUG=1`, `DEBUG=1`; `DEBUG='*'` ignored | pass |
| `--quiet`; `--quiet --verbose` (exit 2) | pass |
| `--data` / `OPENTIDE_DATA_ROOT` | fail ([A9](https://github.com/opentidehq/opentide/issues/1659)) |
| `--proxy` / `OPENTIDE_PROXY` | pass (via doctor; `info` ignores a malformed proxy since it makes no call) |
| `--show-completion bash/zsh/fish/powershell/pwsh`; `tcsh` (exit 2 with list) | pass |
| `--install-completion` (bash, sandboxed HOME): writes `~/.bash_completions/opentide.sh`, sources it from `.bashrc`; completion of `setup p` and `--platform` values works | pass |
| `opentide commands` (58 commands, grouped) | pass |
| `opentide --json commands`: `global_options`, `environment`, every command has an `example`; keys as docs/cli/commands.md | pass (illustrative `"version": "0.18.0"` in the doc, note N7) |
| `opentide commands --bogus` / `commands extra` (exit 2) | pass |
| Unknown command `nosuchcmd` (exit 2, `usage_unknown_command`); typo `valdate` suggests `validate` | pass |
| `opentide explain <code>` (filename_slug, usage_invalid_value, invalid_ref) | pass |
| `opentide explain` (lists 467 codes) | pass |
| `opentide explain no_such_code_xyz` (exit 2, `usage_invalid_choice`, human + `--json`); `filename_mismatc` suggests `filename_mismatch` | pass |

#### 1.3 New repository from zero (repository-setup.md, quickstart.md "New repository from scratch", cli/setup.md)

| Item | Result |
|---|---|
| quickstart "New repository from scratch" block, literally (setup --yes, setup platforms, setup mcp --cursor, setup skills --generic, generate, validate) | pass (validate passes on an empty repo; `--strict` fails with "no detection objects", as documented) |
| repository-setup "Scripted onboarding" one-shot (`--path --name --org --description --platform x2 --ci github`) | pass (output wrapping: [A13](https://github.com/opentidehq/opentide/issues/1665)) |
| repository-setup step-by-step block (platforms, ci, env, hooks, mcp, skills) | pass |
| `setup repo` | pass |
| `setup platforms` with all 13 flags at once (13 TOML files; `info` shows all enabled) | pass |
| `setup platforms` failure paths: no flag (exit 2), `--nope` (exit 2), `setup --platform nope` (exit 2 with the 13 choices) | pass |
| `setup platforms` on an existing, user-edited TOML (left unchanged; a broken TOML is reported with line/column) | pass |
| `setup ci github/gitlab/azure` | pass (content bugs: [A1](https://github.com/opentidehq/opentide/issues/1623)-[A6](https://github.com/opentidehq/opentide/issues/1656), [A11](https://github.com/opentidehq/opentide/issues/1656)) |
| `setup ci` failure paths: missing provider, `jenkins`, `--default-branch "my branch"`/`"2024"`, `--promotion-target NOPE` (exit 2) | pass |
| `setup ci --python-version` validation | fail ([A11](https://github.com/opentidehq/opentide/issues/1656)) |
| `setup ci` re-run on a user-edited pipeline | fail ([A5](https://github.com/opentidehq/opentide/issues/1656)) |
| `setup env` (writes `.env.example` with `OPENTIDE_REPO_ROOT`, ignores `.env`); re-run keeps user lines | pass |
| `setup env --path ./nonexist` (creates the folder) | pass |
| `setup hooks` (in git: installs `.git/hooks/pre-commit`; outside git: warns, writes files); `--no-install` | pass |
| `setup mcp --vscode --cursor --claude-code --generic` (4 files, contents as documented) | pass |
| `setup mcp` re-run on an edited `.cursor/mcp.json` (merges, keeps other servers and custom args, warns) | pass |
| `setup mcp` with no host (exit 2) | pass |
| MCP server written by setup starts: `initialize` + `tools/list` (10 tools) over stdio | pass |
| `setup vscode` (deprecation warning, `.vscode/extensions.json`, snippets); `--mcp` | pass |
| `setup vscode --snippets --no-generate` with no templates (exit 1, as documented) | pass |
| `setup skills --generic/--cursor/--claude-code/--github-copilot` | pass (catalogue copy of `detection-engineering` not downloadable here: api.github.com answers 403 in the sandbox, packaged fallback with a warning, as documented) |
| `setup skills --plugin` (`.claude/settings.json` marketplace + enabled plugin) | pass |
| `setup skills discover` (37 skills, from raw.githubusercontent.com manifest), `--query kql`, `--installed`, `--json` | pass |
| `setup skills show <slug>`; `show nope-skill` (exit 1) | pass |
| `setup skills --install mitre-attack`, `--all` (full trees) | not run to completion: tree listing needs api.github.com (403 in this sandbox); failure is clean, exit 1, `command_failed` |
| `setup skills --install no-such-skill` (exit 2); no target (exit 2) | pass |
| `setup --yes` re-run over an existing repo: README, `.gitignore`, `.env.example`, `.pre-commit-config.yaml` kept (warning for README) | pass |
| `setup` interactive wizard at a terminal (starts, prompts; Ctrl-C exits 130) | pass |
| `setup` under a coding agent / `--json` without `--yes` (exit 2, `usage_needs_input`) | pass |
| `setup --yes --path <existing file>` (exit 1) | pass (raw "File exists (os error 17)", note N5) |
| `setup --plan` (JSON) lists exactly the files a real run writes | pass |
| `setup --sharing` without `--ci` (warning, ignored) | pass |
| Documented layout (repository-setup.md "Expected layout") vs actual | fail ([A14](https://github.com/opentidehq/opentide/issues/1671): `.opentide/states/` not created, `inflight/`, `lsp/`, hook files missing from the tree) |
| README written by setup: quick-start commands run | fail ([A12](https://github.com/opentidehq/opentide/issues/1656)) |
| CrowdStrike platform template credentials | fail ([A16](https://github.com/opentidehq/opentide/issues/1655)) |

What `setup` downloads: `setup skills` reads `https://raw.githubusercontent.com/opentidehq/skills/main/manifest.json`
and skill files, and `https://api.github.com/repos/opentidehq/skills/git/trees/main?recursive=1` for full trees.
`doctor` reads pypi.org (`opentide_latest`). Nothing else contacted the network.

#### 1.4 CI generation (`setup ci --help`: github, gitlab, azure)

All variants generated from a repo with all 13 platforms enabled (`/home/user/smoke/a/ci/<variant>/`).

| Variant | Generate | Lint | Every `opentide ...` command/flag exists | Install step works with this build |
|---|---|---|---|---|
| github default | pass | pass (actionlint + shellcheck: 0 findings) | pass | fail ([A1](https://github.com/opentidehq/opentide/issues/1623)) |
| github `--sharing` | pass | pass | pass | fail ([A1](https://github.com/opentidehq/opentide/issues/1623)) |
| github `--no-staging --no-inflight --lint-changed --explorer-pages --no-promotion --python-version 3.13` | pass | pass | pass | fail ([A1](https://github.com/opentidehq/opentide/issues/1623), [A6](https://github.com/opentidehq/opentide/issues/1656)) |
| github `--promotion-target ACCEPTANCE --default-branch development` | pass | pass | pass | fail ([A1](https://github.com/opentidehq/opentide/issues/1623)) |
| gitlab default | pass | pass (glint 0 findings, gitlab-ci-verify --no-lint-api rc 0; glint context comparison MR / main / feature branch sane) | fail ([A2](https://github.com/opentidehq/opentide/issues/1656): `python -m opentide.ci.codequality`) | fail ([A1](https://github.com/opentidehq/opentide/issues/1623)) |
| gitlab `--sharing --lint-changed --explorer-pages` | pass (explorer: "not written for gitlab" warning) | pass | fail ([A2](https://github.com/opentidehq/opentide/issues/1656)) | fail ([A1](https://github.com/opentidehq/opentide/issues/1623)) |
| gitlab `--no-staging --no-inflight --default-branch dev` | pass (warns `--default-branch` ignored) | pass | fail ([A2](https://github.com/opentidehq/opentide/issues/1656)) | fail ([A1](https://github.com/opentidehq/opentide/issues/1623)) |
| azure default | pass | pass (YAML parses; stages Validate/Generate/Deploy/Document; manual review) | pass | fail ([A1](https://github.com/opentidehq/opentide/issues/1623), [A3](https://github.com/opentidehq/opentide/issues/1655)) |
| azure `--sharing --lint-changed --explorer-pages` | pass (explorer: "not written for azure") | pass (adds Share stage) | pass | fail ([A1](https://github.com/opentidehq/opentide/issues/1623), [A3](https://github.com/opentidehq/opentide/issues/1655)) |
| azure `--no-staging --no-inflight --default-branch development` | pass | pass | pass | fail ([A1](https://github.com/opentidehq/opentide/issues/1623), [A3](https://github.com/opentidehq/opentide/issues/1655)) |
| github with `--python-version 'abc"; x'` / `2.7` | fail ([A11](https://github.com/opentidehq/opentide/issues/1656)) | fail ([A11](https://github.com/opentidehq/opentide/issues/1656): actionlint syntax-check) | n/a | n/a |
| gitlab with `--python-version $'3.12\nevil: true'` | fail ([A11](https://github.com/opentidehq/opentide/issues/1656): key injected) | n/a | n/a | n/a |
| Live query jobs: one per platform with a tenant check (9: sentinel, defender_for_endpoint, splunk, sentinel_one, carbon_black_cloud, elastic, graylog, exabeam, google_secops), none for crowdstrike, harfanglab, sysdig, bitdefender | pass | | | |
| Live query job guards: skips without a default-branch tenant; with a tenant, exits 2 naming unset variables | pass | | | |
| Default branch from `git init -b trunk` | pass | | | |

Commands found in the pipelines and checked: `validate --strict [--format sarif|codequality --output ...]`,
`lint --strict [--changed] --format sarif|codequality --output ...`, `validate query --platform <p> --live --changed`,
`generate`, `generate docs --output docs`, `generate inflight`, `generate inflight prune`,
`deploy --dry-run --strategy PREVIEW|RELEASE`, `deploy --strategy PREVIEW|RELEASE --skip-unconfigured`,
`deploy replay-state <commit>`, `share push --changed`, `generate explorer` (explorer job). All exist.
Install pin: every job runs `pip install "opentide==$OPENTIDE_VERSION"` with `OPENTIDE_VERSION: "0.12.0"` ([A1](https://github.com/opentidehq/opentide/issues/1623)).

#### 1.5 Hooks

| Item | Result |
|---|---|
| `setup --hooks` in a git repo: `.pre-commit-config.yaml`, `.opentide/hooks/pre-commit`, `.git/hooks/pre-commit` | pass |
| Native hook: broken KQL (`wher`) blocks the commit with the diagnostic | pass |
| Native hook: invalid status (`config_enum_unknown`) blocks the commit | pass |
| Native hook: valid rule commits | pass |
| `OPENTIDE_SKIP_HOOKS=1` / pre-commit `SKIP=opentide-validate` bypass | pass |
| `pre-commit install` (migration mode, keeps the native hook as `.legacy`): invalid blocked, valid passes | pass |
| Broken content staged, fixed copy in the work tree | fail ([A8](https://github.com/opentidehq/opentide/issues/1670)) |

#### 1.6 Contributor loop

| Item | Result |
|---|---|
| `new threat` / `new objective --threat` / `new rule --platform sentinel --objective` (placeholders listed) | pass |
| `validate --file <new rule>`; `validate --strict`; `lint --strict` (placeholders: exit 1) | pass |
| Fill in rule, commit with hooks | pass |
| act (catthehacker act-24.04, local wheel substituted for the PyPI pin): `validate` job (validate, lint, live query step skips without tenant) | pass (upload-artifact step needs act's artifact server; removed) |
| act `generate` job | pass |
| act `deploy_staging` job (dry-run PREVIEW plan, then "Skipped deploy: no tenants", exit 0) | pass |
| act `deploy_production` job (push on main after a merge commit) | fail ([A4](https://github.com/opentidehq/opentide/issues/1653)) |
| act `document` job | pass |
| act `inflight_prune` job | pass |
| act `inflight_shards` job | not run under act (checkout of a local bare repo by path is rejected by actions/checkout); steps run by hand: pass |
| act `code_scanning` job | not run (needs GitHub code-scanning upload) |
| `validate --strict` fails the build on an error (exit 1, SARIF has 1 `kql_unknown_operator` error, `::error file=...` annotation printed); YAML syntax error exits 1 | pass |
| `deploy --dry-run --strategy PREVIEW` in the PR job; `--skip-unconfigured` exits 0 without tenants | pass |
| `validate query --live --changed` without a tenant (exit 1, `command_failed`, help names `[[tenants]]`) | pass |
| Diff base, PR with full history (merge commit, `GITHUB_BASE_REF`): only the PR's rule selected | pass |
| Diff base, PR with depth-1 checkout: "Could not find git ref origin/main" (exit 1) until the pipeline's own `git fetch --depth=1 origin main`, then pass | pass |
| Diff base, push on main after a merge (first parent): pass; depth-1 clone fails with "Could not find git commit <sha>" (documented: jobs fetch full history) | pass |
| Live deploy / live query to any tenant | needs tenant |

#### 1.7 Docs walk-through (installation.md, repository-setup.md, quickstart.md, tutorial.md)

| Item | Result |
|---|---|
| installation.md: install, verify block (`--version`, `validate`, `generate`, `--json info`, `info`) | pass (pin / "latest 0.28.1": [A1](https://github.com/opentidehq/opentide/issues/1623); stale text: [A14](https://github.com/opentidehq/opentide/issues/1671)) |
| repository-setup.md: wizard, scripted, step-by-step, scoped subcommands (incl. `setup skills --name --org`), MCP and skills tables | pass (layout and skill-count text: [A14](https://github.com/opentidehq/opentide/issues/1671)) |
| quickstart.md: install, generate, validate, validate query, info, coverage, dry-run deploy, generate docs | pass (wrong statements: [A14](https://github.com/opentidehq/opentide/issues/1671)) |
| tutorial.md top to bottom, literally (setup --path, generate, three YAML files from the page, validate, break/fix `detection_model`, info, coverage, `validate query`, dry-run deploy, `generate docs`) | pass |

#### 1.8 Other commands

| Item | Result |
|---|---|
| `rules` without subcommand (exit 2) | pass |
| `rules unreviewed` (default 90d), `--older-than 1d`, `--json --older-than 30d` | pass |
| `rules unreviewed --older-than banana` (exit 2) | pass |
| `share targets` / `preview` / `push` / `status` / `retract` / bare `share`, no target configured (targets: Skipped exit 0; others exit 1 with help) | pass |
| `share push --changed` outside CI (exit 1); `--target nope` (exit 2); `--since` without `--changed` (exit 2); `--type banana` (exit 2) | pass |
| `share` with a target at https://127.0.0.1:9: `targets`, `preview` (dry run plan), `validate --check sharing-config` | pass |
| `share push` without API key (exit 1); with fake key, unreachable (exit 2, `share_unreachable`, `connectivity_failed` per object) | pass |
| `share status` with nothing ever shared | fail ([A7](https://github.com/opentidehq/opentide/issues/1661)) |
| `share retract --type threat` unreachable (exit 2); `retract --delete` without `--yes` (exit 1) | pass |
| `sharing.toml` with `max_tlp = "purple"` (exit 1, `max_tlp_unknown`) | pass |
| `migrate` without subcommand (exit 2) | pass |
| `migrate vocab-scope` dry run (nothing to do; then 2 files, 1 ambiguous: exit 2) | pass |
| `migrate vocab-scope --field banana` (exit 1), `--field surface --apply`, `--apply` (exit 2 with ambiguity), `--apply --force` (exit 0) | pass |
| `deploy migrate-state`: gitignored state dir (exit 1, `deployment_state_ignored`) | pass |
| `deploy migrate-state`: mapping and `rule_id::<tenant>` ids moved to shards, unused Sentinel id dropped with warning, re-run "No vendor rule ids left", `--json` | pass |
| `deploy migrate-state`: plain scalar `rule_id: "12345"` (exit 1, `external_id_shape`) | pass (note N3) |
| `serve`: initialize, run validate twice (warm: 266 ms, then 6 ms), progress notifications, `explain nope` (exit 2), nested `serve` refused, bad params (-32602), parse error (-32700), unknown method (-32601), `--help` as run, shutdown + exit (rc 0), stdout protocol only, `commands_digest` = sha256 of `--json commands` | pass |

### Area B: Authoring and validation on 13 platforms, non-functional

Cells: **pass**, **fail (Bn)**, **needs tenant**, **not run (reason)**.

Totals: 127 rows — 107 pass, 18 fail, 1 needs tenant (every `--live` check against a real tenant; Bitdefender deploy included), 1 not run (no docs-provided older-model sample for `migrate`). Bugs: 21 ([B1](https://github.com/opentidehq/opentide/issues/1663)–[B19](https://github.com/opentidehq/opentide/issues/1663), [B21](https://github.com/opentidehq/opentide/issues/1660)–[B22](https://github.com/opentidehq/opentide/issues/1665); B20 unused): 0 blocker, 0 major, 18 minor, 3 docs.

#### 1a. Workspace and `new`

| Item | Result |
|------|--------|
| `setup --yes --path --name --org --description --platform sentinel --ci github` | pass ([B17](https://github.com/opentidehq/opentide/issues/1670): `--org` reaches only the README; [B11](https://github.com/opentidehq/opentide/issues/1665): wrapped output) |
| `setup platforms` with all 13 flags `--yes` | pass ([B11](https://github.com/opentidehq/opentide/issues/1665): output wraps) |
| `generate` (all 6 phases) | pass |
| `new threat --name` | pass |
| `new threat --path` (file, file without `.yaml`, folder, absolute) | pass |
| `new threat --path` into a subfolder of `objects/threats` / outside `objects/` | fail ([B7](https://github.com/opentidehq/opentide/issues/1670)) |
| `new objective --name --threat` | pass |
| `new rule --name --platform` x13 (one rule with all 13 blocks) | pass (validates as written; 31 placeholders) |
| `new rule --objective` | pass (a signal UUID is refused, note N6) |
| `new` interactive prompts (threat name; rule name + platform multi-select; Ctrl-C exits 130) | pass |
| `new` failure: bad `--platform` (exit 2, "a similar value exists: 'splunk'") | pass |
| `new` failure: existing file (`path_exists`, exit 1, JSON) | pass |
| `new` failure: malformed UUID `usage_invalid_value` (2), unknown UUID (2) | pass |
| `new` failure: no `--name` non-interactive / `--json` (`usage_needs_input`, 2) | pass |
| `new` failure: `--name ""` / empty answer at the prompt | fail ([B8](https://github.com/opentidehq/opentide/issues/1670)) |
| `new` failure: outside a workspace (`workspace_not_found`, 1) | pass |
| `new` failure: unwritable path (`path_not_writable`, 1) | pass |
| `new` failure: invalid `lint.toml` (exit 2 before writing) | pass |
| `new` names: slug, `CON` → `_con.yaml`, collision `-{uuid8}`, `???` → `object.yaml`, `style = "name"` | pass |
| `new rule --platform splunk` in a workspace without splunk enabled (warns, validate warns `platform_not_enabled`) | pass |
| `docs/usage/tutorial.md` followed literally (setup, generate, three objects, validate, dangling ref, coverage, validate query, deploy dry run, generate docs) | pass for behaviour; fail ([B14](https://github.com/opentidehq/opentide/issues/1671)) for its sample outputs |
| `docs/usage/repository-setup.md` scripted onboarding | pass ([B17](https://github.com/opentidehq/opentide/issues/1670): README platform list) |

#### 1b. A realistic rule per platform and language (`new` → edited → `validate --strict` + `lint --strict` clean)

| Platform | Language / rule type | Rule file (`ws/objects/rules/`) | Result |
|----------|----------------------|------------|--------|
| sentinel | KQL (SecurityEvent 4656, entities, grouping) | `sentinel-lsass-handle-access.yaml` | pass |
| defender_for_endpoint | KQL (DeviceProcessEvents) | `defender-procdump-against-lsass.yaml` | pass ([B2](https://github.com/opentidehq/opentide/issues/1663): any `alert.category` accepted) |
| splunk | SPL (Sysmon EID 1, `index= sourcetype=`) | `splunk-encoded-powershell.yaml` | pass |
| sentinel_one | single event (S1QL/PowerQuery) | `sentinelone-shadow-copy-deletion.yaml` | pass (no offline engine, by design) |
| sentinel_one | correlation (sub_queries) | `sentinelone-discovery-burst-correlation.yaml` | pass |
| crowdstrike | CQL correlation rule | `crowdstrike-rare-lolbin-network-connection.yaml` | pass ([B2](https://github.com/opentidehq/opentide/issues/1663): `trigger`/`outcome` unchecked) |
| harfanglab | Sigma | `harfanglab-sigma-certutil-download.yaml` | pass ([B2](https://github.com/opentidehq/opentide/issues/1663): condition/modifiers unchecked) |
| harfanglab | YARA signature | `harfanglab-yara-mimikatz-strings.yaml` | pass |
| harfanglab | YARA decomposed (meta/strings/condition/imports) | `harfanglab-yara-decomposed-cobalt-strike.yaml` | pass ([B4](https://github.com/opentidehq/opentide/issues/1663): position in `validate query --json`) |
| carbon_black_cloud | Lucene (CBC dialect) | `carbon-black-office-spawning-script-host.yaml` | pass |
| elastic | Kibana KQL (`type: query`, `language: kuery`, risk mapping) | `elastic-kuery-whoami-execution.yaml` | pass |
| elastic | Lucene (`type: query`, `language: lucene`) | `elastic-lucene-net-user-add.yaml` | pass |
| elastic | EQL sequence | `elastic-eql-office-child-then-network.yaml` | pass |
| elastic | ES\|QL | `elastic-esql-many-failed-logons.yaml` | pass |
| elastic | threshold | `elastic-threshold-rdp-brute-force.yaml` | pass |
| elastic | new_terms | `elastic-new-terms-rare-parent.yaml` | pass ([B3](https://github.com/opentidehq/opentide/issues/1663): opaque error for a wrong `history_window_start`) |
| elastic | threat_match (query + threat.query) | `elastic-threat-match-bad-ip.yaml` | pass |
| elastic | machine_learning | `elastic-ml-rare-process.yaml` | pass |
| sysdig | Falco condition + output | `sysdig-shell-in-container.yaml` | pass |
| bitdefender | detection criteria | `bitdefender-rundll32-no-arguments.yaml` | pass ([B5](https://github.com/opentidehq/opentide/issues/1663): span) — deploy: needs tenant |
| bitdefender | YARA | `bitdefender-yara-webshell.yaml` | pass — deploy: needs tenant |
| graylog | filter (Lucene, Graylog dialect) | `graylog-ssh-root-login-filter.yaml` | pass |
| graylog | aggregation | `graylog-failed-logins-aggregation.yaml` | pass |
| exabeam | one sequence | `exabeam-failed-logins-from-outside.yaml` | pass |
| exabeam | two sequences + correlation | `exabeam-spray-then-success.yaml` | pass |
| google_secops | YARA-L 2.0 (events/match/outcome/condition) | `google-secops-brute-force-then-success.yaml` | pass |
| all 13 | `--live` checks of these rules | needs tenant (unconfigured tenants fail cleanly: see 1c) |

Friction from `new`'s template to a valid rule: low. Placeholders are listed by `new` and by
`lint`; the commented template lists every key. Real stumbles: Elastic `history_window_start: now-14d`
([B3](https://github.com/opentidehq/opentide/issues/1663), opaque); Graylog `NOT source_ip:10.0.0.0/8` (clear Lucene message, must quote); Graylog
`priority: 3` (clear: must be a word); EQL `maxspan` > lookback, a risk score outside the band and
Falco's deprecated `evt.dir` (clear lint warnings). The template's threat `#chaining: - key:` gives
no hint of the real keys ([B15](https://github.com/opentidehq/opentide/issues/1663)).

#### 1c. `validate`

| Item | Result |
|------|--------|
| `validate` whole workspace (28 objects, 24 queries) | pass |
| `--check` each of `id-uniqueness`, `uuid-format`, `schema`, `configuration`, `queries`, `sharing-config` (pass + failure each) | pass |
| `--check cve` against 127.0.0.1:9 (warning, `--strict` exit 1, bad `timeout` exit 1) | pass |
| `duplicate_id`, `invalid_uuid` (non-hex, non-v4), `missing_uuid`, `invalid_ref`, `vocab_unknown` | pass |
| `metadata.created`/`modified` validation | fail ([B1](https://github.com/opentidehq/opentide/issues/1663)) |
| `metadata.schema` unknown / other type / wrong case / missing | pass ([B13](https://github.com/opentidehq/opentide/issues/1671): docs wrong) |
| `--strict` (warnings fail; empty workspace fails; `--allow-empty`; `--allow-empty` alone exit 2) | pass |
| `--file` (repo-relative, `./`, absolute, bare name, repeatable, unknown → `scope_no_match`) | pass |
| `--uuid` (match, unknown, malformed → `scope_no_match`, note N7) | pass |
| `--type threat --type objective`; `--type hunt` exit 2 | pass |
| `--queries warn` / `warn --strict` / `off`; conflicts with `--check` exit 2; bad value exit 2 | pass |
| `--fix`, `--fix --dry-run` (diff, `would_fix`), `--dry-run` alone exit 2; CRLF kept by `--fix` | pass |
| `--watch` (re-validates on save, Ctrl-C exits 0; refused with `--json`, `--fix`, agent/plain mode) | pass |
| `--format sarif` / `codequality` (stdout and `--output`; `--json` needs `--output`; text + `--output` exit 2; unwritable output exit 1) | pass |
| `--repo` from another directory | pass |
| `--json` purity: 31 invocations (success, usage errors, failures) — one document, one line, `exit_code`/`failure` consistent, nothing on stderr | pass |
| `--json` shape per `json-output.md` (envelope, `checks`, `report.issues`, `summary`) | pass |
| configuration findings (unknown key, missing field, enum) | pass ([B10](https://github.com/opentidehq/opentide/issues/1659): no line/column) |
| configuration TOML syntax error | fail ([B10](https://github.com/opentidehq/opentide/issues/1659)) |
| object placeholder queries | fail ([B6](https://github.com/opentidehq/opentide/issues/1671)) |
| validate a value a vendor rejects (CrowdStrike trigger/outcome, Sigma condition/modifier, Defender category) | fail ([B2](https://github.com/opentidehq/opentide/issues/1663)) |
| threat `chaining` keys / self-loop | fail ([B15](https://github.com/opentidehq/opentide/issues/1663)) |
| `platform_not_enabled` warning on a disabled platform | pass |
| sharing-config (`[misp]` vs `[[misp]]`, unknown key, bad `max_tlp`, literal API key redacted) | pass |

#### 1d. `validate query`

| Item | Result |
|------|--------|
| `--platform` sentinel, defender_for_endpoint, splunk, crowdstrike, harfanglab, carbon_black_cloud, elastic (8 queries), sysdig (2), bitdefender, graylog (2), exabeam (3), google_secops | pass (12/12 offline platforms) |
| `--platform sentinel_one` offline: exit 2, `usage_missing_option`, names `--live` | pass |
| `--file` per offline language: `.kql .spl .esql .eql .kuery .lucene .falco .cql .yar .yara .exabeam .yaral .yl2` (valid + invalid each, line/column checked) | pass |
| `--file` failure paths: missing file (2), non-UTF-8 (1), empty (1), wrong `--platform` for extension (2), `--live` with a file (2), upper-case extension | pass |
| bare `validate query` (all platforms) | pass |
| `--changed` (and with `--platform` → "Skipped"), `--uuid`, `--queries warn/off`, `--strict`, `validate --queries warn query` carry-over | pass |
| `--changed --file`, `--live` without `--platform`, `--queries` with `--live`, `--strategy`/`--wide`/`--check-timeout` offline → exit 2 | pass |
| `--live` crowdstrike / harfanglab / sysdig / bitdefender → `supported: false`, exit 1 | pass |
| `--live` sentinel / elastic / google_secops / splunk without tenants → clean failure exit 1 | pass (real tenants: needs tenant) |
| `queries[].line/column` in `--json` | fail ([B4](https://github.com/opentidehq/opentide/issues/1663), HarfangLab decomposed YARA) |

#### 1e. `lint`

| Item | Result |
|------|--------|
| default run (all five checks) on the scaffolded and on the finished workspace | pass |
| `--check filenames` (+ `--fix` rename), `metadata`, `recommended` (`--verbose` note), `placeholders`, `queries` | pass |
| `--strict` (exit 1 on findings), `--changed`, `--file`, unknown `--file` (1), `--changed --file` (2), `--changed` outside git (1) | pass |
| `--format sarif` / `codequality`, `--json --format sarif` without `--output` (2), `--json --strict` (`issues_found`) | pass |
| `lint.toml`: unknown field, unknown key, bad severity, unknown kind, bad regex, bad style → exit 2; `severity = "error"`; `style = "name"`; `[queries] enabled = false`; `pattern` | pass |
| `lint.toml` TOML syntax error | fail ([B10](https://github.com/opentidehq/opentide/issues/1659): exit 1 `command_failed`, no position) |
| `//` comment line in a folded `>-` KQL query | fail ([B16](https://github.com/opentidehq/opentide/issues/1660)) |

#### 1f. `explain`

| Item | Result |
|------|--------|
| `explain <code>` for every code met (≈80: all `validate`/`lint`/query-engine codes above, `failure.code`s, `config_parse`, `unknown_key`, `missing_field`, `cve_lookup_unavailable`, …) — each prints a page, exit 0 | pass |
| `explain` (list, 467 codes = `diagnostics.md` headings), `--json explain`, any case | pass |
| unknown code: exit 2, `usage_invalid_choice`, `failure.suggestion` | pass |
| suggestion quality (`kql_parse`) | fail ([B19](https://github.com/opentidehq/opentide/issues/1663)) |

#### 1g. Error placement (line AND column counted by hand)

| Item | Result |
|------|--------|
| KQL in `|`, `|-` deeper indent, `|2`, `>-`, `>`, plain multi-line, plain one line, double-quoted with escapes, double-quoted multi-line, single-quoted with `''`, comment line + unicode, tabs inside | pass (12/12) |
| KQL unclosed `(` followed by another pipe | fail ([B21](https://github.com/opentidehq/opentide/issues/1660)) |
| Defender KQL, SPL (`|` and `>-`), ES\|QL, EQL (`>-`), Kibana KQL, Lucene (Elastic, CBC, Graylog), Falco (`|` and `>-`), CQL, YARA (HarfangLab signature, decomposed strings, Bitdefender), Exabeam 2nd sequence, YARA-L events and condition | pass (17/17) |
| YAML syntax: unclosed flow, bad indent, unclosed quote | pass |
| YAML syntax: tab, duplicate key, unclosed `[` note | fail ([B9](https://github.com/opentidehq/opentide/issues/1663)) |
| schema type errors (`enabled: maybe`, scalar for a list, `version: 1.5`), unknown keys (top, block, nested), missing required field, bad technique, bad status, unknown platform key | pass |
| snippet framing (1 line of context, underline, help) | pass ([B5](https://github.com/opentidehq/opentide/issues/1663): one-character span; [B22](https://github.com/opentidehq/opentide/issues/1665): no truncation of long lines) |
| CRLF files: 31 placement cases give identical positions to LF | pass |
| paths with spaces (workspace dir, file name; SARIF URI `%20`-encoded) | pass |

#### 1h. `tui` (pty via pexpect + pyte)

| Item | Result |
|------|--------|
| opens on Catalogue (threat → objective → 26 rules), header counts | pass |
| keys 1–6 switch Catalogue/Coverage/Results/Visibility/Configuration/Chains; `v` runs validate into Results; `y` file view | pass |
| `q` exits 0; alt screen left, cursor shown, mouse off, `stty -g` identical before/after; Ctrl-C exits 0 and restores; resize to 5x10 and back | pass |
| failure: not a tty / `--json` (`usage_tui_needs_tty`, exit 2); `NO_COLOR`, `TERM=dumb`, `CI`, `--no-color` refused naming the cause; `NO_COLOR` + `OPENTIDE_OUTPUT=human` opens | pass |
| no workspace / empty workspace: opens with "No detection objects" (note N3) | pass |

#### 1i. `migrate`

| Item | Result |
|------|--------|
| `migrate vocab-scope` dry run, `--field surface`, `--force`, `--apply` (re-run idempotent), `--json` | pass |
| ambiguous value (`Account`) → exit 2; `--field bogus` → exit 1 | pass |
| hint from `validate` towards `migrate`; `migrate` outside a workspace | fail ([B18](https://github.com/opentidehq/opentide/issues/1659)) |
| an older-model sample from the docs | not run (the docs give none; built by hand from the `0.14.0` change described in `migrate.md`) |

#### 1j. Non-functional

| Item | Result |
|------|--------|
| startup: `--version` 21 ms (Python entry point; native binary 3.7 ms), `--help` 28 ms, `info` 32 ms, `explain` 25 ms (20 runs each) | pass |
| `validate` 28 objects 0.25 s; `lint` 0.19 s | pass |
| `validate` 312 rules: 0.30 s, 98 MB peak; `lint` 0.32 s, 96 MB; `validate query` 0.28 s, 78 MB | pass |
| `validate` 3,120 rules: 0.84 s, 141 MB; `lint` 0.91 s, 148 MB | pass |
| 21.7 MB YAML (validate 0.70 s, 191 MB) | pass |
| 1.16 MB one-line KQL query (0.84 s, 204 MB) | pass |
| 1 MB one-line Lucene query with an error | fail ([B22](https://github.com/opentidehq/opentide/issues/1665): 2 MB code frame) |
| 10k-deep query parens in all 11 offline languages (clean depth errors, ≤0.3 s, no crash) | pass ([B22](https://github.com/opentidehq/opentide/issues/1665): Lucene message quotes 19 KB) |
| 3,000-deep YAML block, 10k-deep flow sequence and flow map | pass (clean `yaml_parse`) |
| binary junk, Latin-1, UTF-16, NUL bytes, empty, whitespace-only, comment-only, top-level list/scalar, alias-heavy file | pass (clean `yaml_parse`/`missing_uuid`, no panic) |
| UTF-8 BOM | pass |
| whole bad workspace: `validate`, `--json validate`, `lint`, `--json lint`, `validate query`, `generate`, `info` — no panic, no backtrace, JSON parses | pass |
| CRLF positions; paths with spaces | pass |
| colour off at a terminal (`NO_COLOR`, `--no-color`, `FORCE_COLOR=0`) | fail ([B12](https://github.com/opentidehq/opentide/issues/1665)) |
| plain output never wraps | fail ([B11](https://github.com/opentidehq/opentide/issues/1665)) |

### Area C: MCP server, language server, editors, WASM

Cells: **pass**, **fail (Cn)**, **needs tenant**, **not run (reason)**.

#### 1a. MCP server (`opentide mcp start`, wheel and release binary)

| # | Item | Result |
|---|---|---|
| M1 | smoke-test.md section 5 `printf` pipeline, wheel: 3 lines, `serverInfo` opentide 0.12.0, 10 tools, `passed`/`kql` | pass |
| M2 | the same, release binary | pass |
| M3 | `initialize`: serverInfo, instructions (docs/mcp/index.md), capabilities | pass |
| M4 | `tools/list` vs docs/mcp/tools.md: 10 tools, names, parameters, required | pass |
| M5 | `resources/list` vs resources.md: 6 resources | pass |
| M6 | `resources/templates/list`: 6 templates, `{+name}` for vocabularies | pass |
| M7 | `prompts/list` | pass (empty list, though `prompts` is advertised: note N1) |
| M8 | `search` success: text, platform, UUID, technique, status filters | pass |
| M9 | `search` failure: missing `query`, `query` not a string (isError) | pass |
| M10 | `search` with an unknown `type` value | fail ([C9](https://github.com/opentidehq/opentide/issues/1667)) |
| M11 | `get_chaining` success (incl. upper-case, padded UUID) and failure (unknown, missing) | pass |
| M12 | `coverage` success (all, technique, tactic) and failure (unknown technique, wrong type) | pass |
| M13 | `validate_rule` success (valid, valid with warning) and failure (unknown, missing) | pass |
| M14 | `validation_report` success: whole catalogue, `file`, bare file name, `uuid`, `object_type` + `queries` | pass |
| M15 | `validation_report` failure: bad `queries`, bad `object_type`, `../` traversal, absolute path outside, missing file | pass |
| M16 | `validation_report` after editing files on disk: fresh reads, `fix` edits, `next_actions`, new file, broken YAML | pass |
| M17 | `explain` success (Tide code, engine code, list) and failure (typo gets a suggestion, wrong type) | pass |
| M18 | `validate_query` failure inputs: unknown platform, bad `language`, `language` on a non-Elastic platform, missing `query`, bad `live`, 5 MB query (0.3 s), 100k-deep nesting, non-ASCII | pass |
| M19 | `validate_query` with an unknown `stack` | fail ([C9](https://github.com/opentidehq/opentide/issues/1667)) |
| M20 | `validate_query` live payload shape | fail ([C7](https://github.com/opentidehq/opentide/issues/1667)) |
| M21 | `run_query` without `live`: refuses, contacts nothing | pass |
| M22 | `run_query` failure: unknown tenant, unknown platform, bad `limit`, `limit` 99999, bad `since`; `rule` source | pass |
| M23 | `deploy_rule` dry run for a platform the rule has no block for | fail ([C16](https://github.com/opentidehq/opentide/issues/1667)) |
| M24 | `deploy_rule` failure: unknown platform, unknown UUID, missing platform | pass |
| M25 | `deployment_status` success (state file, no state) and failure (unknown, missing) | pass |
| M26 | unknown tool name (isError) | pass |
| M27 | errors as data: 149 calls, no crash, server alive after each | pass |
| M28 | stdout carries only JSON-RPC lines (also with `--debug`); logs on stderr | pass |
| M29 | request before `initialize` | pass (refused with -32602; the message is obscure: see [C8](https://github.com/opentidehq/opentide/issues/1667)) |
| M30 | a line that is not JSON | fail ([C8](https://github.com/opentidehq/opentide/issues/1667)) |
| M31 | `tools/call` or `resources/read` without `params` | fail ([C8](https://github.com/opentidehq/opentide/issues/1667)) |
| M32 | unknown method (-32601), batch (-32600), `ping`, empty line | pass |
| M33 | shutdown on stdin EOF: exit 0, an in-flight call still answered | pass |
| M34 | SIGTERM idle and busy (exit by the signal, no orphan process); SIGINT exit 130 | pass |
| M35 | started in an empty folder, or `OPENTIDE_REPO_ROOT` naming a missing folder | fail ([C1](https://github.com/opentidehq/opentide/issues/1659)) |
| M36 | started in an Agent Plugin root: catalogue tools refused with `workspace_not_found`; `CLAUDE_PROJECT_DIR` picks the workspace | pass |
| M37 | nothing contacted: no-network namespace, fake credentials fail on DNS per tenant | pass |
| M38 | `resources/read` of `index`, `rules`, `threats`, `objectives`, `vocabularies`, `platforms` | pass |
| M39 | `rules/{uuid}`, `threats/{uuid}`, `objectives/{uuid}`: hit and miss (`error` field) | pass |
| M40 | `schemas/{object_type}`: before `opentide generate` an error with a hint; after, `rule`, `rule::1.0`, `rule.1.1`, `threat`, `objective`; bogus type an error | pass |
| M41 | `templates/{object_type}` | fail ([C3](https://github.com/opentidehq/opentide/issues/1667)) |
| M42 | `vocabularies/{+name}`: `tlp`, `att&ck`, `actors`, unknown | pass |
| M43 | unknown URIs (`opentide://nosuch`, `file:///etc/passwd`, `opentide://rules/../../etc/passwd`): -32602 | pass |
| M44 | `opentide setup mcp --vscode --cursor --claude-code --generic --yes`: each written config, run as written, starts a server that answers `search` | pass |
| M45 | `setup mcp --plan` writes nothing; merging keeps other servers in an existing file | pass |
| M46 | `setup mcp` when `opentide` is not on `PATH` | fail ([C6](https://github.com/opentidehq/opentide/issues/1670)) |
| M47 | `opentide doctor`: `mcp_config` check | pass |
| M48 | `opentide mcp` (rc 2, `usage_error`, `--json`, help at a TTY), `mcp stop`, `mcp start --bogus` (rc 2) | pass |
| M49 | smoke-test.md section 5, second checkbox: an MCP host's model calls the tools | not run (needs an interactive MCP host with a model; the scripted client made the same calls) |
| M50 | `validate_query` with `live: true` against a real tenant | needs tenant |
| M51 | `run_query` with `live: true` against a real tenant | needs tenant |
| M52 | `deploy_rule` with `dry_run: false` against a real tenant | needs tenant |

#### 1b. MCP, platform x step

`validate_query` offline: one valid and one broken query each (Elastic: ES\|QL, EQL, Kibana KQL and Lucene). Live columns: no credentials, no network.

| Platform | `validate_query` offline | `validate_query` live | `run_query` live | `deploy_rule` dry run | `deploy_rule` dry_run false |
|---|---|---|---|---|---|
| sentinel | pass | pass | pass | pass | fail ([C2](https://github.com/opentidehq/opentide/issues/1667)) |
| defender_for_endpoint | pass | pass | pass | pass | pass |
| splunk | pass | pass | pass | pass | fail ([C2](https://github.com/opentidehq/opentide/issues/1667)) |
| sentinel_one | pass (refuses offline and names `live: true`, as documented) | pass | pass | pass | fail ([C2](https://github.com/opentidehq/opentide/issues/1667)) |
| crowdstrike | pass | pass (`supported: false`) | pass | pass | pass |
| harfanglab | pass | pass (`supported: false`) | pass | pass | fail ([C2](https://github.com/opentidehq/opentide/issues/1667)) |
| carbon_black_cloud | pass | pass | pass | pass | fail ([C2](https://github.com/opentidehq/opentide/issues/1667)) |
| elastic | pass | pass | pass | pass | fail ([C2](https://github.com/opentidehq/opentide/issues/1667)) |
| sysdig | pass | pass (`supported: false`) | pass (`supported: false`) | pass | fail ([C2](https://github.com/opentidehq/opentide/issues/1667)) |
| bitdefender | pass | pass (`supported: false`) | pass (`supported: false`) | pass | pass (no tenant configured; refused) |
| graylog | pass | pass (no tenant: names the file) | pass | pass | pass |
| exabeam | pass | pass (no tenant) | pass | pass | pass |
| google_secops | pass | pass (no tenant) | pass | pass | pass |

"pass" in the live columns means it failed cleanly, as data, naming the unset variable or the missing tenant, and contacted nothing.

#### 1c. Language server (`opentide lsp start` and `opentide-lsp --stdio`)

| # | Item | Result |
|---|---|---|
| L1 | `initialize`: serverInfo `opentide-lsp` 0.12.0, `positionEncoding` utf-16, incremental sync, trigger characters, `experimental.opentide` (`host` null from the binary, as documented) | pass |
| L2 | language-id aliases `kusto`, `kibana-kql`, `yara-l`, `logscale`; `sql` gets nothing | pass |
| L3 | all 30 Tide objects opened: object diagnostics (`metadata_recommended`, `filename_mismatch`, `bitdefender_severity_collapsed`) | pass |
| L4 | UTF-16 positions with `é𝄞` (a surrogate pair) before the error, every language (table 1d) | pass |
| L5 | hover: KQL table, column, operator; Tide vocabulary value; Tide key; past the end of the file; unopened file | pass (note N4) |
| L6 | completion: Tide keys, KQL after `\|` and in a `.kql` file, SPL after `\| `, `\| w` | pass |
| L7 | completion triggered by the space after `\| ` in a query inside a rule | fail ([C5](https://github.com/opentidehq/opentide/issues/1668)) |
| L8 | `completionItem/resolve` | pass |
| L9 | semantic tokens full: rules and the 13 query files, every token in bounds; YARA-L in `rule-google-secops-process-1.0.yaml` checked token by token | pass |
| L10 | semantic tokens range | pass (not advertised; -32601, consistent) |
| L11 | code actions: quick fix from a suggestion, with and without `context.diagnostics`; `source.fixAll.opentide` | pass |
| L12 | documentSymbol, foldingRange, documentLink, codeLens, formatting, inlayHint, workspace/symbol, definition, references, signatureHelp, documentHighlight, selectionRange | pass |
| L13 | YARA: prepareRename, rename, refused rename, formatting, definition | pass |
| L14 | pull diagnostics: `diagnosticProvider`, `textDocument/diagnostic`, `unchanged` by `previousResultId`, `workspace/diagnostic` | pass |
| L15 | `initializationOptions.workspace` and `opentide/didChangeWorkspace` (the `invalid_ref` goes once the object is supplied) | pass |
| L16 | `opentide/analyze` | fail ([C10](https://github.com/opentidehq/opentide/issues/1668)) |
| L17 | `opentide/highlight` (default KQL, YARA-L) | pass |
| L18 | `opentide/compiledKql` (with and without `tenant`), `opentide/compiledSpl` | pass |
| L19 | `opentide/fs/read`: absolute path; outside, traversal, missing give `""` | fail ([C10](https://github.com/opentidehq/opentide/issues/1668): a workspace-relative path gives `""`) |
| L20 | `opentide/catalog` (`root` and `null`) | pass |
| L21 | `opentide/catalogChanged` notification | not run (needs a catalog change after the client fetched it; not triggered) |
| L22 | unknown `opentide/*` method; debug-only `opentide/__panic` absent in release | pass |
| L23 | `.opentide/configurations/platforms/splunk.toml`: clean, wrong type, missing key, unknown key and table, TOML syntax error | pass |
| L24 | `deployment.toml`, `sharing.toml`, `visibility.toml`; `resources.toml` (no model, no findings); a `.toml` outside `configurations/` (ignored) | pass |
| L25 | TOML hover and completion; no semantic tokens for TOML (documented) | pass |
| L26 | `shutdown` + `exit`: exit 0; a request after `shutdown` refused | pass |
| L27 | `exit` without `shutdown`, stdin EOF: exit 1; SIGINT 130 (wheel); SIGTERM | pass |
| L28 | request before `initialize` (-32002); `didOpen` before it dropped; second `initialize` refused | pass |
| L29 | malformed JSON-RPC: bad body (-32700), batch array, `id: null`, broken header, truncated frame | pass |
| L30 | unknown method (-32601), unknown notification ignored, bad params (-32602) | pass |
| L31 | huge documents: 5 MB `.kql` (1.8 s), 1.5 MB rule (0.6 s, 250k tokens), 100k-deep nesting (`nesting deeper than 256 levels`) | pass |
| L32 | `$/cancelRequest` | pass |
| L33 | stdout carries frames only | pass |
| L34 | `opentide lsp` (rc 2), `lsp start --bogus` (rc 2), the message at a TTY, `--stdio` accepted | pass |
| L35 | `opentide-lsp --version`, `--version --json`, no arguments (rc 2), `--help` | pass |
| L36 | wheel and binary give the same answers | pass |
| L37 | catalog cached under the user cache directory / `OPENTIDE_CACHE_DIR`, as documented | fail ([C17](https://github.com/opentidehq/opentide/issues/1671)) |
| L38 | docs/cli/lsp.md and docs/usage/migration/language-server.md vs the server | fail ([C15](https://github.com/opentidehq/opentide/issues/1671)) |

#### 1d. Language server, language x step

Standalone: a query file of that extension with `é𝄞` before the error. Embedded: the rule's query broken by an incremental `didChange`, the diagnostic at the right UTF-16 position, cleared on revert.

| Language | Standalone file | Embedded in a rule | Semantic tokens |
|---|---|---|---|
| KQL (`.kql`; sentinel, defender_for_endpoint) | pass | pass | pass |
| SPL (`.spl`) | pass | pass | pass |
| ES\|QL (`.esql`) | pass | pass | pass |
| EQL (`.eql`) | pass (note N5) | pass | pass |
| Kibana KQL (`.kuery`) | pass | pass | pass |
| Lucene (`.lucene`; carbon_black_cloud, graylog) | pass | pass | pass |
| Falco (`.falco`; sysdig) | pass | pass | pass |
| CQL (`.cql`; crowdstrike) | pass | pass | pass |
| YARA (`.yar`, `.yara`; harfanglab, bitdefender) | pass | pass | pass |
| Exabeam (`.exabeam`) | pass | pass | pass |
| YARA-L (`.yaral`, `.yl2`; google_secops) | pass | pass | pass |

#### 1e. Editors

| # | Item | Result |
|---|---|---|
| [E1](https://github.com/opentidehq/opentide/issues/1653) | `nvim --headless --clean -l scripts/engine/nvim-smoke.lua target/release/opentide-lsp`, Neovim 0.9.5: `nvim-smoke: 0.9, one diagnostic (kql_unknown_operator), pushed diagnostics`, rc 0 | pass |
| [E2](https://github.com/opentidehq/opentide/issues/1654) | the same on Neovim 0.11.5 (release tarball in `/home/user/smoke/c/nvim-dl`) | pass |
| [E3](https://github.com/opentidehq/opentide/issues/1654) | by hand, step 1, Neovim 0.9.5: source `editors/nvim/opentide.lua` and open a file | fail ([C4](https://github.com/opentidehq/opentide/issues/1668)) |
| [E4](https://github.com/opentidehq/opentide/issues/1655) | by hand, steps 2-3, Neovim 0.11.5, opening `$SMOKE/objects/rules/sentinel-a-create.yaml` by its absolute path as written | fail ([C4](https://github.com/opentidehq/opentide/issues/1668)) |
| [E5](https://github.com/opentidehq/opentide/issues/1657) | by hand, steps 2-3, Neovim 0.11.5, opened relative to the workspace: diagnostic on the line, hover on `SecurityEvent`, 54 completions after `\| ` | pass |
| [E6](https://github.com/opentidehq/opentide/issues/1657) | by hand, step 4: `q.kql` gets `kql_unknown_operator` | pass |
| [E7](https://github.com/opentidehq/opentide/issues/1658) | by hand, step 5: a misspelt key in `splunk.toml` gets a diagnostic (through `opentide lsp start`) | pass |
| [E8](https://github.com/opentidehq/opentide/issues/1658) | docs/cli/lsp.md's Neovim snippet (`vim.lsp.config`) | fail ([C15](https://github.com/opentidehq/opentide/issues/1671): attaches to rules, not to `.kql`) |
| [E9](https://github.com/opentidehq/opentide/issues/1662) | `editors/helix/languages.toml`: parses; servers, language ids, file types match docs/cli/lsp.md | pass (static check; Helix not installed) |
| [E10](https://github.com/opentidehq/opentide/issues/1662) | `editors/zed/opentide.json`: parses; language ids and suffixes match | pass (static check; Zed not installed) |
| [E11](https://github.com/opentidehq/opentide/issues/1654) | `opentide setup vscode`: `.vscode/extensions.json` recommends `opentidehq.opentide`, snippets written | pass |
| [E12](https://github.com/opentidehq/opentide/issues/1658) | VS Code by hand (smoke-test.md section 6) | not run (needs desktop VS Code and the extension from opentidehq/vscode-extension; steps for the human in section 4) |

#### 1f. WASM worker

| # | Item | Result |
|---|---|---|
| W1 | `cargo install wasm-bindgen-cli --version 0.2.128 --locked` (Cargo.lock's version) | pass |
| W2 | `CARGO_TARGET_DIR=/home/user/smoke/c/target bash scripts/engine/build-wasm.sh browser`: builds, then fails reading `$root/target` | fail ([C11](https://github.com/opentidehq/opentide/issues/1668)) |
| W3 | the script's smoke steps by hand on the built artifact: the three expected lines (`wasm-bindgen imports only`; `highlight() works for kql, spl, esql, eql, kuery, lucene, falco, cql, exabeam, yara, yaral`; `the language server answers initialize, diagnostics, hover and completion`) | pass |
| W4 | `build-wasm.sh wasi` and `cli` | not run (scope is the browser artifact) |

#### 1g. Counts

| Cell | Count |
|---|---|
| pass | 172 |
| fail | 25 (14 bugs; [C2](https://github.com/opentidehq/opentide/issues/1667) fills 7 platform cells; the docs bugs [C12](https://github.com/opentidehq/opentide/issues/1671)-[C14](https://github.com/opentidehq/opentide/issues/1671) have no cell of their own) |
| needs tenant | 3 |
| not run | 4 |

### Area D: Build outputs, dry-run payloads, live paths without a tenant, SDKs

**1. Build outputs (`generate`)**

| Item | Result |
|---|---|
| `generate` (full pipeline) | pass: 63 files as smoke-test.md says, exit 0, `--json` is one document, a re-run is idempotent (empty git diff). Failure path: **fail ([D1](https://github.com/opentidehq/opentide/issues/1659))** |
| `generate schemas` | pass: 8 files, all valid draft 2020-12; all 30 rules validate against the router `opentide.schema.json` |
| `generate templates` | pass: 17 files, all parse as YAML |
| `generate vocabs` | pass |
| `generate snippets` | pass: valid JSON |
| several phases at once (`schemas templates vocabs snippets`) | pass, 26 files. **fail ([D1](https://github.com/opentidehq/opentide/issues/1659)):** does not stop at `schemas` on a broken file |
| unknown phase | pass: exit 2, `usage_invalid_choice` |
| `generate docs` | pass: 34 files, 0 broken relative links; all 107 Mermaid diagrams parse with mermaid 11.4.1, every flavour |
| `docs rules`, `objectives`, `threats`, `index` | pass |
| `docs --rules/--threats/--objectives` | pass |
| `docs --changed` | pass; combined with a scope it exits 2 as documented |
| `docs --flavor` github, gitlab, azure_devops, generic | pass. `--flavor bogus`: **fail ([D8](https://github.com/opentidehq/opentide/issues/1659))** |
| `docs --output` | pass |
| docs with a dangling reference | pass: exit 1 with the documented message (see note N5) |
| `exports`, `exports navigator`, `objects`, `revisions` | pass: the navigator file is a valid ATT&CK layer (format 4.5), checked on a fixture that has techniques |
| `exports bogus` | pass: exit 2 |
| `generate explorer`, `--include-visibility`, `--visibility-tlp` and their failure paths | pass |
| `inflight`, `inflight prune` | pass |
| `extract` with no subcommand | pass: exit 2 |
| `extract sentinel`, `defender`, `elastic [--space, --include-prebuilt]` | needs tenant; the clean failure (unset or fake credentials) passes with exit 1 |
| broken configuration TOML | **fail ([D9](https://github.com/opentidehq/opentide/issues/1659))** |
| `generate` outside a workspace | **fail ([D17](https://github.com/opentidehq/opentide/issues/1659))** |
| `generate` on a fresh `setup repo` scaffold | pass |

**2. Deploy: plan, dry-run and payloads**

| Item | Result |
|---|---|
| `validate query` (offline) and `deploy --dry-run` JSON, all 13 platforms | pass: every row matches the smoke-test.md section 4 table |
| plain-text dry-run, all 13 platforms | pass |
| live payload versus the vendor API, 12 platforms | pass (Sentinel and Defender with notes N1 and N2) |
| live payload, Graylog | **fail ([D2](https://github.com/opentidehq/opentide/issues/1654))** |
| `--uuid`, `--file`, `--all` and how they combine | pass |
| `--strategy` missing, `STAGING`, bogus | pass: exit 2 |
| `--plan` and `DEPLOYMENT_PLAN` | pass: exit 2 |
| `deploy metadata` | pass: exit 2, `not_implemented` |
| `migrate-state` | pass |
| `--keep-deprecated`, `--wide`, `--skip-unconfigured`, `--persist-state-externally`, `--skip-promotion` | pass |
| dry-run of a rule that fails to compile | pass: `would fail`, diagnostics, exit 1 |
| `deployment_state_unpersisted` in CI | pass (the docs are incomplete, [D15](https://github.com/opentidehq/opentide/issues/1671)) |
| broken rule YAML | **fail ([D9](https://github.com/opentidehq/opentide/issues/1659))** |
| repository whose only commit is the root commit | **fail ([D10](https://github.com/opentidehq/opentide/issues/1662))** |
| "not in the plan" note | **fail ([D11](https://github.com/opentidehq/opentide/issues/1662))** |
| dry-run `api_request` versus the docs | **fail ([D12](https://github.com/opentidehq/opentide/issues/1662))** |
| `--json` purity on deploy and generate | pass |
| SDK `deploy_plan` writes nothing | pass: the workspace copy is byte-identical afterwards |


**Per-platform matrix (sections 2 and 3)**

Columns: offline `validate query`; `deploy --dry-run --json` vs smoke-test.md section 4; plain-text dry-run; the request a real deploy sends (captured at the local stand-in) vs the vendor REST API; `opentide query` with unset and fake creds (127.0.0.1:9); `validate query --live` unset and fake creds; real deploy with unset creds / unreachable tenant; live success.

| Platform | validate query | dry-run JSON | dry-run text | live request vs vendor API | `query` no tenant | `--live` no tenant | real deploy no tenant | live success |
|---|---|---|---|---|---|---|---|---|
| `sentinel` | pass | pass | pass | pass (N1) | pass | pass | fail ([D7](https://github.com/opentidehq/opentide/issues/1658)) | needs tenant |
| `defender_for_endpoint` | pass | pass ([D12](https://github.com/opentidehq/opentide/issues/1662)) | pass | pass (N2) | pass | pass | pass | needs tenant |
| `splunk` | pass | pass ([D12](https://github.com/opentidehq/opentide/issues/1662)) | pass | pass | pass | pass | fail ([D7](https://github.com/opentidehq/opentide/issues/1658)) | needs tenant |
| `sentinel_one` | pass | pass ([D12](https://github.com/opentidehq/opentide/issues/1662)) | pass | pass | pass | pass | fail ([D7](https://github.com/opentidehq/opentide/issues/1658)) | needs tenant |
| `crowdstrike` | pass | pass ([D12](https://github.com/opentidehq/opentide/issues/1662)) | pass | pass | pass | pass (`supported: false`, exit 1) | pass | needs tenant |
| `harfanglab` | pass | pass ([D12](https://github.com/opentidehq/opentide/issues/1662)) | pass | pass | pass | pass (`supported: false`, exit 1) | fail ([D7](https://github.com/opentidehq/opentide/issues/1658)) | needs tenant |
| `carbon_black_cloud` | pass | pass ([D12](https://github.com/opentidehq/opentide/issues/1662)) | pass | pass | pass | pass | fail ([D7](https://github.com/opentidehq/opentide/issues/1658)) | needs tenant |
| `elastic` | pass | pass ([D12](https://github.com/opentidehq/opentide/issues/1662)) | pass | pass | pass | pass | fail ([D7](https://github.com/opentidehq/opentide/issues/1658)) | needs tenant |
| `sysdig` | pass | pass | pass | pass | pass (exit 2, no runner) | pass (`supported: false`, exit 1) | fail ([D7](https://github.com/opentidehq/opentide/issues/1658)) | needs tenant |
| `bitdefender` | pass | pass | pass | pass (N4) | pass (exit 2, no runner; [D16](https://github.com/opentidehq/opentide/issues/1671) docs) | pass (`supported: false`, exit 1) | fail ([D6](https://github.com/opentidehq/opentide/issues/1658), [D7](https://github.com/opentidehq/opentide/issues/1658)) | needs tenant |
| `graylog` | pass | pass | pass | fail ([D2](https://github.com/opentidehq/opentide/issues/1654)) | fail ([D3](https://github.com/opentidehq/opentide/issues/1654)) | fail ([D3](https://github.com/opentidehq/opentide/issues/1654), [D4](https://github.com/opentidehq/opentide/issues/1658)) | pass | needs tenant |
| `exabeam` | pass | pass | pass | pass | pass | pass | fail ([D7](https://github.com/opentidehq/opentide/issues/1658)) | needs tenant |
| `google_secops` | pass | pass | pass | pass | fail ([D5](https://github.com/opentidehq/opentide/issues/1658)) | fail ([D4](https://github.com/opentidehq/opentide/issues/1658), [D5](https://github.com/opentidehq/opentide/issues/1658)) | fail ([D7](https://github.com/opentidehq/opentide/issues/1658)) | needs tenant |

"pass ([D12](https://github.com/opentidehq/opentide/issues/1662))": the plan and counts match section 4, but `api_request` is the rule block, not the request ([D12](https://github.com/opentidehq/opentide/issues/1662)). This matrix is a per-platform view of the rows counted above; the counts do not add it again.

**3. Live paths with no tenant**

| Item | Result |
|---|---|
| `opentide query`, unset and fake credentials | pass on 11 platforms: sysdig and bitdefender exit 2 (no runner); the others exit 1 with a clean message. **fail:** graylog ([D3](https://github.com/opentidehq/opentide/issues/1654)), google_secops ([D5](https://github.com/opentidehq/opentide/issues/1658)) |
| `validate query --live`, unset and fake credentials | pass on 11. crowdstrike, harfanglab, sysdig and bitdefender give `supported: false` with exit 1 and name the platform. **fail:** graylog ([D3](https://github.com/opentidehq/opentide/issues/1654), [D4](https://github.com/opentidehq/opentide/issues/1658)), google_secops ([D4](https://github.com/opentidehq/opentide/issues/1658), [D5](https://github.com/opentidehq/opentide/issues/1658)) |
| real deploy with unset credentials or an unreachable tenant | pass on 3 (defender, crowdstrike, graylog). **fail ([D7](https://github.com/opentidehq/opentide/issues/1658))** on 10 |
| `query` usage errors (no query, two queries, `--tenant`, `--since`, `--from`, `--limit`, `--language`, unknown `--rule`, `--rule` on harfanglab and google_secops, no tenant) | pass: all exit 2 |
| live success paths, 13 platforms | needs tenant |

**4. Python SDK**

| Item | Result |
|---|---|
| `Workspace.open` | **fail ([D13](https://github.com/opentidehq/opentide/issues/1669))** |
| `from_files`, `root`, `repr` | pass |
| `validate` with `check`, `files`, `uuids`, `strict`, `queries` | pass. `types` input checking: **fail ([D13](https://github.com/opentidehq/opentide/issues/1669))** |
| `lint` (`checks`, `strict`) | pass |
| `info`, `info(environment)`, `catalog`, `coverage`, `rules`, `objectives`, `threats` | pass |
| `deploy_plan` (`strategies`, `uuids`, `files`, `platform`, `keep_deprecated`, `environment`) | pass. Input checking: **fail ([D13](https://github.com/opentidehq/opentide/issues/1669))** |
| `run_json` and `Workspace.run_json` | pass |
| `OpentideError` (codes, pickle, copy) | pass |
| `tenants`, `TenantConfig` | pass |
| `Connection.open` | pass: `credential_unset` names `S1_API_TOKEN` |
| `query`, `validate_query`, `deploy` against an unreachable tenant | pass: `tenant_unreachable`, `scope=tenant` on deploy, `usage_invalid_value` and `usage_invalid_choice` |
| `start`/`end` given as a string | **fail ([D14](https://github.com/opentidehq/opentide/issues/1669))** |
| `canceller`, `capabilities`, `operation_unsupported` | pass |
| `opentide.analysis.check_query` | pass |
| `EngineUnavailableError` | not run |
| models (load, `model_*`, `ValidationError`, frozen, `model_copy`, pickle, `DeprecationWarning`) | pass |
| models docs | **fail ([D16](https://github.com/opentidehq/opentide/issues/1671))** |
| plugins API, built from the `docs/sdk/platforms.md` sample | pass: validate finding, dry-run, real deploy recording `acme-rule-17`, then update, `--live`, `query`, `--rule` refused |
| the 30 Python doc fences | pass: 19 run alone; 4 are continuation fragments; 2 need pyyaml or pydantic as the docs say; 3 stop with `credential_unset` as expected |
| public-name enumeration | **fail ([D16](https://github.com/opentidehq/opentide/issues/1671))** |

**5. Node SDK**

| Item | Result |
|---|---|
| smoke-test.md section 0 npm step, followed exactly | pass: `PASS ... runs on linux-x64-gnu`, `kept .../npm-work`, rc=0 |
| section 7 one-liner | pass: objects 30, errors 0, warnings 1 |
| the 10 `typescript.md` fences, CommonJS | pass: the `Connection` fences stop with `credential_unset`; strict exits 1 |
| the same 10 fences, ESM | pass, same results |
| failure paths | pass, except **[D13](https://github.com/opentidehq/opentide/issues/1669)** |
| `npx @opentide/opentide` with the documented commands | pass |
| `--json commands` and a dry-run, npm versus PyPI | pass: identical |
| `tsc` | pass (run by `test.mjs`) |

**6. Rust SDK**

| Item | Result |
|---|---|
| the 6 `rust.md` examples (`from_files`, `validate`, `catalog`, `deploy_plan`, `query`, `cli::run_json`), compiled in a fresh path-dependency project and run | pass |
| `Workspace::open` on a missing path | **fail ([D13](https://github.com/opentidehq/opentide/issues/1669))** |

### Area E: Phase 2: Elastic 8.19/9.5, Graylog 6.3, Splunk 10.6, Falco

Every cell is pass, fail (bug id), needs tenant, or not run (with the reason). "pass*" means the step passed, with a minor finding attached.

| Step | elastic-8.19 | elastic-9.5 | graylog-6.3 | splunk-10.6 | sysdig / falco |
|---|---|---|---|---|---|
| 1 Configure, `doctor` | pass. doctor has no tenant connectivity check ([ED6](https://github.com/opentidehq/opentide/issues/1658)) | pass ([ED6](https://github.com/opentidehq/opentide/issues/1658)) | pass ([ED6](https://github.com/opentidehq/opentide/issues/1658)) | pass ([ED6](https://github.com/opentidehq/opentide/issues/1658)) | pass: credentials warn, as expected |
| 2 First deploy, verify object via API | pass: query, language (esql/eql/kuery/lucene), severity, risk, interval/from, enabled, tags, index and threat checked. The first deploy needs a second commit or `--all` ([E9](https://github.com/opentidehq/opentide/issues/1662)) | pass | **fail ([E2](https://github.com/opentidehq/opentide/issues/1654))**: streams and notification aliases are dropped. Query, priority, schedule, group_by/condition, state and field_spec are right | **fail ([E5](https://github.com/opentidehq/opentide/issues/1657))**: every rule is refused for the `soc_macro_auto_mdr_mapping` macro. pass once that macro was created by hand: search, cron, earliest/latest, trigger, severity, enabled. ES notable/risk/correlation: needs ES tenant | needs tenant. The dry-run payload loads in Falco 0.45.2 (`falco -V`: Ok; only the expected unused-macro warning) |
| 3 Fires / does not fire | pass: ES\|QL 2, EQL 1, KQL 1 alert; Lucene must-not fired 0, ran `succeeded` | pass (same counts) | pass: filter fired 2, aggregation fired 1, must-not fired 0 | pass: scheduler `result_count` 4 vs 0, both `success` | needs tenant |
| 4 Update (query + severity) in place | pass: same Kibana id, revision 0→1 | pass | pass: same definition id, `~ update` planned from state | pass. Renaming a rule duplicates the saved search ([E6](https://github.com/opentidehq/opentide/issues/1657)) | needs tenant |
| 5 Idempotent redeploy | pass*: revision unchanged, `updated_at` rewritten, reported "4 created or updated" ([E10](https://github.com/opentidehq/opentide/issues/1662)) | pass: nothing modified. Still reported "4 created or updated" ([E10](https://github.com/opentidehq/opentide/issues/1662)) | pass*: `updated_at` rewritten, "3 updated" ([E10](https://github.com/opentidehq/opentide/issues/1662)) | pass*: `updated` rewritten ([E10](https://github.com/opentidehq/opentide/issues/1662)) | needs tenant |
| 6 Disable / delete | pass: `- disable` sets `enabled:false`, `× delete` removes it. Re-enabling works | pass | pass: `state: DISABLED`, definition deleted, shard removed | pass: `disabled=1`, saved search deleted | needs tenant |
| 7 Failures (bad cred, tenant down, one invalid rule among valid ones) | pass for bad cred and the invalid rule: `failures[]` present, exit 1, the rest deployed. **fail ([E7](https://github.com/opentidehq/opentide/issues/1658))** for Kibana down. `GITHUB_STEP_SUMMARY` written ([ED4](https://github.com/opentidehq/opentide/issues/1671)) | same as 8.19 ([E7](https://github.com/opentidehq/opentide/issues/1658)) | pass: invalid query refused by `/api/search/validate`, the rest deployed. 401 and down fail the tenant | pass: invalid SPL refused, the rest deployed. 401 is per rule (documented). Refused and hung tenant handled | pass: an unset token is refused before any request |
| 8 From CI (`setup ci github`) | **fail ([E1](https://github.com/opentidehq/opentide/issues/1653), [E4](https://github.com/opentidehq/opentide/issues/1655), [E15](https://github.com/opentidehq/opentide/issues/1653))**. actionlint is clean. Resume: the **unmodified generated workflow ran under act** (`tools/act_run.sh`, logs `act-pr1.log`, `act-prod1.log`, `act-prod2.log`). PR event: validate, live gate (staging tenant), generate and deploy_staging all pass, and the rule lands in the staging space. Push of the merge: every job is green, but the production job deploys to 0 tenants ([E1](https://github.com/opentidehq/opentide/issues/1653)) and the write-back pushes `status: PRODUCTION`. Default space: 0 rules. The next edit of the now-PRODUCTION rule deploys to the prod tenant correctly | **fail ([E1](https://github.com/opentidehq/opentide/issues/1653))**. The staging job passes | **fail ([E1](https://github.com/opentidehq/opentide/issues/1653))** | **fail ([E1](https://github.com/opentidehq/opentide/issues/1653))** | not run (needs tenant) |
| 9 Teardown | pass | pass | pass: 3 anonymous volumes removed by hand | pass (`rm -v`) | pass (only `--rm` containers) |
| `validate query --live` | pass. Auth-failure output misleading ([E8](https://github.com/opentidehq/opentide/issues/1658)) | pass ([E8](https://github.com/opentidehq/opentide/issues/1658)) | **fail ([E3](https://github.com/opentidehq/opentide/issues/1654))** with stream aliases. pass with raw stream ids | **fail ([E5](https://github.com/opentidehq/opentide/issues/1657))** without the macro. pass with it ([E8](https://github.com/opentidehq/opentide/issues/1658)) | pass: `supported: false`, exit 1, as documented |
| `opentide query` | pass: ES\|QL, EQL, Lucene, kuery (preview), `--rule` × 4, `--format jsonl`. Failure exit codes right | pass | **fail ([E3](https://github.com/opentidehq/opentide/issues/1654), [E11](https://github.com/opentidehq/opentide/issues/1654))**. pass with raw stream ids | pass: ad hoc, `stats`, usage errors exit 2. `--rule` fails without the macro ([E5](https://github.com/opentidehq/opentide/issues/1657)) | pass: exit 2, "no query runner", as documented |

Cleanup, after the resume as well: every `smoke-e-*` container was removed with `docker rm -f -v` (ES/Kibana 8.19, Graylog with OpenSearch and Mongo, Splunk), and the `smoke-e-net` network is removed. My act runs left no containers or volumes. The volumes still present (`act-opentide-Update-inflight-preview-shards-…`, `act-toolcache`) belong to another tester. The act workspace (`ws-act`), its bare origin (`origin-act.git`) and the act logs (`act-*.log`) remain on disk as evidence.

## Findings

Sorted by severity:
- **blocker:** a release candidate can't ship with it.
- **major:** wrong behaviour users will hit.
- **minor:** wrong but survivable, or confusing.
- **docs:** the docs disagree with the behaviour.

A finding that two areas reported points at the one tracked (*same as*). Full reproductions, expected and actual output, and code locations are in each issue.

| ID | Severity | Finding | Issue | Fix PR |
|---|---|---|---|---|
| A1 | blocker | Version 0.12.0 is below 0.28.1 and already on PyPI; pipelines pin 0.12.0, which installs the old CLI that crashes | [#1623](https://github.com/opentidehq/opentide/issues/1623) | — |
| E1 | blocker | Production deploy job promotes rules, deploys them to 0 tenants and reports success | [#1653](https://github.com/opentidehq/opentide/issues/1653) | [#1664](https://github.com/opentidehq/opentide/pull/1664) |
| E2 | blocker | Graylog deploy sends empty streams and notifications (aliases dropped); dry run resolves them | [#1654](https://github.com/opentidehq/opentide/issues/1654) | [#1666](https://github.com/opentidehq/opentide/pull/1666) |
| A2 | major | GitLab validate after_script runs python -m opentide.ci.codequality, which no longer exists | [#1656](https://github.com/opentidehq/opentide/issues/1656) | — |
| A3 | major | Azure pipeline never maps credentials into steps (no env:) | [#1655](https://github.com/opentidehq/opentide/issues/1655) | — |
| A4 | major | Production job promotes and commits even when the deploy reached no tenant *(same as E1)* | [#1653](https://github.com/opentidehq/opentide/issues/1653) | [#1664](https://github.com/opentidehq/opentide/pull/1664) |
| A5 | major | setup ci silently overwrites a user-edited pipeline; --plan calls it a merge | [#1656](https://github.com/opentidehq/opentide/issues/1656) | — |
| A6 | major | --explorer-pages job builds from opentide@development source and needs undocumented secrets | [#1656](https://github.com/opentidehq/opentide/issues/1656) | — |
| A7 | major | share status reports never-shared objects as created on the target | [#1661](https://github.com/opentidehq/opentide/issues/1661) | — |
| B16 | major | A // line in a folded >- KQL query comments out the rest: deployed rule matches every event; validate and lint clean | [#1660](https://github.com/opentidehq/opentide/issues/1660) | — |
| C1 | major | MCP with no workspace (or missing OPENTIDE_REPO_ROOT) serves an empty catalogue; validation_report ok: true | [#1659](https://github.com/opentidehq/opentide/issues/1659) | — |
| D1 | major | generate silently ignores malformed object files: exit 0, rule missing from outputs | [#1659](https://github.com/opentidehq/opentide/issues/1659) | — |
| D2 | major | Real Graylog deploy sends streams:[] and notifications:[] (setup.setup lookup) *(same as E2)* | [#1654](https://github.com/opentidehq/opentide/issues/1654) | [#1666](https://github.com/opentidehq/opentide/pull/1666) |
| D3 | major | Graylog query and --live reject documented stream_ids aliases *(same as E3)* | [#1654](https://github.com/opentidehq/opentide/issues/1654) | — |
| E3 | major | Graylog query and validate query --live reject stream aliases the tenant defines | [#1654](https://github.com/opentidehq/opentide/issues/1654) | — |
| E4 | major | Generated GitHub pipeline never passes the tenant's own credential variables | [#1655](https://github.com/opentidehq/opentide/issues/1655) | — |
| E5 | major | Splunk needs an undocumented soc_macro_auto_mdr_mapping macro; nothing deploys without it | [#1657](https://github.com/opentidehq/opentide/issues/1657) | — |
| E6 | major | Renaming a Splunk rule leaves the old saved search running (duplicate alerting) | [#1657](https://github.com/opentidehq/opentide/issues/1657) | — |
| E7 | major | Unreachable Kibana is a per-rule failure: every rule retried, tenant never stopped | [#1658](https://github.com/opentidehq/opentide/issues/1658) | — |
| E14 | major | Build is 0.12.0, an existing older PyPI release *(same as A1)* | [#1623](https://github.com/opentidehq/opentide/issues/1623) | — |
| A8 | minor | Git hook validates the working copy, not the staged content | [#1670](https://github.com/opentidehq/opentide/issues/1670) | — |
| A9 | minor | --data / OPENTIDE_DATA_ROOT has no effect; a missing path is accepted | [#1659](https://github.com/opentidehq/opentide/issues/1659) | — |
| A10 | minor | OPENTIDE_REPO_ROOT naming a missing folder makes validate pass (exit 0) | [#1659](https://github.com/opentidehq/opentide/issues/1659) | — |
| A11 | minor | --python-version unchecked: breaks GitHub YAML, injects GitLab keys, accepts 2.7 | [#1656](https://github.com/opentidehq/opentide/issues/1656) | — |
| A12 | minor | Generated README quick-start command fails (deploy --dry-run without --strategy) | [#1656](https://github.com/opentidehq/opentide/issues/1656) | — |
| A13 | minor | Redirected human output wraps at 80 columns; docs say never wrapped | [#1665](https://github.com/opentidehq/opentide/issues/1665) | — |
| A15 | minor | PyPI summary says nine platforms; there are 13 | [#1671](https://github.com/opentidehq/opentide/issues/1671) | — |
| A16 | minor | CrowdStrike template leaves credentials empty instead of $VAR; pipelines pass no secret | [#1655](https://github.com/opentidehq/opentide/issues/1655) | — |
| B1 | minor | metadata.created/modified accept any string ('yesterday', 2026-02-30) | [#1663](https://github.com/opentidehq/opentide/issues/1663) | — |
| B2 | minor | validate passes values the platform rejects (CrowdStrike trigger/outcome, HarfangLab Sigma, Defender category) | [#1663](https://github.com/opentidehq/opentide/issues/1663) | — |
| B3 | minor | Opaque 'ElasticConfig validation failed ... duration' for bad new_terms window, not placed at the value | [#1663](https://github.com/opentidehq/opentide/issues/1663) | — |
| B4 | minor | validate query --json places a HarfangLab YARA error at the metadata.uuid line | [#1663](https://github.com/opentidehq/opentide/issues/1663) | — |
| B5 | minor | bitdefender_criterion_field underline covers one character | [#1663](https://github.com/opentidehq/opentide/issues/1663) | — |
| B7 | minor | new --path outside objects/ writes a file opentide never reads, then suggests a failing validate --file | [#1670](https://github.com/opentidehq/opentide/issues/1670) | — |
| B8 | minor | Empty name at the interactive prompt gets the 'prompts only at a terminal' message | [#1670](https://github.com/opentidehq/opentide/issues/1670) | — |
| B9 | minor | YAML error frames: tab on previous line, no unclosed-[ note, odd duplicate-key wording | [#1663](https://github.com/opentidehq/opentide/issues/1663) | — |
| B10 | minor | Config TOML syntax error is command_failed with no position (config_parse documented) *(same as D9)* | [#1659](https://github.com/opentidehq/opentide/issues/1659) | — |
| B11 | minor | Plain output wraps at 80 columns; docs say never *(same as A13)* | [#1665](https://github.com/opentidehq/opentide/issues/1665) | — |
| B12 | minor | NO_COLOR / --no-color / FORCE_COLOR=0 at a terminal still emit bold escapes | [#1665](https://github.com/opentidehq/opentide/issues/1665) | — |
| B15 | minor | Threat chaining accepts any keys and a self-loop | [#1663](https://github.com/opentidehq/opentide/issues/1663) | — |
| B17 | minor | setup --org never reaches new; README platform list goes stale after setup platforms | [#1670](https://github.com/opentidehq/opentide/issues/1670) | — |
| B18 | minor | Old unscoped vocabulary value gets no migrate vocab-scope hint; migrate outside a workspace exits 0 | [#1659](https://github.com/opentidehq/opentide/issues/1659) | — |
| B19 | minor | explain kql_parse suggests yaml_parse | [#1663](https://github.com/opentidehq/opentide/issues/1663) | — |
| B21 | minor | Unclosed ( in KQL before a pipe reported as 'expected a name' at the wrong token | [#1660](https://github.com/opentidehq/opentide/issues/1660) | — |
| B22 | minor | Frames and messages not truncated: a 1 MB one-line query prints ~2 MB | [#1665](https://github.com/opentidehq/opentide/issues/1665) | — |
| C2 | minor | deploy_rule dry_run:false drops the deployer's error for 7 of 9 tenant platforms | [#1667](https://github.com/opentidehq/opentide/issues/1667) | — |
| C3 | minor | opentide://templates/rule (and rule::1.1) returns the rule::1.0 template; rule::1.0 refused | [#1667](https://github.com/opentidehq/opentide/issues/1667) | — |
| C4 | minor | editors/nvim/opentide.lua fails on Neovim 0.9.5 and misses rules opened by absolute path | [#1668](https://github.com/opentidehq/opentide/issues/1668) | — |
| C5 | minor | Completion after '\| ' returns nothing in a query inside a rule (.kql gets 54 items) | [#1668](https://github.com/opentidehq/opentide/issues/1668) | — |
| C6 | minor | setup mcp never warns when opentide is not on PATH, though docs say it does | [#1670](https://github.com/opentidehq/opentide/issues/1670) | — |
| C7 | minor | Live validate_query results carry an internal _exit_code key | [#1667](https://github.com/opentidehq/opentide/issues/1667) | — |
| C8 | minor | MCP: a non-JSON line gets no reply; a call without params answers Method not found | [#1667](https://github.com/opentidehq/opentide/issues/1667) | — |
| C9 | minor | validate_query accepts any stack; search accepts any type, silently | [#1667](https://github.com/opentidehq/opentide/issues/1667) | — |
| C10 | minor | opentide/analyze: unknown language = no diagnostics; opentide/fs/read: '' for relative path | [#1668](https://github.com/opentidehq/opentide/issues/1668) | — |
| C11 | minor | build-wasm.sh builds into $CARGO_TARGET_DIR but reads $root/target | [#1668](https://github.com/opentidehq/opentide/issues/1668) | — |
| C16 | minor | deploy_rule dry run for a platform with no block answers a successful preview | [#1667](https://github.com/opentidehq/opentide/issues/1667) | — |
| D4 | minor | --live reports SecOps/Graylog tenant failures as Queries rejected, no reason in JSON | [#1658](https://github.com/opentidehq/opentide/issues/1658) | — |
| D5 | minor | Google SecOps reports a refused connection as tenant_unauthorized | [#1658](https://github.com/opentidehq/opentide/issues/1658) | — |
| D6 | minor | Bitdefender reports refused TCP connect as create_unconfirmed and asks for manual cleanup | [#1658](https://github.com/opentidehq/opentide/issues/1658) | — |
| D7 | minor | Deploy without creds/tenant: result shape differs per platform; Elastic tries every rule | [#1658](https://github.com/opentidehq/opentide/issues/1658) | — |
| D8 | minor | generate docs --flavor bogus exits 1 command_failed, not 2 usage_invalid_choice | [#1659](https://github.com/opentidehq/opentide/issues/1659) | — |
| D9 | minor | TOML/YAML parse errors come back as command_failed with no diagnostics | [#1659](https://github.com/opentidehq/opentide/issues/1659) | — |
| D10 | minor | Deploy without --all reads nothing when HEAD is the root commit *(same as E9)* | [#1662](https://github.com/opentidehq/opentide/issues/1662) | — |
| D11 | minor | Dry-run 'not in the plan' note counts other platforms' rules under --platform | [#1662](https://github.com/opentidehq/opentide/issues/1662) | — |
| D12 | minor | Dry-run api_request is the rule block with defaults for 6 platforms; contradicts docs | [#1662](https://github.com/opentidehq/opentide/issues/1662) | — |
| D13 | minor | Python/Node/Rust SDKs accept inputs the CLI refuses (bogus types, platform, limit=0) | [#1669](https://github.com/opentidehq/opentide/issues/1669) | — |
| D14 | minor | Python Connection.query/validate_query raise raw AttributeError for string start/end | [#1669](https://github.com/opentidehq/opentide/issues/1669) | — |
| D17 | minor | generate outside a workspace writes 20 files there and exits 0 | [#1659](https://github.com/opentidehq/opentide/issues/1659) | — |
| ED6 | minor | No tenant connectivity check anywhere (doctor checks only env vars) | [#1658](https://github.com/opentidehq/opentide/issues/1658) | — |
| E8 | minor | --live credential refusal reported as rejected queries, with a green tick | [#1658](https://github.com/opentidehq/opentide/issues/1658) | — |
| E9 | minor | Deploy on a repo whose only commit is the root commit reads no rule | [#1662](https://github.com/opentidehq/opentide/issues/1662) | — |
| E10 | minor | No-op redeploy rewrites every rule and reports it as changed | [#1662](https://github.com/opentidehq/opentide/issues/1662) | — |
| E11 | minor | Graylog opentide query --rule is refused; docs don't say so | [#1654](https://github.com/opentidehq/opentide/issues/1654) | — |
| E12 | minor | Success info printed as warnings; redactor masks 'HTTP'; wrong advice text | [#1658](https://github.com/opentidehq/opentide/issues/1658) | — |
| E13 | minor | Production job's dry-run step says nothing will deploy (no promotion simulated) | [#1653](https://github.com/opentidehq/opentide/issues/1653) | — |
| E15 | minor | On a push to main the live gate checks to-be-promoted rules only against PREVIEW tenants; a RELEASE-only setup exits 2 | [#1653](https://github.com/opentidehq/opentide/issues/1653) | — |
| A14 | docs | Getting-started pages: 0.28.1 pin, validate query exit 2, layout, skills, Python-era text | [#1671](https://github.com/opentidehq/opentide/issues/1671) | — |
| B6 | docs | Docs contradict on placeholder queries; a YARA-L placeholder counts as 1 query valid | [#1671](https://github.com/opentidehq/opentide/issues/1671) | — |
| B13 | docs | validate.md describes unknown schema identifiers wrongly | [#1671](https://github.com/opentidehq/opentide/issues/1671) | — |
| B14 | docs | Tutorial sample outputs drifted (file counts, missing queries check) | [#1671](https://github.com/opentidehq/opentide/issues/1671) | — |
| C12 | docs | MCP docs say validate_query refuses unless live: true; it checks offline | [#1671](https://github.com/opentidehq/opentide/issues/1671) | — |
| C13 | docs | MCP install pages pin opentide==0.28.1 *(same as A14)* | [#1671](https://github.com/opentidehq/opentide/issues/1671) | — |
| C14 | docs | Stale MCP docs: exit code row, deploy_rule message, --uuid, engine shape | [#1671](https://github.com/opentidehq/opentide/issues/1671) | — |
| C15 | docs | docs/cli/lsp.md disagrees with the server (configurationSchemas, custom requests, editor setup) | [#1671](https://github.com/opentidehq/opentide/issues/1671) | — |
| C17 | docs | lsp start caches nothing; docs describe a cache under OPENTIDE_CACHE_DIR | [#1671](https://github.com/opentidehq/opentide/issues/1671) | — |
| D15 | docs | Docs list 3-5 platforms keeping vendor ids; 8 write state shards *(same as ED2)* | [#1671](https://github.com/opentidehq/opentide/issues/1671) | — |
| D16 | docs | SDK docs drift: models.md, 0.28.1 pin, check_query languages, dir(opentide) leaks | [#1671](https://github.com/opentidehq/opentide/issues/1671) | — |
| ED1 | docs | configuration.md: 'info --platform' does not show what a platform expects | [#1671](https://github.com/opentidehq/opentide/issues/1671) | — |
| ED2 | docs | deployment-state.md: wrong platform count, misses Graylog/Bitdefender/SecOps, no Splunk rename caveat | [#1671](https://github.com/opentidehq/opentide/issues/1671) | — |
| ED3 | docs | platforms.md says Graylog validate query exits 2 offline; it runs offline *(same as A14)* | [#1671](https://github.com/opentidehq/opentide/issues/1671) | — |
| ED4 | docs | ci-cd.md: job summary lists UUIDs, not rule names | [#1671](https://github.com/opentidehq/opentide/issues/1671) | — |
| ED5 | docs | quickstart pins opentide==0.28.1 while the build is 0.12.0 *(same as A14)* | [#1671](https://github.com/opentidehq/opentide/issues/1671) | — |

## Go / no-go

**No-go for 1.0.0-rc.1 at `d11702e9c`.** Land these first:

1. **[#1623](https://github.com/opentidehq/opentide/issues/1623)**: bump the workspace to 1.0.0 (`release.py bump 1.0.0`, release-management Step 0).
   - At 0.12.0, `doctor` tells users to downgrade-upgrade to 0.28.1.
   - Every pipeline `setup ci` generates pins `opentide==0.12.0`, which installs the old Python CLI.
2. **[#1653](https://github.com/opentidehq/opentide/issues/1653)**: a RELEASE push deploys the promoted rules to no tenant, exits 0 and commits the promotion. Fixed by [#1664](https://github.com/opentidehq/opentide/pull/1664).
3. **[#1654](https://github.com/opentidehq/opentide/issues/1654)**: Graylog deploys drop stream and notification aliases, so every definition searches all streams and notifies no one. Fixed by [#1666](https://github.com/opentidehq/opentide/pull/1666); `query` and `--live` still need their part.

Strongly recommended before the candidate, because a new user hits each of these on the documented path:
- [#1655](https://github.com/opentidehq/opentide/issues/1655): CI credentials.
- [#1656](https://github.com/opentidehq/opentide/issues/1656): the GitLab Code Quality step and overwritten pipelines.
- [#1657](https://github.com/opentidehq/opentide/issues/1657): the Splunk macro, without which nothing deploys to plain Splunk.
- [#1659](https://github.com/opentidehq/opentide/issues/1659): a missing workspace passes as `ok: true`.
- [#1660](https://github.com/opentidehq/opentide/issues/1660): a `//` in a folded KQL query silently widens the deployed rule.
- [#1661](https://github.com/opentidehq/opentide/issues/1661): `share status`.
- [#1658](https://github.com/opentidehq/opentide/issues/1658): tenant failures misclassified.

The minor and docs issues can follow in candidates 2 and later.

## By hand, for a person

- **VS Code** (not possible in an agent's container):
  1. Package and install the extension from opentidehq/vscode-extension.
  2. Point its server at a build's `opentide-lsp`; this repository names no setting for that, and `docs/cli/lsp.md` should.
  3. Open a copy of the `smoke-test.md` section 2 workspace.
  4. Break `objects/rules/sentinel-a-create.yaml`'s `| where` into `| wherre`, then check the diagnostic, hover on `SecurityEvent`, and completion after `| ` (expect [C5](https://github.com/opentidehq/opentide/issues/1668): typing the space may pop nothing; Ctrl+Space works).
  5. Do the same in a `q.kql` file.
  6. Check the YARA-L semantic colours in `rule-google-secops-process-1.0.yaml`.
  7. Check `.vscode/mcp.json` from `setup mcp --vscode` with Copilot agent mode.
- **An MCP host with a model** (`smoke-test.md` section 5, second box): ask it to validate one query in each language and explain a code.
- **SaaS tenants**, for live deploy, `--live` and `query`:
  - Sentinel, Defender for Endpoint, SentinelOne, CrowdStrike, HarfangLab, Carbon Black, Exabeam, Google SecOps and Sysdig Secure.
  - Bitdefender GravityZone (credentials are in the environment, but out of scope by the user's choice).
  - Splunk **Enterprise Security** (notables, risk, correlation searches).
  - `generate extract sentinel|defender|elastic` against real tenants.
- **Other machines:**
  - The CI-built wheels on an older glibc (the local wheel is `manylinux_2_39`, so the Ubuntu 22.04 install was not run).
  - macOS, and Windows and Windows on Arm (PowerShell launcher, `Scripts` on `PATH`).
- **Network:** `setup skills --install` / `--all` with access to `api.github.com`.
