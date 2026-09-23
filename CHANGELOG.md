# Changelog

All notable changes to the `opentide` package are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Version numbers come from git tags via hatch-vcs.

## [Unreleased]

### Fixed

- The `deploy` reference, troubleshooting, and tutorial pages match 0.5.0 output: a dry-run prints `== MDR Deployment ==` and `OK Deployment completed` (the plan and payloads only with `--json`), `deploy metadata` exits `2` with `FATAL: Metadata deployment is not implemented for splunk` rather than logging intent, and the tutorial's T1059 coverage query lists the rule alone, not an objective ([#299](https://github.com/OpenTideHQ/opentide/issues/299)).

### Tests

- A `text` or `json` fence in `docs/` tagged `output-of="opentide …"` (plus `exit=N` for a command meant to fail) is run against a repository scaffolded as in the tutorial, with deployers stubbed. Its lines or JSON values and its exit code must match the live command, the command must be printed on the same page, and a failing sample's section must say which code it exits with ([#299](https://github.com/OpenTideHQ/opentide/issues/299)).

## [0.5.0] — 2026-09-23

Minor on 0.4.0. Upgrade if your threats follow `threat::1.0` and list their `impact` / `leverage` names: 0.4.0 rejected every such threat with `Input should be a valid string` ([#189](https://github.com/OpenTideHQ/opentide/issues/189)). It is a minor rather than a patch because a threat written the way 0.4.0 required (`impact: Data Breach`) now fails validation until it becomes a one-item list — read **Changed** before upgrading a pipeline.

### Changed

- `threat.impact` and `threat.leverage` must be non-empty YAML lists of vocabulary names, as `threat::1.0` specifies. A single string (`impact: Data Breach`), which 0.4.0 required, now fails validation with `must be a YAML list of impact vocabulary names`; rewrite it as a one-item list. Several names joined with `;` fail too, as the whole value or as one list item: give each name its own item and keep all of them ([#189](https://github.com/OpenTideHQ/opentide/issues/189)).
- In the SDK `ThreatBody.impact` and `ThreatBody.leverage` are `list[str]`. Generated threat templates, editor schemas (`type: array`, `minItems: 1`), and the explorer bundle carry both fields as lists ([#189](https://github.com/OpenTideHQ/opentide/issues/189)).

### Fixed

- A threat written to the `threat::1.0` spec (`impact: [Data Breach, Identity Theft]`) no longer fails with `Input should be a valid string`, and `validate` no longer suggests a single vocabulary name for a `;`-joined value, which would drop the other names ([#189](https://github.com/OpenTideHQ/opentide/issues/189)).

### Tests

- The 14 `threat-*.yaml` conformance fixtures from [OpenTideHQ/specifications](https://github.com/OpenTideHQ/specifications) are vendored under `tests/fixtures/specifications/threat-1.0/` and run through `opentide validate --file` in the E2E suite. The valid fixture must pass, each invalid one must fail on the field it breaks, and a guard test fails when upstream adds a fixture without an expectation ([#189](https://github.com/OpenTideHQ/opentide/issues/189)).

### Install

```bash
pip install opentide==0.5.0
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

Rewrite each `impact: Data Breach` as a one-item list (same for `leverage`), then run `opentide generate` so new threats start from the list template. If your CI patches the installed model to accept lists, drop that step.

## [0.4.0] — 2026-09-22

Minor on the public 0.3.0 beta. Upgrade if a first-run command crashed, printed a traceback, or quietly did nothing: this release fixes the first-user bugs filed against 0.3.0 ([#239](https://github.com/OpenTideHQ/opentide/issues/239)–[#258](https://github.com/OpenTideHQ/opentide/issues/258), [#202](https://github.com/OpenTideHQ/opentide/issues/202), [#233](https://github.com/OpenTideHQ/opentide/issues/233)) and the test-harness gaps that let them ship ([#259](https://github.com/OpenTideHQ/opentide/issues/259)). It is a minor rather than a patch because several fixes change output that scripts can depend on — read **Changed** before upgrading a pipeline. If you generated GitHub CI with `opentide setup ci`, regenerate it — see **Security**.

### Security

- The inflight job written by `opentide setup ci github` checked out the pull request head and ran `git push origin HEAD:<default branch>`. Whenever the pull request was up to date with the default branch, that push fast-forwarded the default branch to the pull request, landing its unreviewed changes. Generated GitHub, GitLab, and Azure inflight jobs now commit only `.opentide/inflight/` shards, on a separate worktree of the default branch, and push that. Regenerate existing pipelines with `opentide setup ci <github|gitlab|azure> --yes` ([#244](https://github.com/OpenTideHQ/opentide/issues/244)).

### Changed

- `opentide validate query` is an offline syntax check (KQL, SPL, S1QL, Lucene) by default and needs no platform SDK, credentials, or network. It follows each dialect's quoting and escaping: KQL multi-line strings (```` ``` ```` and `~~~`), S1QL `||` (with an operand on each side), and Lucene backslash escapes, mixed range ends, and `/regex/` terms. The previous tenant round-trip is `validate query --live`, which names the extra to install when the SDK is missing. JSON output reports `mode: offline-syntax` or `mode: live` ([#239](https://github.com/OpenTideHQ/opentide/issues/239)).
- `validate query` for CrowdStrike and HarfangLab returns the normal `ok` / `status` envelope with `supported: false` instead of a bare payload ([#247](https://github.com/OpenTideHQ/opentide/issues/247)).
- `query` is required and must not be blank on Splunk and Carbon Black configurations, as on the other query platforms. A rule with `query: ""` now fails validation instead of deploying nothing ([#233](https://github.com/OpenTideHQ/opentide/issues/233)). See [Upgrading to 0.4.0](https://opentide.org/docs/usage/concepts/platforms/#upgrading-to-040).
- `opentide --json setup` without `--yes` refuses to start the interactive wizard and exits non-zero with one JSON error ([#255](https://github.com/OpenTideHQ/opentide/issues/255)).
- MCP `search` always returns a list (a UUID lookup included, which also honours the other filters and ignores case; `get_chaining` resolves UUIDs the same way and returns the graph for them), `platform=` matches the configuration key exactly, and `coverage` for a parent technique includes sub-technique rules and reports `matched_techniques` ([#252](https://github.com/OpenTideHQ/opentide/issues/252), [#253](https://github.com/OpenTideHQ/opentide/issues/253)).
- MCP `opentide://vocabularies` returns an index (`metadata`, `entry_count`, `uri`) instead of every entry; read `opentide://vocabularies/{name}` for entries ([#254](https://github.com/OpenTideHQ/opentide/issues/254)).
- MCP `run_query` is an explicit stub (`stub: true`, `rows: null`, no `results` key) rather than a successful empty result ([#258](https://github.com/OpenTideHQ/opentide/issues/258)).
- `mcp` is pinned `<2` and the unused `fastmcp` dependency is gone. `opentide[sentinel]` declares the Azure packages the Sentinel validator and deployer import ([#256](https://github.com/OpenTideHQ/opentide/issues/256), [#239](https://github.com/OpenTideHQ/opentide/issues/239)).
- The positional `PATH` on `setup` subcommands is deprecated in favour of `--path` / `-C`. Giving both is a usage error ([#248](https://github.com/OpenTideHQ/opentide/issues/248)).

### Fixed

- `deploy metadata` and `generate inflight prune` no longer run their parent command first — a live deploy, or a second JSON document on stdout ([#243](https://github.com/OpenTideHQ/opentide/issues/243)).
- `opentide info coverage --technique T1059` works in either argument order ([#257](https://github.com/OpenTideHQ/opentide/issues/257)).
- Every `setup` subcommand accepts `--path` / `-C` and `--yes` / `-y`. Given before the subcommand (`opentide setup --path DIR --yes env`) they apply to it; other `setup` options in that position are refused instead of silently ignored, and a subcommand's `--help` after them still shows its help ([#248](https://github.com/OpenTideHQ/opentide/issues/248)).
- `validate --file objects/rules/x.yaml` honours the directory; a path target no longer matches a same-named file elsewhere. The ID-uniqueness check and the MCP `validation_report` tool resolve the same targets against the workspace, so a duplicate UUID is reported and an MCP server started outside the repository still finds the file ([#240](https://github.com/OpenTideHQ/opentide/issues/240)).
- Unparseable object YAML is reported as a `yaml_parse` validation issue instead of a traceback, including files the indexer skips ([#250](https://github.com/OpenTideHQ/opentide/issues/250)).
- `generate docs --changed` reports a structured failure in a repository without commits instead of a traceback. `generate docs --changed` and `generate inflight` find the baseline on `development`, `main`, or `master` (upstream, remote, or local), or whatever `origin/HEAD` names, count untracked object YAML, keep non-ASCII file names, and work when the workspace is nested inside the checkout. A pushed feature branch (`git push -u`, or an `actions/checkout` job) is compared with the default branch rather than its own remote copy, which hid every committed change ([#241](https://github.com/OpenTideHQ/opentide/issues/241), [#251](https://github.com/OpenTideHQ/opentide/issues/251)).
- `generate extract sentinel|defender` fail with a reportable error that names the missing extra, tenant, or key instead of `ModuleNotFoundError` / `KeyError` at import ([#242](https://github.com/OpenTideHQ/opentide/issues/242)).
- `opentide generate explorer` is registered and writes `explorer.bundle.json` / `explorer.search.json`; the GitHub CI template calls it instead of the nonexistent `opentide explorer build` ([#202](https://github.com/OpenTideHQ/opentide/issues/202)).
- A Sentinel-only `validate query` or deploy loads only the Sentinel engine: no missing-validator warnings for other vendors and no `ERROR` for platforms the repository disabled. An engine that fails to load is reported instead of a traceback ([#246](https://github.com/OpenTideHQ/opentide/issues/246)).
- `setup ci gitlab` inflight jobs use `${CI_JOB_TOKEN}` / `${CI_SERVER_HOST}` and a commit message GitLab can parse; `setup ci azure` inflight jobs actually commit and push (`set -e` script, `persistCredentials: true`, no cross-stage `dependsOn`); GitLab jobs that run `git` install it on the `python:*-slim` image. GitHub and Azure jobs target the repository's default branch (`setup ci --default-branch`, else `origin/HEAD`) instead of assuming `main`, and inflight jobs retry when another job publishes first and keep the shards other pull requests publish while they run ([#244](https://github.com/OpenTideHQ/opentide/issues/244)).
- The pre-commit hook validates the worktree being committed rather than an exported `OPENTIDE_REPO_ROOT`, and `--repo` overrides an exported workspace ([#249](https://github.com/OpenTideHQ/opentide/issues/249)). A workspace nested below the Git root is validated at its own path, several workspaces in one repository share the hook instead of the last `setup hooks` run replacing the others, and a hook whose workspace was moved or deleted fails instead of passing every commit. Setup no longer installs into a user-wide `core.hooksPath`, where the hook would fail commits in every other repository, and no longer crashes on Windows when the hooks directory is on another drive.
- `--no-color`, `NO_COLOR`, `FORCE_COLOR=0`, and `PY_COLORS=0` keep every line free of ANSI escapes, including Typer help and usage errors on CI runners that force colour. Importing `opentide.ci` no longer changes a host application's Typer colour settings ([#282](https://github.com/OpenTideHQ/opentide/pull/282)).
- MCP `coverage` and actor search read `rule.techniques` and `threat.actors`, not only `tags.*` ([#252](https://github.com/OpenTideHQ/opentide/issues/252)).
- MCP `opentide://schemas/{object_type}` resolves `rule` / `rule::1.0` instead of returning `{}`, `opentide://templates/{object_type}` accepts the same forms for the current schema version, and vocabularies are JSON rather than Pydantic `repr()` strings ([#254](https://github.com/OpenTideHQ/opentide/issues/254)).
- MCP `validate_query` returns real findings instead of `valid: true` for any string ([#245](https://github.com/OpenTideHQ/opentide/issues/245)).
- `opentide-mcp` from a plain `pip install opentide` prints the install line for the `mcp` extra instead of a traceback, and `opentide setup mcp` warns when the extra is missing ([#256](https://github.com/OpenTideHQ/opentide/issues/256)).
- `splunk::2.x` rules map `search`, `cron_schedule`, and flat throttling / notable / risk / email fields the same way in `validate` and `deploy`, and a migrated `cron_schedule` deploys as a scheduled search ([#233](https://github.com/OpenTideHQ/opentide/issues/233)).
- Tutorial, quickstart, and CLI reference samples match live output ([#247](https://github.com/OpenTideHQ/opentide/issues/247)).

### Tests

The CI harness now exercises the paths a first user takes, so these bugs fail CI if they return ([#259](https://github.com/OpenTideHQ/opentide/issues/259)): interactive setup on a real PTY ([#260](https://github.com/OpenTideHQ/opentide/issues/260)); `validate query` against the real validators ([#261](https://github.com/OpenTideHQ/opentide/issues/261)); the wheel job runs `opentide-mcp` with and without the extra ([#262](https://github.com/OpenTideHQ/opentide/issues/262)); a Typer argv matrix ([#263](https://github.com/OpenTideHQ/opentide/issues/263)); unmocked MCP tests plus a stdio JSON-RPC client ([#264](https://github.com/OpenTideHQ/opentide/issues/264)); hook tests that run `git commit` ([#265](https://github.com/OpenTideHQ/opentide/issues/265)); unmocked `generate extract` / `generate explorer` ([#266](https://github.com/OpenTideHQ/opentide/issues/266)); repo-relative `validate --file` ([#267](https://github.com/OpenTideHQ/opentide/issues/267)); git-baseline e2e for HEAD-less and non-`main` repositories ([#268](https://github.com/OpenTideHQ/opentide/issues/268)); assertions on GitLab and Azure job scripts ([#269](https://github.com/OpenTideHQ/opentide/issues/269)); and every documented `opentide` command resolved against the live CLI, with read-only samples executed as golden tests ([#270](https://github.com/OpenTideHQ/opentide/issues/270)).

### Not in this release

- [#189](https://github.com/OpenTideHQ/opentide/issues/189) (`ThreatBody.impact` / `leverage` as `list[str]`) waits on [OpenTideHQ/specifications#12](https://github.com/OpenTideHQ/specifications/issues/12).

### Install

```bash
pip install opentide==0.4.0
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

Regenerate generated CI and hooks to pick up the fixed templates: `opentide setup ci <github|gitlab|azure> --yes` and `opentide setup hooks --yes`.

## [0.3.0] — 2026-09-21

Minor maintenance release on the public 0.2.1 beta. Upgrade for current runtime and toolchain floors (cryptography 50.x, typer 0.27) and a clean GitHub Code Quality pass.

### Changed

- Recreated stale Dependabot uv upgrades on current trunk ([#235](https://github.com/OpenTideHQ/opentide/pull/235)): cryptography **50.0.1** (CVE-2026-69247), dulwich **1.2.15**, typer **0.27.2** (extra `all` was removed in 0.27; rich/shellingham/colorama are default deps), syrupy **5.5.3** (stay on 5.x), ruff **0.16.8**, ty **0.0.82** (dev extra only; `typing_extensions` stays a runtime dependency).
- Cleared GitHub Code Quality findings from the CodeQL `python-code-quality` suite ([#236](https://github.com/OpenTideHQ/opentide/pull/236)).

### Install

```bash
pip install opentide==0.3.0
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

## [0.2.1] — 2026-09-18

Patch on the public 0.2.0 beta. Upgrade if you validate `threat.cve` identifiers or generate threat documentation that should link to CIRCL Vulnerability-Lookup.

### Added

- CVE validation and generated threat CVE tables use [CIRCL Vulnerability-Lookup](https://vulnerability.circl.lu) instead of scraping NVD through `mitrecve`. `opentide validate --check cve` looks up CVE, GHSA, and GCVE identifiers (`GET /api/vulnerability/{id}`); unknown IDs return empty JSON. Generated docs link to `https://vulnerability.circl.lu/vuln/{id}` and can enrich published date, severity, and aliases ([#109](https://github.com/OpenTideHQ/opentide/issues/109)).
- `threat.cve` is a first-class optional list on the threat body, so schema validation accepts CVE identifiers. GNA 0 GCVE ids (`GCVE-0-YEAR-N`) map to the reserved CVE key.

### Changed

- Bundled `documentation.toml` `[cve]` defaults to Vulnerability-Lookup (`base_url` / `default_db_link`). Legacy NVD link prefixes are remapped. The CVE check stays **opt-in** (`--check cve`) so default `opentide validate` stays offline.

### Install

```bash
pip install opentide==0.2.1
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

## [0.2.0] — 2026-09-18

Minor on the public 0.1.8 beta. Upgrade if you generate templates or VS Code snippets — optional YAML now hugs `#` to each key, spacers stay blank, and rule `configurations` are commented platform stubs rather than `{}`.

### Changed

- `opentide generate templates` walks Pydantic `FieldInfo` instead of the JSON Schema `gen_template` walker. Optional sections are commented YAML blocks (`#` hugs each key; nested optionals are not commented again; spacer blanks stay blank), placeholders are typed (no `null`), nested bodies come from nested models, and rule `configurations` are commented platform stubs rather than `{}` ([#223](https://github.com/OpenTideHQ/opentide/issues/223)).
- VS Code snippet conversion treats commented nested keys as mapping children, so `configurations:` with only `#sentinel:` stubs is not turned into a tabstop.

### Install

```bash
pip install opentide==0.2.0
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

## [0.1.8] — 2026-09-16

Patch on the public 0.1.7 beta. Upgrade if first-time `setup` / `generate` logged missing object folders as errors, dumped YAML `null`, attached live children under `#key:` parents, skipped platform TOML from `setup repo --platform`, emitted Title-Case UUID documentation paths, or looked up `objective.priority` in `criticality::1.0`.

### Added

- VS Code snippets use `tide-threat` / `tide-objective` / `tide-rule` / `tide-<platform>` prefixes, `scope: yaml`, descriptions, and tabstops on empty scalars. Missing core or enabled-platform templates fail loud ([#194](https://github.com/opentidehq/opentide/issues/194)).
- `opentide setup vscode --mcp` writes `.vscode/mcp.json` through the existing MCP helper. Parent `--vscode-setup` still does not imply MCP ([#193](https://github.com/opentidehq/opentide/issues/193)).

### Fixed

- Absent `objects/{threats,objectives,rules}` folders log at **debug**, once per path. Paths that exist but are not a directory still log at **error** ([#212](https://github.com/OpenTideHQ/opentide/issues/212)).
- Optional template subtrees dumped as `#key:` now comment nested children, so `uuid` / `name` no longer attach to the previous mapping ([#209](https://github.com/OpenTideHQ/opentide/issues/209)).
- Generated templates skip `default: None` (no YAML `null`) and restore typed placeholders ([#210](https://github.com/OpenTideHQ/opentide/issues/210)).
- `opentide setup repo --platform` writes and enables `.opentide/configurations/platforms/*.toml`, so `generate` emits `#sentinel:` (and other) configuration stubs ([#211](https://github.com/OpenTideHQ/opentide/issues/211)).
- Objective documentation renders `priority` as the author string. It is not looked up in `criticality::1.0` ([#204](https://github.com/OpenTideHQ/opentide/issues/204)).
- GitHub/generic docs use lowercase `docs/{rules,objectives,threats}/<slug>.md`. UUID permalinks stay GitLab-only ([#203](https://github.com/OpenTideHQ/opentide/issues/203)).

### Install

```bash
pip install opentide==0.1.8
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

## [0.1.7] — 2026-09-16

Patch on the public 0.1.6 beta. Upgrade if VS Code YAML reported "Matches multiple schemas", generated templates hid required nested fields, `setup vscode` skipped snippets or crashed on a missing path, JSON validate stamped every check failed, or `invalid_ref` pointed at parent objects.

### Fixed

- `invalid_ref` is attributed to the leaf UUID field. JSON `validate` reports per-check `status` (`uuid`, `metadata`, `schema`, `vocab`, `query`, `references`). Vocabulary names skip YAML list indices ([#186](https://github.com/opentidehq/opentide/issues/186)).
- VS Code `yaml.schemas` maps each object folder recursively (`objects/threats/**/*.yaml`) instead of the `opentide.schema.json` router glob, so nested files keep editor association ([#185](https://github.com/opentidehq/opentide/issues/185)).
- MCP templates use `servers` for VS Code 1.102+ / Cursor, host-specific `OPENTIDE_REPO_ROOT` (`${workspaceFolder}` vs `${CLAUDE_PROJECT_DIR}`), `.vscode/extensions.json`, and `AGENTS.md` ([#188](https://github.com/opentidehq/opentide/issues/188)).
- Template `$ref` / `$defs` expansion inlines nested object bodies. Nested `required` lists are no longer inherited from the parent, so required nested fields stay uncommented ([#191](https://github.com/opentidehq/opentide/issues/191)).
- `opentide setup vscode` generates templates and schemas before writing snippets, and fails if snippets were requested but could not be written ([#192](https://github.com/opentidehq/opentide/issues/192)).
- `opentide setup vscode` creates a missing target directory before generate, so `chdir` no longer raises `FileNotFoundError` ([#200](https://github.com/opentidehq/opentide/pull/200)).

### Install

```bash
pip install opentide==0.1.7
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

## [0.1.6] — 2026-09-15

Patch on the public 0.1.5 beta. Upgrade if `opentide generate` crashed on unquoted YAML dates, or if interactive `opentide setup` crashed after choosing a CI provider.

### Fixed

- Unquoted `YYYY-MM-DD` values in `metadata.created` / `modified` no longer crash `opentide generate` with `TypeError: Object of type date is not JSON serializable`. The YAML loader stringifies timestamps so export JSON matches the schema's string dates ([#178](https://github.com/opentidehq/opentide/issues/178)).
- Interactive `opentide setup` no longer raises `ValueError: validate must be callable` on the CI workflow features checkbox. Optional Questionary checkboxes omit `validate` ([#177](https://github.com/opentidehq/opentide/issues/177)).

### Install

```bash
pip install opentide==0.1.6
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

## [0.1.5] — 2026-09-13

Patch on the public 0.1.4 beta. Upgrade if you regenerate ATT&CK or MISP vocabularies, or if you run the weekly ingest workflow.

### Added

- Weekly (and `workflow_dispatch`) ingest for MITRE ATT&CK STIX and MISP threat actors. Vocabularies merge with per-key RFC 0003 versions; schema pins for techniques, actors, and datasources bump in the same PRs. `uv run python scripts/vocabulary/sync_upstream.py --check|--apply`.

### Fixed

- ATT&CK groups are catalog-only (`att&ck.groups`); live objects pin them via `threat.actors.name` → `actors::*`. Ingest no longer reports pin bumps for vocabs that no pin file references (`att&ck.groups`, `mitigations`).
- Weekly ingest fetches `chore/vocab-upstream` before `git push --force-with-lease` so later cycles can update the specifications branch.

### Install

```bash
pip install opentide==0.1.5
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

## [0.1.4] — 2026-09-13

Patch on the public 0.1.3 beta. Upgrade if `opentide generate` crashed with `'str' object has no attribute 'get'` on `threat.actors`, or if you authored actors as vocabulary ID strings.

### Fixed

- `threat.actors` is a list of objects (`name` is a scoped actors-vocabulary ID such as `att&ck::G0006`; optional `sighting` and `references`), matching CoreTide. Generated JSON Schema no longer teaches `list[str]`. `opentide generate` no longer crashes calling `.get` on a string ([#172](https://github.com/opentidehq/opentide/issues/172)).
- Nested vocabulary fields (for example threat leverage / viability and objective composition) are validated against the pinned vocabs instead of being skipped.
- Explorer export uses timezone-aware UTC so the package imports on Python 3.10.

### Install

```bash
pip install opentide==0.1.4
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

## [0.1.3] — 2026-09-11

Patch on the public 0.1.2 beta. Upgrade if you ran `setup ci`, `deploy` / `validate query` locally, followed the tutorial, or installed without Azure/pandas extras.

### Fixed

- `opentide setup ci` emits parseable GitHub, GitLab, and Azure YAML. `textwrap.dedent` no longer strips indentation from already-indented step blocks ([#163](https://github.com/opentidehq/opentide/issues/163)).
- `opentide deploy` and `validate query` no longer crash locally when `DEPLOYMENT_PLAN` is unset. Unset or blank env defaults to `FULL`; illegal names fail with a clear error. Local debug compiles from the rules folder; PRODUCTION promotion is skipped for `--dry-run` and LocalDebug ([#164](https://github.com/opentidehq/opentide/issues/164)).
- Tutorial objects validate and lint: required `metadata.created` / `modified`, severity vocabulary, filenames matching `slugify(name)`, nested organisation and author. `setup` scaffolds `docs/Rules`, `docs/Objectives`, and `docs/Threats`. Templates emit `YYYY-MM-DD` dates. `generate docs` joins relative docs paths against the repository root ([#165](https://github.com/opentidehq/opentide/issues/165)).
- `opentide info` reports `can_deploy: true` after a base `pip install` (no Azure/pandas extras). Platforms lazy-load optional SDKs; `requests` is a core dependency. Tenant `[platform]` identity is not parsed as a detection-rule schema. Coverage counts top-level `techniques`. `generate extract` runs the installed package modules ([#166](https://github.com/opentidehq/opentide/issues/166)).

### Install

```bash
pip install opentide==0.1.3
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

## [0.1.2] — 2026-09-11

Patch on the public 0.1.1 beta. Upgrade if you scaffold new detection repos, generate on an empty catalogue, or install agent skills.

### Added

- Generated GitHub, GitLab, and Azure pipelines from `opentide setup ci` now set `OPENTIDE_REPO_ROOT` for every job (`github.workspace`, `$CI_PROJECT_DIR`, `$(Build.SourcesDirectory)`) ([#51](https://github.com/opentidehq/opentide/issues/51)).
- `opentide setup env` writes `.env.example` with `OPENTIDE_REPO_ROOT` and adds `.env` to `.gitignore` ([#48](https://github.com/opentidehq/opentide/issues/48)).
- `opentide setup hooks` writes a local pre-commit hook that runs `opentide validate --strict` and installs it into `.git/hooks` when the path is a Git repository ([#49](https://github.com/opentidehq/opentide/issues/49)).
- `opentide lint` reports filename slug mismatches (`slugify(name)`) and missing recommended metadata. `--fix` renames files; `--strict` is the CI gate ([#108](https://github.com/opentidehq/opentide/issues/108)).
- `opentide migrate objects` dry-runs (default) or applies (`--apply`) moves from CoreTide `Configurations/` and `Objects/` paths into `.opentide/configurations/` and `objects/` ([#100](https://github.com/opentidehq/opentide/issues/100)).

### Changed

- `opentide setup skills` discovers the catalogue from the live [OpenTideHQ/skills](https://github.com/OpenTideHQ/skills) `manifest.json` and installs skill trees from that repository. The wheel no longer ships a stale catalogue snapshot or starter `SKILL.md` files. If GitHub is unreachable, discover / show / install fail with an actionable error instead of installing outdated copies ([#152](https://github.com/opentidehq/opentide/issues/152)).

### Fixed

- `opentide generate` on a freshly scaffolded repository no longer crashes in snippet generation (`AttributeError: SimpleNamespace has no attribute 'subschemas'`). Platform templates are resolved from `platform_templates` (with a legacy `subschemas` alias), missing template files are skipped, and an empty object catalogue is treated as a valid export rather than an error ([#153](https://github.com/opentidehq/opentide/issues/153)).

### Install

```bash
pip install opentide==0.1.2
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

## [0.1.1] — 2026-09-11

Patch for the public 0.1.0 wheel. Upgrade if you installed from PyPI and hit `UnicodeDecodeError` on `validate` / `generate`, or if `opentide setup skills discover` started an install wizard.

### Fixed

- `opentide generate` and `opentide validate` no longer crash with `UnicodeDecodeError` when pip has compiled `__pycache__` next to bundled configuration TOMLs. Nested configuration directories load `*.toml` only (same class of fix as [#150](https://github.com/opentidehq/opentide/pull/150)).
- `opentide setup skills discover` and `show` are parsed as subcommands. A positional PATH on the skills group was consuming those names (and prompting for an install).
- Starter skill install (`opentide-detection-rule`, `detection-engineering`) falls back to the packaged skill trees when GitHub is unreachable.

### Install

```bash
pip install opentide==0.1.1
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

## [0.1.0] — 2026-09-09

First public release of the DetectionOps engine as a **PyPI package**. This is a beta (`Development Status :: 4 - Beta`), not a 1.0. The old engine and companion repos are archived; pinned CoreTide submodules still resolve.

### Added

- Install with `pip install opentide` (Python 3.10–3.14). One wheel: CLI (`opentide`), MCP server (`opentide-mcp`), SDK (`from opentide import OpenTide`), and seven platform adapters.
- `opentide setup` scaffolds a detection repository, CI (GitHub, GitLab, Azure DevOps), MCP client config, and agent skills.
- `opentide validate`, `generate`, `deploy`, and `document` as the operator surface. `--strict` is the CI gate.
- Query syntax validation on five platforms: Sentinel, Defender for Endpoint, Splunk, SentinelOne, Carbon Black Cloud. CrowdStrike and HarfangLab **deploy only** — the CLI and MCP report `supported: false` and do not fake a pass.
- Object model: threat → objective → rule, generated JSON Schema from the models, vocabularies as versioned TOML.
- Public companion repos: [specifications](https://github.com/OpenTideHQ/specifications), [library](https://github.com/OpenTideHQ/library), [explorer](https://github.com/OpenTideHQ/explorer), [skills](https://github.com/OpenTideHQ/skills). Docs: [opentide.org](https://opentide.org).

### Changed

- The engine is no longer consumed as a git submodule. Pin a package version instead of a SHA.
- Platform flags use `--platform` (not `--system`).

### Migration

There is no `opentide migrate`. Drop the CoreTide submodule, depend on this package, replace `Orchestration/` scripts with the CLI, set `OPENTIDE_REPO_ROOT`, run `opentide validate --strict`. Guide: [Usage → Migration](https://opentide.org/docs/usage/migration/).

### Stabilization

For four weeks after this release, work is bugs, docs, deployers, agent setup, and migration questions — not new platforms.

### Install

```bash
pip install opentide==0.1.0
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

[Unreleased]: https://github.com/OpenTideHQ/opentide/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/OpenTideHQ/opentide/releases/tag/v0.5.0
[0.4.0]: https://github.com/OpenTideHQ/opentide/releases/tag/v0.4.0
[0.3.0]: https://github.com/OpenTideHQ/opentide/releases/tag/v0.3.0
[0.2.1]: https://github.com/OpenTideHQ/opentide/releases/tag/v0.2.1
[0.2.0]: https://github.com/OpenTideHQ/opentide/releases/tag/v0.2.0
[0.1.8]: https://github.com/OpenTideHQ/opentide/releases/tag/v0.1.8
[0.1.7]: https://github.com/OpenTideHQ/opentide/releases/tag/v0.1.7
[0.1.6]: https://github.com/OpenTideHQ/opentide/releases/tag/v0.1.6
[0.1.5]: https://github.com/OpenTideHQ/opentide/releases/tag/v0.1.5
[0.1.4]: https://github.com/OpenTideHQ/opentide/releases/tag/v0.1.4
[0.1.3]: https://github.com/OpenTideHQ/opentide/releases/tag/v0.1.3
[0.1.2]: https://github.com/OpenTideHQ/opentide/releases/tag/v0.1.2
[0.1.1]: https://github.com/OpenTideHQ/opentide/releases/tag/v0.1.1
[0.1.0]: https://github.com/OpenTideHQ/opentide/releases/tag/v0.1.0
