# Changelog

All notable changes to the `opentide` package are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Version numbers come from git tags via hatch-vcs.

## [Unreleased]

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

[Unreleased]: https://github.com/OpenTideHQ/opentide/compare/v0.2.1...HEAD
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
