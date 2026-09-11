# Changelog

All notable changes to the `opentide` package are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Version numbers come from git tags via hatch-vcs.

## [Unreleased]

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

[Unreleased]: https://github.com/OpenTideHQ/opentide/compare/v0.1.2...HEAD
[0.1.2]: https://github.com/OpenTideHQ/opentide/releases/tag/v0.1.2
[0.1.1]: https://github.com/OpenTideHQ/opentide/releases/tag/v0.1.1
[0.1.0]: https://github.com/OpenTideHQ/opentide/releases/tag/v0.1.0
