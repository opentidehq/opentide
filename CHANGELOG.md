# Changelog

All notable changes to the `opentide` package are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Version numbers come from git tags via hatch-vcs.

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

[0.1.0]: https://github.com/OpenTideHQ/opentide/releases/tag/v0.1.0
