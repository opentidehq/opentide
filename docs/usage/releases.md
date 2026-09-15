---
title: Releases
description: Public package versions of the OpenTide DetectionOps engine on PyPI.
---

# Releases

The engine is the [`opentide`](https://pypi.org/project/opentide/) package. Pin a version in CI. Source of truth for notes is [`CHANGELOG.md`](https://github.com/OpenTideHQ/opentide/blob/development/CHANGELOG.md) in the repository; GitHub Releases are tagged `v*` and publish to PyPI.

## 0.1.6 — 15 September 2026

Patch on 0.1.5. **Upgrade if `opentide generate` crashed on unquoted YAML dates, or if interactive `opentide setup` crashed after choosing a CI provider.**

**Install**

```bash
pip install opentide==0.1.6
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

**What this version fixes**

- Unquoted `created: 2026-09-11` metadata dates no longer crash generate JSON export (`Object of type date is not JSON serializable`).
- Interactive setup no longer raises `validate must be callable` on optional CI feature checkboxes.

**Links**

- [PyPI](https://pypi.org/project/opentide/0.1.6/)
- [GitHub Release](https://github.com/OpenTideHQ/opentide/releases/tag/v0.1.6)
- [CHANGELOG](https://github.com/OpenTideHQ/opentide/blob/development/CHANGELOG.md)

## 0.1.5 — 13 September 2026

Patch on 0.1.4. **Upgrade if you regenerate ATT&CK or MISP vocabularies, or if you run the weekly ingest workflow.**

**Install**

```bash
pip install opentide==0.1.5
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

**What this version adds**

- Weekly (and `workflow_dispatch`) ingest for MITRE ATT&CK STIX and MISP threat actors, with RFC 0003 per-key versions and matching schema pin bumps.

**What this version fixes**

- ATT&CK groups stay catalog-only; live objects pin G-ids through `threat.actors.name` → `actors::*`.
- Later ingest cycles fetch `chore/vocab-upstream` before `git push --force-with-lease`.

**Links**

- [PyPI](https://pypi.org/project/opentide/0.1.5/)
- [GitHub Release](https://github.com/OpenTideHQ/opentide/releases/tag/v0.1.5)
- [CHANGELOG](https://github.com/OpenTideHQ/opentide/blob/development/CHANGELOG.md)

## 0.1.4 — 13 September 2026

Patch on 0.1.3. **Upgrade if `opentide generate` crashed on `threat.actors`, or if you wrote actors as vocabulary ID strings.**

**Install**

```bash
pip install opentide==0.1.4
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

**What this version fixes**

- `threat.actors` is a list of objects (`name: att&ck::G0006`, optional `sighting` / `references`), not `list[str]`.
- `opentide generate` no longer raises `'str' object has no attribute 'get'` on those fields.
- Nested vocabulary fields are checked against the pinned vocabs.

**Links**

- [PyPI](https://pypi.org/project/opentide/0.1.4/)
- [GitHub Release](https://github.com/OpenTideHQ/opentide/releases/tag/v0.1.4)
- [CHANGELOG](https://github.com/OpenTideHQ/opentide/blob/development/CHANGELOG.md)

## 0.1.3 — 11 September 2026

Patch on 0.1.2. **Upgrade if you ran `setup ci`, deployed or validated queries locally, followed the tutorial, or installed without Azure/pandas extras.**

**Install**

```bash
pip install opentide==0.1.3
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

**What this version fixes**

- `opentide setup ci` emits parseable GitHub, GitLab, and Azure YAML.
- `opentide deploy` and `validate query` default `DEPLOYMENT_PLAN` to `FULL` when the env var is unset.
- Tutorial objects validate and lint; `generate docs` writes under the detection repository.
- `opentide info` reports `can_deploy: true` after a base `pip install`. Azure and pandas extras are not required for dry-run.

**Links**

- [PyPI](https://pypi.org/project/opentide/0.1.3/)
- [GitHub Release](https://github.com/OpenTideHQ/opentide/releases/tag/v0.1.3)
- [CHANGELOG](https://github.com/OpenTideHQ/opentide/blob/development/CHANGELOG.md)

## 0.1.2 — 11 September 2026

Patch on 0.1.1. **Upgrade if you scaffold new repos, generate an empty catalogue, or install agent skills.**

**Install**

```bash
pip install opentide==0.1.2
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

**What this version adds**

- `opentide setup ci` sets `OPENTIDE_REPO_ROOT` in generated GitHub, GitLab, and Azure pipelines.
- `opentide setup env` writes `.env.example`; `opentide setup hooks` installs validate-on-commit.
- `opentide lint` for filename slugs and recommended metadata (`--fix`, `--strict`).
- `opentide migrate objects` for CoreTide `Configurations/` and `Objects/` layouts.

**What this version changes**

- Skills install from the live OpenTideHQ/skills catalogue. GitHub must be reachable — there is no packaged fallback.

**What this version fixes**

- `opentide generate` completes on a freshly scaffolded empty repository.

**Links**

- [PyPI](https://pypi.org/project/opentide/0.1.2/)
- [GitHub Release](https://github.com/OpenTideHQ/opentide/releases/tag/v0.1.2)
- [CHANGELOG](https://github.com/OpenTideHQ/opentide/blob/development/CHANGELOG.md)

## 0.1.1 — 11 September 2026

Patch on the public 0.1.0 beta. **Upgrade if you installed 0.1.0 from PyPI.**

**Install**

```bash
pip install opentide==0.1.1
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

**What this version fixes**

- `opentide generate` and `opentide validate` no longer crash with `UnicodeDecodeError` after pip compiles `__pycache__` next to bundled configuration TOMLs.
- `opentide setup skills discover` and `show` run as subcommands instead of being treated as a repository path.
- Starter skills (`opentide-detection-rule`, `detection-engineering`) install from the packaged trees when GitHub is unreachable.

**Links**

- [PyPI](https://pypi.org/project/opentide/0.1.1/)
- [GitHub Release](https://github.com/OpenTideHQ/opentide/releases/tag/v0.1.1)
- [CHANGELOG](https://github.com/OpenTideHQ/opentide/blob/development/CHANGELOG.md)

## 0.1.0 — 9 September 2026

First public beta. Not 1.0.

**Install**

```bash
pip install opentide==0.1.0
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

Python **3.10–3.14**. One wheel: CLI, MCP (`opentide-mcp`), SDK, seven platform adapters. Enable platforms with `opentide setup platforms` — not with pip extras.

**What this version is**

- A version you can pin, instead of a CoreTide submodule SHA.
- `opentide setup` for repo, CI, MCP, and skills.
- Honest capability: seven platforms deploy; five validate query syntax (Sentinel, Defender, Splunk, SentinelOne, Carbon Black). CrowdStrike and HarfangLab are deploy-only.

**What it is not**

- A hard cut for existing instances. Pinned CoreTide checkouts keep resolving. Migrate when you next touch CI — [migration guide](./migration/index.md).
- A freeze forever. For **four weeks** after 0.1.0 the maintainers treat this as a support window: deployer bugs, docs, agent setup, migration questions. File issues on [OpenTideHQ/opentide](https://github.com/OpenTideHQ/opentide/issues).

**Links**

- [PyPI](https://pypi.org/project/opentide/0.1.0/)
- [GitHub Release](https://github.com/OpenTideHQ/opentide/releases/tag/v0.1.0)
- [Announcement](https://opentide.org/blog/the-engine-is-opentide/)
- [Installation](./installation.md)
