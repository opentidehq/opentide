---
title: Releases
description: Public package versions of the OpenTide DetectionOps engine on PyPI.
---

# Releases

The engine is the [`opentide`](https://pypi.org/project/opentide/) package. Pin a version in CI. Source of truth for notes is [`CHANGELOG.md`](https://github.com/OpenTideHQ/opentide/blob/development/CHANGELOG.md) in the repository; GitHub Releases are tagged `v*` and publish to PyPI.

## 0.1.2 — 11 September 2026

Patch on 0.1.1. **Upgrade if you scaffold new repos, generate an empty catalogue, or install agent skills.**

**Install**

```bash
pip install opentide==0.1.2
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

**What this version adds**

- `opentide setup ci` sets `OPENTIDE_REPO_ROOT` in generated GitHub, GitLab, and Azure pipelines ([#51](https://github.com/opentidehq/opentide/issues/51)).
- `opentide setup env` writes `.env.example`; `opentide setup hooks` installs validate-on-commit ([#48](https://github.com/opentidehq/opentide/issues/48), [#49](https://github.com/opentidehq/opentide/issues/49)).
- `opentide lint` for filename slugs and recommended metadata (`--fix`, `--strict`) ([#108](https://github.com/opentidehq/opentide/issues/108)).
- `opentide migrate objects` for CoreTide `Configurations/` and `Objects/` layouts ([#100](https://github.com/opentidehq/opentide/issues/100)).

**What this version changes**

- Skills install from the live [OpenTideHQ/skills](https://github.com/OpenTideHQ/skills) catalogue. GitHub must be reachable — there is no packaged fallback ([#152](https://github.com/opentidehq/opentide/issues/152)).

**What this version fixes**

- `opentide generate` completes on a freshly scaffolded empty repository ([#153](https://github.com/opentidehq/opentide/issues/153)).

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
