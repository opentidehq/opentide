---
title: Releases
description: Public package versions of the OpenTide DetectionOps engine on PyPI.
---

# Releases

The engine is the [`opentide`](https://pypi.org/project/opentide/) package. Pin a version in CI. Source of truth for notes is [`CHANGELOG.md`](https://github.com/OpenTideHQ/opentide/blob/development/CHANGELOG.md) in the repository; GitHub Releases are tagged `v*` and publish to PyPI.

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
