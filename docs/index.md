---
title: OpenTide
description: DetectionOps engine — validate, generate, deploy, and document detection rules across seven security platforms.
---

# OpenTide

OpenTide is the **DetectionOps engine** for detection-as-code repositories. Install it from PyPI, point it at your content repository, and use the CLI, MCP server, or Python SDK to validate objects, generate schemas, deploy rules, and publish documentation.

## Choose your path

| Section | Audience | Start here |
|---------|----------|------------|
| [Usage](./usage/index.md) | Detection engineers setting up and operating repos | [Installation](./usage/installation.md) |
| [CLI](./cli/index.md) | Operators and CI pipelines | [Global options](./cli/global-options.md) |
| [MCP](./mcp/index.md) | AI agents and editor integrations | [Installation](./mcp/installation.md) |
| [SDK](./sdk/index.md) | Python developers embedding OpenTide | [Registry API](./sdk/registry.md) |

## Quick start

```bash
pip install opentide
export OPENTIDE_REPO_ROOT=/path/to/detection-repo

opentide setup --yes --platform sentinel --ci github
opentide generate
opentide validate --strict
opentide deploy --platform sentinel --dry-run
```

## Platform coverage

OpenTide supports **seven deployment platforms** and **five query validators**. CrowdStrike and HarfangLab deploy but do not support query syntax validation — OpenTide never fakes validation for those platforms.

See [Platforms](./usage/concepts/platforms.md) for the capability matrix.

## Package surfaces

| Surface | Entry | Ships with |
|---------|-------|------------|
| CLI | `opentide` | `pip install opentide` |
| MCP server | `opentide-mcp` | `pip install opentide` |
| Python SDK | `from opentide import OpenTide` | `pip install opentide` |
| Platform adapters | entry points under `opentide.platforms` | `pip install opentide` |

## For doc site maintainers

This repository ships **Fumadocs-ready** content under `docs/`. See [docs/README.md](./README.md) and [docs/fumadocs/](./fumadocs/) for integration scaffolding when building the website repository.
