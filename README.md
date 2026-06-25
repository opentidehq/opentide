# opentide

[![Coverage](https://raw.githubusercontent.com/OpenTideHQ/opentide/python-coverage-comment-action-data/badge.svg)](https://github.com/OpenTideHQ/opentide/actions/workflows/ci.yml)

**OpenTide** — the DetectionOps engine for detection-as-code: validate, generate schemas, deploy rules, and document content across seven security platforms.

## Install

```bash
pip install "opentide[sentinel,cli,mcp]>=0.1"
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate
```

## Documentation

| Section | Audience |
|---------|----------|
| [Usage](docs/usage/index.md) | Setup, workflows, migration |
| [CLI](docs/cli/index.md) | Command reference |
| [MCP](docs/mcp/index.md) | Agent server |
| [SDK](docs/sdk/index.md) | Python API |

Docs are structured for the [Fumadocs](docs/fumadocs/) site in [OpenTideHQ/website](https://github.com/OpenTideHQ/website). This repo validates content only: `scripts/validate-docs.sh`.

Contributors: see [`AGENTS.md`](AGENTS.md) and [`.agents/skills/docs-maintenance/SKILL.md`](.agents/skills/docs-maintenance/SKILL.md).

## Repository

[OpenTideHQ/opentide](https://github.com/OpenTideHQ/opentide) · Python 3.10–3.14 · Trunk: `development`
