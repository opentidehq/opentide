# opentide

[![Coverage](https://raw.githubusercontent.com/OpenTideHQ/opentide/python-coverage-comment-action-data/badge.svg)](https://github.com/OpenTideHQ/opentide/actions/workflows/ci.yml)

**OpenTide** — the DetectionOps engine for detection-as-code: validate, generate schemas, deploy rules, and document content across seven security platforms.

## Install

```bash
pip install opentide
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate
```

## Documentation

Published docs: [opentide.org/docs/usage/](https://opentide.org/docs/usage/).

| Section | Audience |
|---------|----------|
| [Usage](https://opentide.org/docs/usage/) | Setup, workflows, migration |
| [CLI](https://opentide.org/docs/cli/) | Command reference |
| [MCP](https://opentide.org/docs/mcp/) | Agent server |
| [SDK](https://opentide.org/docs/sdk/) | Python API |

Source for those pages lives in [`docs/`](docs/) (Fumadocs). This repo validates content only: `scripts/validate-docs.sh`. The site is [OpenTideHQ/website](https://github.com/OpenTideHQ/website).

Contributors: see [`AGENTS.md`](AGENTS.md) and [`.agents/skills/docs-maintenance/SKILL.md`](.agents/skills/docs-maintenance/SKILL.md).

## Repository

[OpenTideHQ/opentide](https://github.com/OpenTideHQ/opentide) · Python 3.10–3.14 · Trunk: `development`
