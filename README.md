# opentide

[![PyPI](https://img.shields.io/pypi/v/opentide.svg)](https://pypi.org/project/opentide/)
[![Coverage](https://raw.githubusercontent.com/opentidehq/opentide/python-coverage-comment-action-data/badge.svg)](https://github.com/opentidehq/opentide/actions/workflows/ci.yml)

**opentide** — the DetectionOps engine for detection-as-code: validate, generate schemas, deploy rules, and document content across eight security platforms.

## Install

```bash
pip install opentide==0.17.2
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate
```

Release notes: [CHANGELOG.md](CHANGELOG.md) · [Usage → Releases](https://opentide.org/docs/usage/releases/)

## Documentation

Published docs: [opentide.org/docs/usage/](https://opentide.org/docs/usage/).

| Section | Audience |
|---------|----------|
| [Usage](https://opentide.org/docs/usage/) | Setup, workflows, migration |
| [CLI](https://opentide.org/docs/cli/) | Command reference |
| [MCP](https://opentide.org/docs/mcp/) | Agent server |
| [SDK](https://opentide.org/docs/sdk/) | Python API |

Source for those pages lives in [`docs/`](docs/) (Fumadocs). This repo validates content only: `scripts/validate-docs.sh`. The site is [opentidehq/website](https://github.com/opentidehq/website).

Contributors: see [`AGENTS.md`](AGENTS.md) and [`.agents/skills/docs-maintenance/SKILL.md`](.agents/skills/docs-maintenance/SKILL.md).

## Repository

[opentidehq/opentide](https://github.com/opentidehq/opentide) · Python 3.10–3.14 · Trunk: `development`
