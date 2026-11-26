# opentide

[![PyPI](https://img.shields.io/pypi/v/opentide.svg)](https://pypi.org/project/opentide/)
[![CI](https://github.com/opentidehq/opentide/actions/workflows/ci.yml/badge.svg?branch=development)](https://github.com/opentidehq/opentide/actions/workflows/ci.yml)

**opentide** — spec-driven development for agentic detection engineering.

opentide gives every detection an ontology and a taxonomy, so it stays threat-aligned, maintainable and fast to ship, with or without agents. It validates objects, generates schemas, deploys rules, and documents content across thirteen security platforms: Microsoft Sentinel, Microsoft Defender, Splunk Enterprise Security, SentinelOne, CrowdStrike Falcon, HarfangLab, Carbon Black Cloud, Elastic Security, Sysdig Secure, Bitdefender GravityZone, Graylog, Exabeam New-Scale SIEM and Google Security Operations.

## Install

```bash
pip install opentide==1.1.0
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate
```

opentide 1.1.0 runs on one Rust core. The same release is on [crates.io](https://crates.io/crates/opentide) (`cargo install opentide --features cli`) and [npm](https://www.npmjs.com/package/@opentide/opentide) (`npm install @opentide/opentide`).

Release notes: [CHANGELOG.md](https://github.com/opentidehq/opentide/blob/development/CHANGELOG.md) · [Usage → Releases](https://opentide.org/docs/usage/releases/)

## Documentation

Published docs: [opentide.org/docs/usage/](https://opentide.org/docs/usage/).

| Section | Audience |
|---------|----------|
| [Usage](https://opentide.org/docs/usage/) | Setup, workflows, migration |
| [CLI](https://opentide.org/docs/cli/) | Command reference |
| [MCP](https://opentide.org/docs/mcp/) | Agent server |
| [SDK](https://opentide.org/docs/sdk/) | Python API |

Source for those pages lives in [`docs/`](https://github.com/opentidehq/opentide/tree/development/docs) (Fumadocs). This repo validates content only: `scripts/validate-docs.sh`. The site is [opentidehq/website](https://github.com/opentidehq/website).

Contributors: see [`AGENTS.md`](https://github.com/opentidehq/opentide/blob/development/AGENTS.md) and [`.agents/skills/docs-maintenance/SKILL.md`](https://github.com/opentidehq/opentide/blob/development/.agents/skills/docs-maintenance/SKILL.md).

## Repository

[opentidehq/opentide](https://github.com/opentidehq/opentide) · Python 3.10–3.14 · Trunk: `development`
