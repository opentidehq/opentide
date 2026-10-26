---
name: opentide-detection-ops
description: >-
  Detection-as-code workflows with opentide — validate objects, generate schemas,
  deploy rules, and understand the threat/objective/rule model.
---

# opentide Detection Operations

Use this skill when authoring or reviewing detection content in an opentide repository.

## Object model

| Object | Path | Purpose |
|--------|------|---------|
| Threat | `objects/threats/` | Threat vectors (TVM) |
| Objective | `objects/objectives/` | Detection objectives |
| Rule | `objects/rules/` | MDR detection rules |

## Core commands

```bash
opentide validate
opentide generate
opentide validate query --platform sentinel --live --file objects/rules/<rule>.yaml
opentide deploy --dry-run --strategy PREVIEW --all
```

`validate query --live` sends queries to the tenant. Pass `--file` or `--uuid` to check the rules you changed; without them it checks every rule in the catalogue. CI passes `--changed`, which checks the rules the pull request changed.

`deploy --strategy PREVIEW` deploys rules whose status maps to `PREVIEW` (default `DEVELOPMENT`, `IMPROVING`, `STAGING`, `ACCEPTANCE`); `--strategy RELEASE` deploys those mapping to `RELEASE` (default `PRODUCTION`) and disables or deletes those mapping to `DISABLEMENT` or `DELETION`. `STAGING` and `PRODUCTION` are status names, not strategies. Each rule goes to the tenants whose `strategies` accept the run's strategy. Without `--all`, deploy reads the rules the last commit changed (in CI: the pull request or push).

## Platform capabilities

| Platform | Deploy | Query validate |
|----------|:------:|:--------------:|
| Sentinel | yes | KQL |
| Defender | yes | KQL |
| Splunk | yes | SPL |
| SentinelOne | yes | S1QL |
| Carbon Black | yes | Lucene |
| CrowdStrike | yes | no |
| HarfangLab | yes | no |

Never fake query validation for CrowdStrike or HarfangLab.

## Workflow

1. Run `opentide generate` after changing bundled vocabularies or when schemas are missing.
2. Validate before deploy: `opentide validate --strict`.
3. Use `opentide setup mcp` and `opentide mcp start` for agent-assisted rule work.

## Running opentide as an agent

Add `--json` to every command: stdout is then one JSON document.

```bash
opentide --json commands                                   # every command, option and an example
opentide --json validate --file objects/rules/<rule>.yaml
opentide explain <code>
```

- Branch on the exit code first: `0` success; `1` failure; `2` usage error or a check that could not run; `3` partial `share`. Then read `failure.code` for the detail, for example `issues_found` or `command_failed` on `1`, `usage_invalid_choice` (with `failure.suggestion`) or `no_tenant_reached` on `2`.
- Each finding (`report.issues` from `validate`, `findings` from `lint`) has `code`, `path`, `line`, `column`, `end_column` (1-based, end exclusive), `help` and `fix`. Each of `fix.edits` replaces the text from (`line`, `column`) up to (`end_line`, `end_column`) with `replacement`; apply `safe: true` edits as they are (they only respell the same word) and check the others against `help`. For a finding with no fix, `opentide explain <code>` says what it means and how to fix it.
- Follow `next_actions`: `[{command, reason}]`.
- Loop: search (`opentide --json info coverage --technique <id>`), draft, `opentide --json validate --file <file>` until `ok` is `true`, then `opentide --json deploy --dry-run --strategy PREVIEW --all`. People review, merge and deploy.
