---
name: opentide-detection-workflow
description: >-
  Detection-as-code workflows with opentide — validate objects, generate schemas,
  deploy rules, and understand the threat/objective/rule model.
---

# opentide detection workflow

Use this skill when authoring or reviewing detection content in an opentide repository.

## Object model

| Object | Path | Purpose |
|--------|------|---------|
| Threat | `objects/threats/` | Threat vectors (TVM) |
| Objective | `objects/objectives/` | Detection objectives |
| Rule | `objects/rules/` | Detection rules |

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
| Elastic | yes | Kuery, Lucene, EQL, ES\|QL |
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
