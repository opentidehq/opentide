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
opentide deploy --dry-run
```

`validate query --live` sends queries to the tenant. Pass `--file` or `--uuid` to check the rules you changed; without them it checks every rule in the catalogue. CI passes `--changed`, which checks the rules the pull request changed.

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
