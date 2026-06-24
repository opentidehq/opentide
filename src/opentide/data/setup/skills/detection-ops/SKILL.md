---
name: opentide-detection-ops
description: >-
  Detection-as-code workflows with OpenTide — validate objects, generate schemas,
  deploy rules, and understand the threat/objective/rule model.
---

# OpenTide Detection Operations

Use this skill when authoring or reviewing detection content in an OpenTide repository.

## Object model

| Object | Path | Purpose |
|--------|------|---------|
| Threat | `Objects/Threat Vectors/` | Threat vectors (TVM) |
| Objective | `Objects/Detection Objectives/` | Detection objectives |
| Rule | `Objects/Detection Rules/` | MDR detection rules |

## Core commands

```bash
opentide validate
opentide generate
opentide validate query --platform sentinel
opentide deploy --platform sentinel --dry-run
```

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
3. Use `opentide setup mcp` and `opentide-mcp` for agent-assisted rule work.
