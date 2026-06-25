---
title: Detection-as-code
description: Authoring threat, objective, and rule objects with validate-generate-deploy workflow.
---

# Detection-as-code workflow

OpenTide treats detection content as versioned YAML objects with generated schemas, automated validation, and platform deployment.

## Object layout

| Object | Path | Purpose |
|--------|------|---------|
| Threat | `objects/threats/` | Threat vectors (TVM) |
| Objective | `objects/objectives/` | Detection objectives and signals |
| Rule | `objects/rules/` | MDR detection rules with platform queries |

Objects chain: **threat → objective → rule**. Use `opentide info` or MCP `get_chaining` to inspect relationships.

## Daily loop

```bash
# After editing YAML or bundled vocabularies
opentide generate                    # refresh schemas/templates if needed
opentide validate --strict           # schema, UUID, uniqueness, cross-object refs
opentide validate query --platform sentinel
opentide deploy --platform sentinel --dry-run
opentide generate docs                 # refresh wiki pages
```

## Authoring checklist

1. Set `metadata.schema` to the correct revision (e.g. `rule::1.0`).
2. Use generated templates from `.opentide/templates/` for new objects.
3. Run `opentide validate --file objects/rules/my-rule.yaml` while iterating.
4. Narrow validation with `--uuid` or `--type` for large repos.
5. Never skip query validation for platforms that support it before deploy.

## Status and promotion

Rules carry a `status` field (e.g. `STAGING`, `PRODUCTION`). Deployment respects visibility and promotion configuration under `.opentide/configurations/`.

Promotion runs inside `opentide deploy` before production deployment when configured — there is no separate `mutate promote` CLI command.

## Platform queries

Each rule may define platform-specific query blocks. Only **five platforms** support query syntax validation:

| Platform | Query language |
|----------|----------------|
| Sentinel | KQL |
| Defender for Endpoint | KQL |
| Splunk | SPL |
| SentinelOne | S1QL |
| Carbon Black Cloud | Lucene |

CrowdStrike and HarfangLab **deploy** but return `supported: false` for query validation — never fake a pass.

## Exports and coverage

```bash
opentide generate exports navigator
opentide generate exports revisions
opentide --json info --technique T1059 coverage
```

## Agent-assisted authoring

Configure MCP and skills so agents can search, validate, and dry-run deploy:

```bash
opentide setup mcp --cursor --yes
opentide setup skills --yes --generic
```

See [Agentic setup](./agentic-setup.md) and [MCP tools](../../mcp/tools.md).
