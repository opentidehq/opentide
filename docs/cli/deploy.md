---
title: opentide deploy
description: Deploy detection rules to configured platforms with dry-run, promotion, and plan controls.
---

# opentide deploy

Deploy detection rules to configured platforms.

```bash
opentide deploy --platform sentinel --dry-run
opentide deploy --platform splunk --plan STAGING
```

## Options

| Flag | Env | Purpose |
|------|-----|---------|
| `--platform` | — | Target platform (see [platforms](../usage/concepts/platforms.md)) |
| `--plan` | `DEPLOYMENT_PLAN` | Deployment plan / strategy |
| `--tenant` | — | Tenant scope (recorded in result payload) |
| `--file` | — | Single-file scope (recorded in result payload) |
| `--wide` | — | Wide output |
| `--dry-run` | — | Simulate deployment without writes |
| `--keep-deprecated` | — | Include deprecated rules |
| `--skip-promotion` | — | Skip promotion step |

## Subcommands

### deploy metadata

Deploy Splunk metadata lookup table (platform-specific). Currently signals intent in logs — full metadata deployment integration is pending:

```bash
opentide deploy metadata --platform splunk
```

## Per-rule deployment via SDK or MCP

```python
rule = OpenTide.Rules[uuid]
result = rule.deploy("sentinel", dry_run=True)
```

MCP: `deploy_rule(uuid, platform, dry_run=True)` (defaults to dry-run).

## Source

`src/opentide/cli/__init__.py`, `src/opentide/cli/services/deploy.py`
