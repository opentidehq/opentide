---
title: opentide deploy
description: Deploy detection rules to configured platforms with dry-run, promotion, and plan controls.
---

# opentide deploy

Deploy detection rules to configured platforms, honoring each rule's `status` and your deployment plan.

```bash
opentide deploy --platform sentinel --dry-run
opentide deploy --platform splunk --plan STAGING
```

## When to use it

- On merge to `main` in CI, to push validated rules to a platform.
- Locally with `--dry-run` to preview exactly what a deploy would change.

Always `--dry-run` first, and always [validate](./validate.md) before deploying.

## Prerequisites

A real (non-dry-run) deploy contacts the platform API, so it needs:

1. The platform **enabled** in `.opentide/configurations/platforms/<name>.toml`.
2. **Credentials** for that platform, typically via environment variables referenced from the platform TOML — see [Configuration → credentials](../usage/configuration.md#credentials).

`--dry-run` needs neither and is safe to run anywhere.

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

## Output

```text
deploy (dry-run): sentinel
  Sentinel KQL Rule  STAGING  → would create/update
deploy: 1 rule planned, 0 applied (dry-run)
```

A real deploy reports created/updated/skipped counts. With `--json`, the payload includes `"ok"`, the target platform, and per-rule results. Non-zero [exit codes](./exit-codes.md) signal deployment errors.

## Subcommands

### deploy metadata

Deploy the Splunk metadata lookup table (platform-specific).

```bash
opentide deploy metadata --platform splunk
```

<Callout type="warn">
`deploy metadata` currently only signals intent in logs — full metadata deployment integration is pending. Do not rely on it to push lookup tables yet.
</Callout>

## Troubleshooting

- **Authentication error** — credentials missing/wrong; see [Troubleshooting](../usage/troubleshooting.md#deploy-fails-with-an-authentication-error).
- **A rule did not deploy** — check its `status` strategy; `INERT` statuses never deploy. See [Configuration → deployment statuses](../usage/configuration.md#deployment-statuses-and-strategies).
- **Platform not found** — it is not enabled in your workspace config.

## Per-rule deployment via SDK or MCP

```python
rule = OpenTide.Rules[uuid]
result = rule.deploy("sentinel", dry_run=True)
```

MCP: `deploy_rule(uuid, platform, dry_run=True)` (defaults to dry-run).

## Source

`src/opentide/cli/__init__.py`, `src/opentide/cli/services/deploy.py`
