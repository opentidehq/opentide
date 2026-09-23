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
| `--wide` | — | Wide output |
| `--dry-run` | — | Simulate deployment without writes |
| `--keep-deprecated` | — | Include deprecated rules |
| `--skip-promotion` | — | Skip promotion step |

## Output

A dry-run in the [tutorial](../usage/tutorial.md) repository prints the section header on stderr and the result on stdout:

```bash
opentide deploy --platform sentinel --dry-run
```

```text output-of="opentide deploy --platform sentinel --dry-run"
== MDR Deployment ==
OK Deployment completed
```

A colour terminal draws the header as a rule. Human output does not list the rules; `DEBUG=1` logs each selected rule to stderr, and `--json` returns the plan:

```bash
opentide --json deploy --platform sentinel --dry-run
```

```json output-of="opentide --json deploy --platform sentinel --dry-run"
{
  "deployed": [],
  "dry_run": true,
  "plan": { "sentinel": ["00000000-0000-4000-8003-000000000001"] },
  "payloads": {
    "sentinel": [
      {
        "uuid": "00000000-0000-4000-8003-000000000001",
        "name": "Sentinel KQL Rule",
        "api_request": "..."
      }
    ]
  },
  "missing_tenants": {
    "sentinel": ".opentide/configurations/platforms/sentinel.toml"
  },
  "advice": "add (or uncomment) a [[tenants]] entry in .opentide/configurations/platforms/sentinel.toml",
  "ok": true,
  "status": "completed",
  "message": "Deployment completed",
  "warnings": [
    "sentinel has no tenants configured in .opentide/configurations/platforms/sentinel.toml, so a real deploy would stop"
  ]
}
```

`plan` lists the rule UUIDs selected for each platform. `payloads` is present on dry-runs only; each rule's `api_request` (elided here) is the request the Sentinel deployer compiles when the `sentinel` extra is installed, and otherwise the rule's platform configuration block. The [tutorial](../usage/tutorial.md) scaffold leaves `[[tenants]]` commented out, so this dry-run previews the payload, leaves `deployed` empty, and warns that a real deploy would stop. After you uncomment a tenant, `deployed` lists the platform and the warning is gone. A real deploy returns the same envelope with `"dry_run": false` and no `payloads`. Non-zero [exit codes](./exit-codes.md) signal deployment errors.

When no rules match the selected plan, the command reports `skipped` with exit `0`. The reserved `deploy metadata` command is hidden and returns a non-zero “not implemented” result rather than reporting false success.

## Subcommands

### deploy metadata

Reserved stub. Hidden from `--help`; it deploys nothing and exits `2` with “not implemented”:

```bash
opentide deploy metadata --platform splunk
opentide --json deploy metadata --platform splunk
```

```text output-of="opentide deploy metadata --platform splunk" exit=2
FATAL: Metadata deployment is not implemented for splunk
```

```json output-of="opentide --json deploy metadata --platform splunk" exit=2
{
  "error": "Metadata deployment is not implemented for splunk",
  "ok": false,
  "status": "failed",
  "message": "Metadata deployment is not implemented for splunk"
}
```

<Callout type="warn">
`deploy metadata` is not implemented. Do not rely on it to push lookup tables.
</Callout>

## Troubleshooting

- **Authentication error** — credentials missing/wrong; see [Troubleshooting](../usage/troubleshooting.md#deploy-fails-with-an-authentication-error).
- **A rule did not deploy** — check its `status` strategy; `INERT` statuses never deploy. See [Configuration → deployment statuses](../usage/configuration.md#deployment-statuses-and-strategies).
- **`WARNING … rule file(s) in subfolders of objects/rules are not deployed`** — a rule file has to sit directly in `objects/rules/`. A file in a subdirectory is outside the rule catalogue and is not deployed. Move it up into `objects/rules/` to deploy it. In CI, the warning names only the subdirectory files the change touched.
- **Platform not found** — it is not enabled in your workspace config.
- **`skipped` with no rules in a new repository** — git does not keep empty folders, so a fresh clone has no `objects/rules/` until the first rule is committed. Deploy treats the missing folder as an empty catalogue: it reports `skipped` with exit `0`, an empty `plan`, and the `dry_run` flag, and contacts no platform.
- **No tenants** — `setup repo` enables a platform and leaves the `[[tenants]]` example commented out. A real `deploy` of rules for that platform exits `1` before any engine loads, and names the file to edit. `--dry-run` still previews the payloads and warns that a real deploy would stop.

## Per-rule deployment via SDK or MCP

```python
rule = OpenTide.Rules[uuid]
result = rule.deploy("sentinel", dry_run=True)
```

MCP: `deploy_rule(uuid, platform, dry_run=True)` (defaults to dry-run).

## Source

`src/opentide/cli/__init__.py`, `src/opentide/cli/services/deploy.py`
