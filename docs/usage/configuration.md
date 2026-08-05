---
title: Configuration
description: What lives in .opentide/configurations/ — enabling platforms, credentials, deployment statuses, promotion, and visibility.
---

# Configuration

OpenTide ships sensible defaults inside the package. Your repository customises them under `.opentide/configurations/`. This guide is the practical tour of that directory; the normative merge rules live in the [Configuration spec](/docs/specifications/specs/configuration/).

## How configuration is layered

OpenTide deep-merges configuration from several sources. Later layers win; nested tables merge, scalars replace.

```mermaid
flowchart LR
  bundled["1 · Package defaults<br/>(bundled in the wheel)"] --> platforms["2 · Bundled platform configs"]
  platforms --> client["3 · Your workspace<br/>.opentide/configurations/"]
  client --> parent["4 · Parent instance<br/>(nested workspaces)"]
```

You only ever edit **layer 3** — your workspace. You override just the keys you care about; everything else falls through to the package defaults.

```
.opentide/configurations/
├── paths.toml              # workspace directory layout
├── deployment.toml         # statuses + promotion
├── schema.toml             # template defaults, vocabulary extensions
├── visibility.toml         # what is exposed/deployed
├── documentation.toml      # `opentide generate docs` settings
└── platforms/
    ├── sentinel.toml
    └── splunk.toml
```

<Callout type="warn">
Do not put vocabulary files here. Vocabularies are canonical in the [specifications](/docs/specifications/specs/vocabularies/format/); extend them through `schema.toml`, never by copying `.vocab.toml` files.
</Callout>

## Enabling a platform

A platform is loaded only when it is enabled in your workspace config. Create one file per platform under `platforms/`:

```toml
# .opentide/configurations/platforms/sentinel.toml
[platform]
enabled = true
```

Confirm what the engine actually loaded:

```bash
opentide info
opentide --json info --platform sentinel
```

See [Platforms](./concepts/platforms.md) for the capability matrix and the exact `--platform` identifiers.

## Credentials

Deploying rules or running live query checks needs platform credentials. Keep secrets out of the repo — reference environment variables from the platform TOML and inject them at runtime (locally via a `.env` you never commit, in CI via secrets).

```toml
# .opentide/configurations/platforms/sentinel.toml
[platform]
enabled = true

[[tenants]]
name = "Primary"
description = "Production Sentinel workspace"
deployment = "ALWAYS"

[tenants.setup]
resource_group = "rg-soc"
workspace_name = "soc-sentinel"
workspace_id = "$AZURE_WORKSPACE_ID"
azure_tenant_id = "$AZURE_TENANT_ID"
azure_subscription_id = "$AZURE_SUBSCRIPTION_ID"
azure_client_id = "$AZURE_CLIENT_ID"
azure_client_secret = "$AZURE_CLIENT_SECRET"
```

<Callout type="info">
Exact connection keys differ per platform. Use `opentide info --platform <name>` to see what a platform expects, and never commit real secrets — see [CI/CD](./workflows/ci-cd.md#secrets) for injecting them in pipelines.
</Callout>

If you sit behind an outbound proxy, configure it in `deployment.toml`:

```toml
[proxy]
proxy_host = "proxy.internal"
proxy_port = 8080
proxy_user = "${PROXY_USER}"          # optional; enables authenticated proxy
proxy_password = "${PROXY_PASSWORD}"
```

## Deployment statuses and strategies

Every rule's `status` must match a status defined in the merged `deployment.toml`. That is the only constraint — statuses are a configurable set, not a fixed lifecycle, and OpenTide does not enforce an order between them. OpenTide ships this set out of the box:

| Status | Strategy | What it does |
|--------|----------|--------------|
| `DESIGN` | `INERT` | Functional design only — never deployed |
| `DEVELOPMENT` | `PREVIEW` | Under technical implementation |
| `IMPROVING` | `PREVIEW` | Qualified, being refined |
| `STAGING` | `PREVIEW` | Deployed to staging for operational testing |
| `ACCEPTANCE` | `PREVIEW` | Production-ready; analyst validating alert + playbook |
| `PRODUCTION` | `RELEASE` | Live production deployment |
| `DISABLED` | `DISABLEMENT` | Present but inactive |
| `REMOVED` | `DELETION` | Removed from platforms |

The **strategy** decides how `deploy` treats a rule: `INERT` never deploys, `PREVIEW` targets staging, `RELEASE` goes to production, `DISABLEMENT`/`DELETION` tear down. You can add or rename statuses by overriding `deployment.toml`:

```toml
# .opentide/configurations/deployment.toml
[[statuses]]
name = "PILOT"
description = "Limited rollout to a pilot workspace"
strategy = "PREVIEW"
```

Full field contract: [Deployment spec](/docs/specifications/specs/deployment/).

## Promotion

Promotion rewrites a rule's status directly to `promotion_target` — it is a single jump, not a step through intermediate statuses.

```toml
# .opentide/configurations/deployment.toml
[promotion]
enabled = true
promotion_target = "PRODUCTION"
```

There is no separate promote command. Edit a rule's `status` in YAML for deliberate changes, then run `opentide deploy` — when promotion is enabled, deploy applies the promotion target to every status whose strategy is not `RELEASE`, `DISABLEMENT`, or `DELETION`. See [`deploy`](../cli/deploy.md) and the [detection-as-code workflow](./workflows/detection-as-code.md#status-and-deployment-strategy).

## Deployment plan

The `DEPLOYMENT_PLAN` environment variable selects which plan `deploy` and `validate query` operate under, letting you keep separate plans (e.g. per environment) without editing config:

```bash
export DEPLOYMENT_PLAN=production
opentide deploy --platform sentinel
```

See [CLI global options](../cli/global-options.md) for how it resolves.

## Visibility and documentation

- `visibility.toml` controls which objects are exposed/deployed in a given context; it is validated by a generated `visibility` schema.
- `documentation.toml` tunes `opentide generate docs` output (which folders, which sections). See [`generate docs`](../cli/generate.md).

## Paths

`paths.toml` overrides the default workspace layout (where `objects/`, `docs/`, and `.opentide/` live). Most repos never touch it; the defaults are described in the [Workspace spec](/docs/specifications/specs/workspace/).

## Related

- [Configuration spec](/docs/specifications/specs/configuration/) — normative merge order and file contract.
- [Repository setup](./repository-setup.md) — how `opentide setup` scaffolds this directory.
- [Troubleshooting](./troubleshooting.md) — "unknown status", "platform not loaded", and other config errors.
