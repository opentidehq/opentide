---
title: Configuration
description: What lives in .opentide/configurations/ — enabling platforms, credentials, deployment statuses, promotion, and visibility.
---

# Configuration

opentide ships sensible defaults inside the package. Your repository customises them under `.opentide/configurations/`. This guide is the practical tour of that directory; the normative merge rules live in the [Configuration spec](/docs/specifications/specs/configuration/).

## How configuration is layered

opentide deep-merges configuration from several sources. Later layers win; nested tables merge, scalars replace.

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
├── schema.toml             # template defaults
├── visibility.toml         # what is exposed/deployed
├── documentation.toml      # `opentide generate docs` settings
└── platforms/
    ├── sentinel.toml
    └── splunk.toml
```

<Callout type="warn">
Do not put vocabulary files here, and do not try to extend a vocabulary locally. Vocabularies are canonical in the [specifications](/docs/specifications/specs/vocabularies/format/) and are **not** locally extensible: a missing entry is added upstream, never injected from your repository. The CoreTIDE-era `[vocabulary]` block in `schema.toml` was removed in 0.13.0 — if you carried one, it was silently ignored by validation and is now simply dropped.

`threat.surface` is covered by that rule like every other vocabulary. Earlier releases harvested an extra surface value from a `visibility.toml` asset that named a technology, so an instance could effectively invent one; that no longer happens, and it was never a supported mechanism. A technology the catalogue does not yet name is [proposed upstream](https://github.com/opentidehq/specifications) — which is what makes a surface value mean the same thing in every opentide instance. Where a local system needs naming, the asset itself is the place for it.

Two fields are deliberately **not** vocabularies, because their values are per-organisation rather than shared: `response.responders` (your alert handling teams) and `configurations.<platform>.status` (your deployment statuses). Both are *configuration enums* — you declare the allowed values in `deployment.toml`, the generated schema offers them in your editor, and `validate` holds authored objects to them. Declaring none leaves the field unconstrained.
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

If you sit behind an outbound proxy, pass it on the command, or set `OPENTIDE_PROXY`. Either wins over `HTTP_PROXY` and `HTTPS_PROXY`; omitting both leaves those variables as they are. Hosts listed in `NO_PROXY` are still reached directly, so an internal tenant can bypass the proxy that a cloud tenant needs ([global options](../cli/global-options.md#proxy)). The same retirement covers platform tenant config, not only `[cve].proxy`: a `proxy` key under `[tenants.setup]` or in `deployment.toml` `[proxy]` fails the command and names `opentide --proxy`.

```bash
opentide --proxy http://user:pass@proxy.internal:8080 validate --strict
```

## Deployment statuses and strategies

Every rule's `status` must match a status defined in the merged `deployment.toml`. That is the only constraint — statuses are a configurable set, not a fixed lifecycle, and opentide does not enforce an order between them. opentide ships this set out of the box:

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

`opentide setup --no-promotion` or `--promotion-target <STATUS>` writes this table, with or without `--ci`; see [setup](../cli/setup.md#default-callback-flags).

There is no separate promote command. Edit a rule's `status` in YAML for deliberate changes, then run `opentide deploy` — when promotion is enabled, deploy applies the promotion target to every status whose strategy is not `RELEASE`, `DISABLEMENT`, or `DELETION`. See [`deploy`](../cli/deploy.md) and the [detection-as-code workflow](./workflows/detection-as-code.md#status-and-deployment-strategy).

## Deployment plan

Three words sound alike and mean different things:

| Term | What it is | Who defines it | Examples |
|------|------------|----------------|----------|
| **Status** | A rule block's lifecycle label (`status:` in the YAML) | You, in `deployment.toml` `[[statuses]]` | `DEVELOPMENT`, `STAGING`, `PRODUCTION` |
| **Strategy** | What deploy does with a rule in that status | The [deployment spec](/docs/specifications/specs/deployment/): fixed | `INERT`, `PREVIEW`, `RELEASE`, `DISABLEMENT`, `DELETION` |
| **Plan** | Which pipeline a run is, chosen with `--plan` or `DEPLOYMENT_PLAN` | The deployment spec: fixed | `STAGING`, `PRODUCTION`, `FULL` |

A plan is not a status. It names a pipeline, and selects rules by the **strategy** of their status, never by the status name:

| Plan | Pipeline | Rule files read | Deploys rules whose strategy is | To tenants whose `deployment` is |
|------|----------|-----------------|---------------------------------|----------------------------------|
| `STAGING` | Pull or merge request | Those the request changed | `PREVIEW` (and `UNIVERSAL`) | `STAGING`, `ALWAYS`, or `MANUAL` when the rule lists it |
| `PRODUCTION` | Push to the default branch | Those the push changed | `RELEASE`, `DISABLEMENT`, `DELETION` (and `UNIVERSAL`) | `PRODUCTION`, `ALWAYS`, or `MANUAL` when the rule lists it |
| `FULL` | Any; the default outside CI | Every rule file | `PREVIEW`, `RELEASE` (and `UNIVERSAL`); `DISABLEMENT` and `DELETION` only with `--keep-deprecated` | `ALWAYS`, or `MANUAL` when the rule lists it |

`PRODUCTION` disables and deletes the `DISABLEMENT` and `DELETION` rules unless you pass `--drop-deprecated`; `FULL` leaves them out unless you pass `--keep-deprecated`, so a full redeploy does not retire your archived rules by accident.

So with the bundled statuses, `--plan STAGING` deploys a rule in `DEVELOPMENT`, `IMPROVING`, `STAGING` or `ACCEPTANCE` (all `PREVIEW`) and skips one in `PRODUCTION` (`RELEASE`). If you add a status named `CANARY` with strategy `PREVIEW`, `--plan STAGING` deploys it too; the plan names never have to match your status names. The tenant `deployment` key uses the plan names: a `STAGING` tenant receives the `STAGING` plan's deploys.

`PREVIEW` and `RELEASE` are not plan names. `opentide deploy --plan PREVIEW` fails and names the plan that deploys `PREVIEW` rules. A skipped rule's `mdr_skipped_for_plan` log line names its status, its strategy and the strategies the plan deploys.

`validate query --live` reads the same plans, with one difference: it only reads, so under `FULL` it checks every tenant a rule can reach, `STAGING` and `PRODUCTION` included ([which tenants are checked](../cli/validate.md#which-tenants-are-checked)). A bare `validate query` refuses and does not read the plan.

`DEPLOYMENT_PLAN` sets the plan when `--plan` is omitted:

```bash
export DEPLOYMENT_PLAN=production
opentide deploy --platform sentinel
```

See [CLI global options](../cli/global-options.md) for how it resolves.

## Visibility and documentation

- `visibility.toml` controls which objects are exposed/deployed in a given context; it is validated by a generated `visibility` schema.
- `documentation.toml` tunes `opentide generate docs` output (which folders, which sections). CVE links and optional API enrichment use [CIRCL Vulnerability-Lookup](https://vulnerability.circl.lu); see [`generate docs`](../cli/generate.md).

## Paths

`paths.toml` overrides the default workspace layout (where `objects/`, `docs/`, and `.opentide/` live). Most repos never touch it; the defaults are described in the [Workspace spec](/docs/specifications/specs/workspace/).

## Related

- [Configuration spec](/docs/specifications/specs/configuration/) — normative merge order and file contract.
- [Repository setup](./repository-setup.md) — how `opentide setup` scaffolds this directory.
- [Troubleshooting](./troubleshooting.md) — "unknown status", "platform not loaded", and other config errors.
