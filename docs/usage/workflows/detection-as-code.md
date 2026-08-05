---
title: Detection-as-code
description: The day-to-day loop for authoring, reviewing, promoting, and deploying detection objects.
---

# Detection-as-code

This is the workflow you live in after onboarding: author objects, validate, review, promote, deploy. If you have not built a chain yet, do the [Tutorial](../tutorial.md) first — this page assumes you understand the [object model](../concepts/object-model.md).

## The daily loop

```mermaid
flowchart LR
  edit["Edit YAML"] --> gen["generate<br/>(if schemas changed)"]
  gen --> val["validate --strict"]
  val --> q["validate query"]
  q --> pr["Open PR → CI gate"]
  pr --> deploy["deploy staging"]
  deploy --> promote["promote → production"]
```

```bash
opentide generate                          # only when schemas/templates changed
opentide validate --strict                 # schema, UUID, uniqueness, chaining
opentide validate query --platform sentinel
opentide deploy --platform sentinel --dry-run
opentide generate docs                          # refresh wiki pages
```

While iterating on a single file, keep the loop tight:

```bash
opentide validate --file objects/rules/my-rule.yaml
```

For large repos, narrow with `--uuid` or `--type` so you validate only what you touched.

## Authoring a good object

Beyond passing validation, good objects are *reviewable* and *chained*.

### Start from a template

New objects should start from the generated templates so required fields and structure are correct:

```bash
cp .opentide/templates/rule.1.0.template.yaml objects/rules/my-rule.yaml
```

### Fill fields with meaning, not placeholders

- **`metadata.schema`** — the correct revision (`rule::1.0`). See [Schema revision](../concepts/schema-revision.md).
- **`metadata.uuid`** — a freshly generated UUID, never copied.
- **`description`** — what the detection catches and why, in a sentence a reviewer can judge.
- **`severity` / `response.alert_severity`** — drawn from the severity [vocabulary](/docs/specifications/specs/vocabularies/catalog/).
- **`techniques` / `att&ck`** — the ATT&CK techniques this addresses; these power coverage reporting.

### Chain it

A rule that references no objective is an [orphan](../concepts/object-model.md#anti-patterns-to-avoid). Point `detection_model` at the objective it implements, and make sure that objective references the threat it covers under `objective.threats`. Verify:

```bash
opentide info
opentide --json info --technique T1059 coverage
```

### Map fields to vocabularies

Fields like `severity`, `impact`, `surface`, `methodology`, and `att&ck` draw their allowed values from published [vocabularies](/docs/specifications/specs/vocabularies/catalog/). (`terrain` is free-form prose, not a vocabulary.) Using a value outside the vocabulary fails validation — check the catalog when unsure.

## Status lifecycle

Every rule has a `status` that drives whether and how it deploys. The bundled lifecycle:

```mermaid
flowchart LR
  DESIGN --> DEVELOPMENT --> IMPROVING --> STAGING --> ACCEPTANCE --> PRODUCTION
  PRODUCTION --> DISABLED --> REMOVED
```

| Phase | Statuses | Deploys? |
|-------|----------|----------|
| Design | `DESIGN` | No (`INERT`) |
| Build & refine | `DEVELOPMENT`, `IMPROVING`, `STAGING`, `ACCEPTANCE` | Staging (`PREVIEW`) |
| Live | `PRODUCTION` | Production (`RELEASE`) |
| Retire | `DISABLED`, `REMOVED` | Disable / delete |

A rule's `status` must exist in your merged `deployment.toml` — see [Configuration → deployment statuses](../configuration.md#deployment-statuses-and-strategies).

## Promotion

Move rules up the lifecycle when they are ready. Edit the rule's `status` in YAML (and commit it), then deploy. When `[promotion]` is enabled in `deployment.toml`, `opentide deploy` applies the configured `promotion_target` as part of the deployment flow — there is no separate `mutate promote` command.

```bash
# after reviewing and bumping status in YAML
opentide deploy --platform sentinel --dry-run
opentide deploy --platform sentinel
```

See [`deploy`](../../cli/deploy.md) and [Configuration → promotion](../configuration.md#promotion).

## Platform queries

Each rule carries per-platform query blocks under `configurations`. Five platforms support **query syntax validation**; two are deploy-only:

| Platform | Query language | Query validate |
|----------|----------------|:--------------:|
| Sentinel | KQL | yes |
| Defender for Endpoint | KQL | yes |
| Splunk | SPL | yes |
| SentinelOne | S1QL | yes |
| Carbon Black Cloud | Lucene | yes |
| CrowdStrike | — | no (deploy only) |
| HarfangLab | — | no (deploy only) |

Always run `opentide validate query --platform <name>` for supporting platforms before deploy. OpenTide reports `supported: false` for CrowdStrike/HarfangLab rather than faking a pass — see [Platforms](../concepts/platforms.md).

## Review checklist

Use this in pull-request reviews:

1. Does `validate --strict` pass? (CI enforces it — see [CI/CD](./ci-cd.md).)
2. Is the rule chained to an objective, and the objective to a threat?
3. Are `severity`, `att&ck`, and vocabulary fields meaningful and valid?
4. Is `status` appropriate for the change (not accidentally `PRODUCTION`)?
5. For supported platforms, does query validation pass?
6. Is `metadata.version` bumped if the detection logic changed?

## Exports and coverage

```bash
opentide generate exports navigator
opentide generate exports revisions
opentide --json info --technique T1059 coverage
```

See [`generate exports`](../../cli/generate.md).

## Agent-assisted authoring

Agents can run the same loop through MCP. Configure once:

```bash
opentide setup mcp --cursor --yes
opentide setup skills --yes --generic
```

Then see [Agentic setup](./agentic-setup.md) for a safe agent workflow and its limits.
