---
title: Glossary
description: Definitions for the OpenTide terms and acronyms used throughout the docs.
---

# Glossary

The terms and acronyms you will meet across the OpenTide docs, defined once. Where a concept has a deeper page, it is linked.

## Objects and content

**Object**
: A typed unit of detection content — a threat, objective, or rule — stored as YAML under `objects/`. Every object carries a `metadata` block. See [Object model](./object-model.md).

**Threat (TVM — Threat Vector Model)**
: A description of *what you defend against*: an actor, technique, or attack surface, with impact and viability ratings. Schema identifier `threat::1.0`.

**Objective (DOM — Detection Objective Model)**
: A *detection goal* and the **signals** that satisfy it. An objective references the threats it covers. Schema identifier `objective::1.0`.

**Rule (MDR — Managed Detection Rule)**
: A *deployable detection*, carrying per-platform query configurations and a status. A rule references the objective it implements via `detection_model`. Schema identifier `rule::1.0`.

**Signal**
: A discrete piece of evidence inside an objective (e.g. "suspicious logon"), with methodology, entities, and data requirements.

**Chaining**
: The reference graph between objects. Rules point at objectives (`detection_model`); objectives point at threats (`objective.threats`). Coverage flows the opposite way: threats are covered by objectives, which are implemented by rules. See [Object model](./object-model.md#chaining).

**Coverage**
: What detection exists for a given threat or ATT&CK technique, derived by walking the chaining graph. Reported by `opentide info` and `generate docs`.

## Versioning and schema

**Schema revision (`metadata.schema`)**
: The structural revision an object conforms to, e.g. `rule::1.0`. Selects the validation model and generated JSON Schema. See [Schema revision](./schema-revision.md).

**Instance version (`metadata.version`)**
: The business/semantic version of a specific object's content. Git is the authoritative change history. Never used to pick a schema file.

**UUID**
: The stable identifier for an object. Cross-object references use UUIDs, so renaming or moving files never breaks the graph.

**Vocabulary**
: A canonical, controlled list of allowed values for a field (e.g. severities, ATT&CK techniques, TLP levels), published in the [specifications](/docs/specifications/specs/vocabularies/catalog/) and bundled with OpenTide.

## Deployment and operations

**Platform**
: A SIEM or EDR target OpenTide deploys to (e.g. Sentinel, Splunk, CrowdStrike). Some platforms also support query validation. See [Platforms](./platforms.md).

**Status**
: A rule's deployment state, e.g. `STAGING` or `PRODUCTION`. Deployment respects status and your promotion configuration.

**Staging**
: Deploying rules in a non-production state for verification before they go live.

**Promotion**
: Advancing rules from a lower status to a higher one (typically `STAGING → PRODUCTION`), individually or in bulk via `opentide deploy`.

**Deployment plan (`DEPLOYMENT_PLAN`)**
: The configuration that decides which rules deploy where and in what status. Referenced by CLI global options and [Configuration](../configuration.md).

**Visibility**
: Configuration controlling which objects are exposed/deployed in a given context. Validated by a generated `visibility` schema.

**Playbook-map**
: A mapping that associates detections with response playbooks. Produced by the legacy `opentide export playbook-map` command (not by the default `opentide generate` pipeline).

**TLP (Traffic Light Protocol)**
: The sharing-sensitivity classification on `metadata.tlp` (e.g. `clear`, `green`, `amber`, `red`).

## Tooling and automation

**Generate**
: `opentide generate` — compile specs + objects into schemas, templates, the IDE router, and indexes. See [`generate`](../../cli/generate.md).

**Document**
: `opentide generate docs` — render human wiki pages from loaded objects. See [`generate docs`](../../cli/generate.md).

**Registry**
: The in-memory index of loaded objects and generated artifacts that the SDK exposes (`OpenTide.Rules`, `OpenTide.Objectives`, …). See [SDK registry](../../sdk/registry.md).

**MCP (Model Context Protocol)**
: The protocol OpenTide's agent server speaks, exposing tools and resources to AI editors. See [MCP](../../mcp/index.md).

**SDK**
: The Python API (`from opentide import OpenTide`) for embedding the engine in your own code. See [SDK](../../sdk/index.md).

**CoreTide**
: The predecessor to OpenTide, distributed via git submodules. Migrating from it? See the [migration guide](../migration/index.md).
