---
title: Schema revision
description: Why every object has two version fields, what each one controls, and how schema revisions coexist.
---

# Schema revision

Every OpenTide object carries **two** version-like fields, and mixing them up is the single most common authoring mistake. This page explains what each controls and why they are separate.

## Two fields, two jobs

| Field | Example | Answers | Authoritative history |
|-------|---------|---------|-----------------------|
| `metadata.schema` | `rule::1.0` | *Which structure does this object follow?* | The specification |
| `metadata.version` | `1.2.0` | *Which revision of this object's content?* | Git |

- **`metadata.schema`** — the **structural schema revision**. It selects the validation model and the generated `rule.1.0.schema.json` your editor and CLI check against. It changes only when the *shape* of the object changes (new required fields, renamed structures), which is rare and governed by the [specifications](/docs/specifications/specs/versioning/).
- **`metadata.version`** — the **instance content version**. It is your semver-style marker for how a specific detection has evolved. Bump it when you meaningfully change the rule's logic. The real, line-by-line history lives in git.

<Callout type="warn">
Never use `metadata.version` to select a schema file. Content revisions and structural revisions are independent — a rule at content `version: 4` can still be `schema: rule::1.0`.
</Callout>

## Naming conventions

The schema identifier maps predictably to files and specs:

| Layer | Format | Example |
|-------|--------|---------|
| Schema identifier | `{family}::{major}.{minor}` | `rule::1.0` |
| Specification file | `specs/objects/{family}-{major}.{minor}.md` | `rule-1.0.md` |
| JSON Schema artifact | `.opentide/schemas/{family}.{major}.{minor}.schema.json` | `rule.1.0.schema.json` |
| Template artifact | `.opentide/templates/{family}.{major}.{minor}.template.yaml` | `rule.1.0.template.yaml` |
| IDE router | `.opentide/schemas/opentide.schema.json` | routes `objects/**/*.yaml` by `metadata.schema` |

Your editor validates YAML live because the IDE router reads each file's `metadata.schema` and applies the matching JSON Schema — no per-file configuration required.

## How revisions coexist

Schema revisions are additive. When a new revision such as `rule::1.1` ships, both revisions can exist in the same repo at once:

1. `opentide generate schemas` emits **both** `rule.1.0.schema.json` and `rule.1.1.schema.json`.
2. The IDE router adds a branch for each identifier and routes objects by their declared `metadata.schema`.
3. Objects opt in individually by setting `metadata.schema: rule::1.1`. Objects that still declare `rule::1.0` keep validating against `1.0` until you migrate them.

This means a schema upgrade never forces a big-bang migration — you move objects over at your own pace. Bulk transitions are a job for [`opentide migrate`](../../cli/migrate.md).

## What to do when

| Situation | Action |
|-----------|--------|
| You changed a rule's detection logic | Bump `metadata.version` |
| You upgraded the OpenTide package | Run `opentide generate` to refresh schema artifacts |
| A new schema revision is available | Migrate objects to the new `metadata.schema` when ready |
| Your editor stopped validating YAML | Regenerate: `opentide generate schemas` |

<Callout type="info">
Implementation detail: how the registry resolves identifiers to models and runs migrations is an internal concern documented in the [SDK registry](../../sdk/registry.md) and the opentide source. Authors only need the `metadata.schema` value.
</Callout>

## Normative reference

- [Versioning spec](/docs/specifications/specs/versioning/) — the rules for how revisions are numbered and deprecated.
- [Metadata spec](/docs/specifications/specs/metadata/) — the full `metadata` field contract.
