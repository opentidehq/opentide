---
title: Why OpenTide
description: The problem detection-as-code teams hit at scale, and the design goals that shape OpenTide.
---

# Why OpenTide

Detection engineering breaks down in predictable ways as a team grows. OpenTide exists to remove those failure modes. This page explains the problem it solves and the principles behind its design — read it before deciding whether OpenTide fits your team.

## The problem

A modern SOC writes detections for several platforms at once — Sentinel, Splunk, Defender, an EDR — and manages hundreds to thousands of rules. Teams that manage this by hand, or with a pile of scripts, run into the same walls:

- **Content drift.** Rules live as raw platform exports or copied YAML. There is no shared schema, so two engineers describe the same rule two different ways. Reviews catch style, not correctness.
- **No link between threat and detection.** A rule exists, but *why*? Which threat does it address, which objective does it satisfy, what is the coverage gap if you delete it? That knowledge lives in people's heads.
- **Multi-platform sprawl.** The same detection idea is re-implemented per platform with no common source of truth. Coverage reporting across platforms is guesswork.
- **Submodule and copy-paste reuse.** Sharing content across repos via git submodules (the CoreTide era) couples repositories, makes upgrades painful, and spreads breaking changes silently.
- **Unsafe automation.** Agents and scripts edit detection YAML with no schema to validate against and no honest signal about which platforms can actually be tested.

## What OpenTide does about it

OpenTide treats detection content as **typed, versioned objects in a git repository** and gives you an engine to work with them.

- **A normative object model.** Every threat, objective, and rule conforms to a published [specification](/docs/specifications/). Validation is schema-driven, not opinion-driven.
- **Explicit chaining.** Rules reference the objectives they satisfy; objectives reference the threats they cover. Coverage and gaps become queryable facts, not tribal knowledge. See the [object model](./concepts/object-model.md).
- **One source, many platforms.** A rule carries per-platform configuration blocks. OpenTide deploys to each platform and, where the platform allows it, validates query syntax — [honestly reporting](./concepts/platforms.md) where it cannot.
- **Generated, not hand-maintained, scaffolding.** JSON Schemas, templates, IDE routing, and documentation are generated from the specs and your objects with `opentide generate` and `opentide generate docs`.
- **Package, not submodule.** OpenTide ships as a PyPI package. You depend on a version, not on someone else's repository layout.
- **Automation as a first-class citizen.** The same engine is exposed as a [CLI](../cli/index.md), a Python [SDK](../sdk/index.md), and an [MCP server](../mcp/index.md) for agents — with capability reporting that never fakes a result.

## Design principles

These principles explain *why* OpenTide behaves the way it does, and where its boundaries are.

| Principle | What it means in practice |
|-----------|---------------------------|
| **Specs are the contract** | The [specifications](/docs/specifications/) are canonical. The Python models implement them; generated JSON Schema is a build artifact, never the source of truth. |
| **Honest capability reporting** | If a platform cannot validate query syntax, the CLI and MCP say `supported: false` rather than returning a fake pass. See [Platforms](./concepts/platforms.md). |
| **Deterministic generation** | `generate` is reproducible: the same specs and objects always produce the same schemas and templates. Generated files are safe to commit and diff. |
| **Git is the history** | Instance content versions (`metadata.version`) track meaning; git tracks the actual change history. See [Schema revision](./concepts/schema-revision.md). |
| **Fail loud in CI, safe by default locally** | Validation errors exit `1` everywhere, and `validate --strict` turns warnings into failures for pipelines. Deploys default to staging and dry-run friendly flows. |

## When OpenTide is *not* the right fit

Being honest about scope:

- You manage a handful of rules on a single platform and are happy in that platform's native UI — the object model overhead may not pay off yet.
- You need a turnkey SaaS detection catalog — OpenTide is an engine and a content model you run yourself, not a hosted product.
- You want live query execution against every platform today — some platforms are deploy-only, and a couple of MCP query tools are still [stubs](./workflows/agentic-setup.md). Check the [platform matrix](./concepts/platforms.md) before committing.

## Next

- [How OpenTide works](./how-it-works.md) — the end-to-end lifecycle.
- [Object model](./concepts/object-model.md) — the three object families and chaining.
- [Installation](./installation.md) — get the CLI on your machine. Latest patch: [0.1.3](./releases.md).
