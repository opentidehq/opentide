---
title: Usage
description: Human-oriented guides for installing OpenTide, onboarding detection repositories, and day-to-day workflows.
icon: BookOpen
---

# Usage

Guides for detection engineers who install OpenTide, scaffold repositories, and operate detection-as-code workflows.

## Getting started

1. [Installation](./installation.md) — PyPI extras, environment variables, and editor prerequisites.
2. [Quickstart](./quickstart.md) — validate, generate, and inspect a repo in five minutes.
3. [Repository setup](./repository-setup.md) — what `opentide setup` scaffolds and how to configure platforms.

## Workflows

| Guide | When to read |
|-------|--------------|
| [Detection-as-code](./workflows/detection-as-code.md) | Authoring and reviewing threat, objective, and rule objects |
| [CI/CD](./workflows/ci-cd.md) | GitHub, GitLab, and Azure pipeline integration |
| [Agentic setup](./workflows/agentic-setup.md) | MCP hosts, agent skills, and copilot instructions |

## Concepts

| Topic | Summary |
|-------|---------|
| [Object model](./concepts/object-model.md) | Threat → objective → rule chaining |
| [Platforms](./concepts/platforms.md) | Deploy and query-validation capabilities |
| [Schema revision](./concepts/schema-revision.md) | `metadata.schema` vs `metadata.version` |

## Migration

Upgrading from CoreTide git submodules? Start with the [migration guide](./migration/index.md).

## Related reference

- [CLI](../cli/index.md) — full command reference
- [MCP](../mcp/index.md) — agent server setup
- [SDK](../sdk/index.md) — programmatic API
