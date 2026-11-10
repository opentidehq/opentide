---
title: Architecture decisions
description: The architecture decision records (ADRs) of the unified core, one per decision, with the context, the decision, its consequences and the evidence behind it, and how to add one.
---

# Architecture decisions

An architecture decision record (ADR) writes down one decision: why it was needed, what was decided, what follows from it and the evidence behind it. Agents and people read these pages before changing what a decision covers. To change a decision, write a new ADR that supersedes it.

The decisions D-1 to D-8 come from the unified-core plan, [§1 Decisions](https://github.com/opentidehq/opentide/blob/docs/unified-core-plan/docs/internal/unified-core.md#1-decisions) (PR [#789](https://github.com/opentidehq/opentide/pull/789), epic [#790](https://github.com/opentidehq/opentide/issues/790)). Until #789 merges, the plan exists only on the branch `docs/unified-core-plan`, so the ADRs link to it there. Every ADR written here is **Proposed**. A maintainer marks it **Accepted** when the plan is approved.

## Index

| ADR | Decision | Title | Status |
|-----|----------|-------|--------|
| [0001](./0001-tide-model-as-rust-code.md) | D-2 | The Tide model is Rust code, with the schema conventions of UC-1.1 ([#807](https://github.com/opentidehq/opentide/issues/807)) | Proposed |
| [0002](./0002-all-logic-in-rust.md) | D-1 | All opentide logic is Rust | Proposed |
| [0003](./0003-cli-is-opentide-cli.md) | D-3 | The CLI is `opentide-cli`, called in-process from Python and npm | Proposed |
| [0004](./0004-merge-language-server.md) | D-4 | language-server merges into this repository with its history | Proposed |
| [0005](./0005-opentide-facade-crate.md) | D-5 | The `opentide` facade crate is the Rust SDK and the only stable API | Proposed |
| [0006](./0006-npm-packages.md) | D-6 | npm: `@opentide/opentide` is both the SDK and the CLI | Proposed |
| [0007](./0007-vscode-extension-stays-separate.md) | D-7 | The VS Code extension stays a separate repository | Proposed |
| [0008](./0008-connectors-in-rust.md) | D-8 | Connectors are Rust, with a Python plugin hook | Proposed |
| [0009](./0009-revision-registry.md) | UC-1.7 | The revision registry: dispatch on `metadata.schema`, unknown revisions checked against the newest of their family, forward migrations ([#813](https://github.com/opentidehq/opentide/issues/813)) | Proposed |
| [0010](./0010-one-diagnostic-model.md) | UC-2.2 | One diagnostic model for `validate`, the SDK, MCP and the language server, and the decisions on the CLI/editor parity gaps ([#817](https://github.com/opentidehq/opentide/issues/817)) | Proposed |

Work items will add these ADRs, each taking the number after the highest one in the index when it is written:

| Work item | Issue | What its ADR decides |
|-----------|-------|----------------------|
| UC-1.9 | [#815](https://github.com/opentidehq/opentide/issues/815) | The Python surface of the Rust models: pyclasses under today's names, `.pyi`, `opentide.models.*` compatibility |

## Statuses

| Status | Meaning |
|--------|---------|
| Proposed | Written and under review. Work may follow it, but the decision can still change |
| Accepted | A maintainer approved it. To change it, write a new ADR |
| Superseded by NNNN | A later ADR replaced it. The page stays, with a link to its successor |

Only a maintainer changes a status to Accepted or Superseded.

## How to add an ADR

1. Take the number after the highest one in the index. The file name is that number followed by a short kebab-case slug: `docs/internal/adr/NNNN-short-slug.md`.
2. Copy the template below. Fill every section, and leave the status at Proposed.
3. Add the slug to [`meta.json`](./meta.json) and a row to the index above, in the same pull request.
4. If the ADR records a plan decision (`D-n`), link it from the plan's Decisions table, in the same pull request or the plan's next status update. If it comes from a work item, the work item's issue and pull request link it, and so does the "to come" table above, until the row moves into the index.
5. To change an accepted decision, write a new ADR that names the one it supersedes. A maintainer then marks the old one "Superseded by NNNN". Do not rewrite the old one's Decision section.
6. Run `scripts/validate-docs.sh` and `uv run pytest tests/test_docs -q --no-cov`. Every relative link must resolve, so do not link a page that is not on the branch yet.

### Template

````markdown
---
title: "NNNN: <decision in a few words>"
description: <one sentence: what is decided>
---

# NNNN: <decision in a few words>

| | |
|---|---|
| Status | Proposed |
| Date | YYYY-MM-DD |
| Decision | D-n, or the work item (UC-x.y) that made it |
| Issues | #… |

## Context

What forces the decision: the problem, the constraints, the measurements.

## Decision

What is decided, in the words of its source (the plan's D-n row, or the work item).

## Consequences

What follows from it: what becomes possible, what it costs, which invariants and work items it touches.

## Evidence

Links: plan sections, issues, pull requests, measurements.
````
