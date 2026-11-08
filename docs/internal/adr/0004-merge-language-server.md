---
title: "0004: language-server merges into this repository"
description: "Decision D-4 of the unified core: opentidehq/language-server merges into opentide with its history and is archived with a pointer; every crate keeps its name and is published from here."
---

# 0004: language-server merges into this repository

| | |
|---|---|
| Status | Proposed |
| Date | 2026-11-07 (the plan's decision), recorded 2026-11-08 |
| Decision | D-4 |
| Issues | UC-0.2 [#800](https://github.com/opentidehq/opentide/issues/800) (PR [#847](https://github.com/opentidehq/opentide/pull/847)), UC-0.3 [#801](https://github.com/opentidehq/opentide/issues/801), UC-6.3 [#842](https://github.com/opentidehq/opentide/issues/842) |

## Context

The Rust engine lived in `opentidehq/language-server`, and the two repositories had to be kept in step by hand:

- 23 of language-server's 197 commits (11.7%) existed only for that, 13 of them to regenerate the Tide catalog.
- opentide moved its engine pin 28 times in 10 days.
- language-server's test suite needs this repository's Python package: it compares the engine with the Pydantic models.

## Decision

`opentidehq/language-server` merges into this repository with its history and is archived with a pointer. Every crate keeps its name and is published from here.

## Consequences

- **UC-0.2 does the merge.** PR [#847](https://github.com/opentidehq/opentide/pull/847) (open when this ADR was written) imports the crates, grammars, highlights, catalogs, editors, npm packages, fuzz targets and test data with `git filter-repo`, keeping their history, into one Cargo workspace. `analysis/` builds from path dependencies. The engine pin, `check_engine_pin.py`, the `opentide-canary.yml` workflow and `requirements-opentide.txt` are removed, `check_engine_catalog.py` becomes a test, and `sync_opentide_schemas.py` now reads this checkout's models. [Importing language-server](../../engine/IMPORT.md) records the source commit, the invocation and the path mapping.
- **The vendor-parser oracles stay.** They check the query parsers against Kusto.Language, Splunk, Elasticsearch and Falco, not against Pydantic, and are kept as CI jobs (UC-0.3, plan §10).
- **Publishing moves here.** language-server's release assets keep publishing, from this repository (UC-0.3). Every crate keeps its name and lockstep version. UC-0.1 (PR [#846](https://github.com/opentidehq/opentide/pull/846)) found that the 14 published engine crates trust `opentidehq/language-server` as their publisher today. They need a publisher from this repository before the first release from here.
- **Agents work in one repository.** UC-0.4 (PR [#848](https://github.com/opentidehq/opentide/pull/848), open when this ADR was written) adds the `AGENTS.md` hierarchy (the root map, `crates/AGENTS.md`, one per crate), the workspace lints, the layer check and the test profiles over the merged workspace.
- **The archive comes last.** UC-6.3 archives language-server with pointers in place and updates the crates' repository URLs, after the release train (UC-5.5) publishes from here.
- **Cross-repository coupling.** The plan's target for coupling commits is 0, down from 11.7% (plan §11).

## Evidence

- Plan: [§1 Decisions](https://github.com/opentidehq/opentide/blob/docs/unified-core-plan/docs/internal/unified-core.md#1-decisions), [§6 Work plan](https://github.com/opentidehq/opentide/blob/docs/unified-core-plan/docs/internal/unified-core.md#6-work-plan) (Phase 0 and Phase 6), [§9 Repository and agentic development](https://github.com/opentidehq/opentide/blob/docs/unified-core-plan/docs/internal/unified-core.md#9-repository-and-agentic-development), [§10 Risks](https://github.com/opentidehq/opentide/blob/docs/unified-core-plan/docs/internal/unified-core.md#10-risks), [§11 Metrics](https://github.com/opentidehq/opentide/blob/docs/unified-core-plan/docs/internal/unified-core.md#11-metrics).
- [Importing language-server](../../engine/IMPORT.md): the source commit, the filter, the path mapping.
- PRs [#846](https://github.com/opentidehq/opentide/pull/846) (UC-0.1, names and publishers), [#847](https://github.com/opentidehq/opentide/pull/847) (UC-0.2, the import), [#848](https://github.com/opentidehq/opentide/pull/848) (UC-0.4, the scaffolding).
