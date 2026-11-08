---
title: "0006: npm packages"
description: "Decision D-6 of the unified core: on npm, @opentide/opentide is both the SDK and the CLI, with @opentide/<platform> native packages (napi-rs 3), @opentide/wasm for the browser, and the plain opentide name as an alias."
---

# 0006: npm packages

| | |
|---|---|
| Status | Proposed |
| Date | 2026-11-07 (the plan's decision), recorded 2026-11-08 |
| Decision | D-6 |
| Issues | UC-0.1 [#799](https://github.com/opentidehq/opentide/issues/799), UC-5.3 [#838](https://github.com/opentidehq/opentide/issues/838), UC-5.4 [#839](https://github.com/opentidehq/opentide/issues/839), UC-5.5 [#840](https://github.com/opentidehq/opentide/issues/840) |

## Context

TypeScript users need the SDK, and some need the CLI from npm without Python. The browser needs a WebAssembly build. The PyPI package is already one package that is both the SDK and the CLI. A split into `sdk` and `cli` packages on npm would be one native module behind two names.

## Decision

npm: `@opentide/opentide` is both the SDK and the CLI (`bin: opentide`), with `@opentide/<platform>` native packages (napi-rs 3) and `@opentide/wasm` for the browser. The plain `opentide` name is an alias.

## Consequences

- **The same shape as PyPI.** One package carries the SDK and the CLI. Its `bin` calls the same `main(argv)` as Python's console script ([ADR 0003](./0003-cli-is-opentide-cli.md)), over the facade ([ADR 0005](./0005-opentide-facade-crate.md)).
- **UC-5.3 builds it.** That item ships `@opentide/opentide` (napi-rs 3), the platform packages, the `bin`, the `.d.ts`, the alias and `@opentide/wasm`, and decides the fate of `@opentide/lsp-client` and `@opentide/lsp-worker`. Its exit criterion: `npx @opentide/opentide --json commands` is byte-identical to PyPI's.
- **Conformance.** UC-5.4's cross-SDK suite runs the same corpus through Rust, Python and Node and expects identical documents.
- **Names.** UC-0.1 (PR [#846](https://github.com/opentidehq/opentide/pull/846)) is reserving `@opentide/opentide` and `opentide` with 0.0.0 placeholders. It found that the `opentide` npm organisation already exists, holding `@opentide/explorer`, which is published from `opentidehq/explorer`.
- **One tag publishes everything,** npm included (UC-5.5, plan §8).

## Evidence

- Plan: [§1 Decisions](https://github.com/opentidehq/opentide/blob/docs/unified-core-plan/docs/internal/unified-core.md#1-decisions), [§6 Work plan](https://github.com/opentidehq/opentide/blob/docs/unified-core-plan/docs/internal/unified-core.md#6-work-plan) (Phase 5), [§8 Distribution](https://github.com/opentidehq/opentide/blob/docs/unified-core-plan/docs/internal/unified-core.md#8-distribution).
- PR [#846](https://github.com/opentidehq/opentide/pull/846) (UC-0.1): the npm names, the organisation, the placeholders.
