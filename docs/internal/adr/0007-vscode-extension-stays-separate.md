---
title: "0007: The VS Code extension stays separate"
description: "Decision D-7 of the unified core: opentidehq/vscode-extension stays a separate repository and consumes @opentide/opentide at one pinned version."
---

# 0007: The VS Code extension stays separate

| | |
|---|---|
| Status | Proposed |
| Date | 2026-11-07 (the plan's decision), recorded 2026-11-08 |
| Decision | D-7 |
| Issues | UC-6.1 [opentidehq/vscode-extension#75](https://github.com/opentidehq/vscode-extension/issues/75), UC-5.3 [#838](https://github.com/opentidehq/opentide/issues/838), UC-5.4 [#839](https://github.com/opentidehq/opentide/issues/839) |

## Context

language-server merges into this repository ([ADR 0004](./0004-merge-language-server.md)), and the same question arises for the VS Code extension. The extension has a different toolchain, a different release channel and a different test harness. Today it bundles CPython to run opentide as a separate program, and its packages weigh 50–61 MiB per platform (plan §11).

## Decision

`opentidehq/vscode-extension` stays a separate repository and consumes `@opentide/opentide` at one pinned version.

## Consequences

- **The coupling becomes one version number.** The extension pins one `@opentide/opentide` version ([ADR 0006](./0006-npm-packages.md)), and `@opentide/wasm` (UC-6.1).
- **The cross-repository contracts stay.** Invariant 4 of plan §3 holds: `opentide serve`, `info catalog`, the tenants in `info` and the progress events, as the extension's `docs/CONTRACTS.md` defines them, and the LSP custom requests.
- **The extension moves when the SDK is proven.** It moves when `@opentide/opentide` passes the cross-SDK conformance suite (plan §7, step 5; UC-5.4).
- **UC-6.1 removes the CPython bundle.** The target is packages without CPython of about 12 MiB (15 MiB at most, plan §11). It is filed in the extension's repository as #75.
- **A licence review comes first.** Today the extension (MIT) runs opentide (EUPL-1.2) as a separate program. Loading an EUPL-1.2 library in-process changes that argument, so a licence review is recorded before UC-6.1. Relicensing the bindings or keeping a process boundary are the fallbacks (plan §10).

## Evidence

- Plan: [§1 Decisions](https://github.com/opentidehq/opentide/blob/docs/unified-core-plan/docs/internal/unified-core.md#1-decisions), [§3 Invariants](https://github.com/opentidehq/opentide/blob/docs/unified-core-plan/docs/internal/unified-core.md#3-invariants), [§6 Work plan](https://github.com/opentidehq/opentide/blob/docs/unified-core-plan/docs/internal/unified-core.md#6-work-plan) (Phase 6), [§7 Rollout](https://github.com/opentidehq/opentide/blob/docs/unified-core-plan/docs/internal/unified-core.md#7-rollout), [§10 Risks](https://github.com/opentidehq/opentide/blob/docs/unified-core-plan/docs/internal/unified-core.md#10-risks), [§11 Metrics](https://github.com/opentidehq/opentide/blob/docs/unified-core-plan/docs/internal/unified-core.md#11-metrics).
- [opentidehq/vscode-extension#75](https://github.com/opentidehq/vscode-extension/issues/75): the extension in-process (UC-6.1).
