---
title: "0002: All opentide logic is Rust"
description: "Decision D-1 of the unified core: schema, workspace, validation, catalogue, compile, connectors and the CLI are implemented once, in Rust, and Python becomes the SDK wrapper and the CLI launcher."
---

# 0002: All opentide logic is Rust

| | |
|---|---|
| Status | Proposed |
| Date | 2026-11-07 (the plan's decision), recorded 2026-11-08 |
| Decision | D-1 |
| Issues | Epic [#790](https://github.com/opentidehq/opentide/issues/790), plan PR [#789](https://github.com/opentidehq/opentide/pull/789) |

## Context

opentide is implemented twice. Python makes the decisions in the CLI, the SDK and MCP. The Rust engine imported from `opentidehq/language-server` makes them in the editor, fed a catalog generated from the Pydantic models. Two implementations disagree:

- Of 80 injected faults (16 kinds × 5 files), 61 were identical in the CLI and the engine. 8 had different codes, 6 were seen by one side only, and 5 by neither.
- On a clean workspace the engine reports 2,200 warnings where `validate` reports none.

Speed is the other force. Measured on 2026-11-07 on a workspace of 1,100 objects, `validate` took 3.18 s in the Python CLI and 0.69 s in the existing Rust engine on 4 threads. With 1,000 warnings it took 12.76 s against 0.69 s. In the CLI's profile of `validate`, 34% of the time went to ruamel re-reading files for line numbers and 27% to repeated file I/O and globbing; the Rust query engine took 3.5%.

## Decision

All opentide logic is Rust: schema, workspace, validation, catalogue, compile, connectors, the CLI.

The CLI, the Python SDK, the TypeScript SDK, the language server and the WebAssembly build are all built from one Rust workspace in this repository. Python becomes the SDK wrapper and the CLI launcher, and does no work of its own.

## Consequences

- **One implementation removes a class of bug.** The CLI and the editor cannot disagree when one implementation decides for both. The target is 0 differences on the fault catalogue (plan §11).
- **Strangler steps, proven against an oracle.** Each step keeps the user-visible contract and is proven by differential tests against the Python implementation at a frozen tag, which stays the oracle until that step's default flips (plan §5, §7). Nothing is ported without a test that compares the Rust result with the oracle's. The tools for this are the golden capture (UC-0.5, [#803](https://github.com/opentidehq/opentide/issues/803)) and the differential runner with the approved-diffs ledger (UC-0.7, [#805](https://github.com/opentidehq/opentide/issues/805)).
- **The invariants do not move.** The nine invariants of plan §3 (the CLI contract, the command tree, diagnostic codes, cross-repository contracts, MCP, workspace formats, SDK import paths, supported platforms, the security posture) hold at every step. Changing one is a separate, explicit decision with its own changelog entry.
- **Scope.** Phases UC-1 to UC-4 replace about 85,000 lines of Python: about 11,600 in UC-1, 11,000 in UC-2, 43,000 in UC-3 and 17,000 in UC-4 (plan §6). The plan's mitigation is the strangler order: each phase ships value on its own, and the oracle stays until each flip (plan §10).
- **Rollout per command.** A command keeps running Python by default until its Rust implementation is identical in `compare` on every corpus for one release. The default then flips with a changelog entry, `OPENTIDE_ENGINE=python` stays for one more release, and the Python implementation is deleted one release after the flip (plan §7).
- **Runtime dependencies.** The target is a wheel with no third-party runtime dependencies, down from 73 packages (plan §11).

## Evidence

- Plan: [introduction](https://github.com/opentidehq/opentide/blob/docs/unified-core-plan/docs/internal/unified-core.md#unified-core), [§1 Decisions](https://github.com/opentidehq/opentide/blob/docs/unified-core-plan/docs/internal/unified-core.md#1-decisions), [§2 Evidence](https://github.com/opentidehq/opentide/blob/docs/unified-core-plan/docs/internal/unified-core.md#2-evidence), [§3 Invariants](https://github.com/opentidehq/opentide/blob/docs/unified-core-plan/docs/internal/unified-core.md#3-invariants), [§5 Correctness strategy](https://github.com/opentidehq/opentide/blob/docs/unified-core-plan/docs/internal/unified-core.md#5-correctness-strategy), [§6 Work plan](https://github.com/opentidehq/opentide/blob/docs/unified-core-plan/docs/internal/unified-core.md#6-work-plan), [§7 Rollout](https://github.com/opentidehq/opentide/blob/docs/unified-core-plan/docs/internal/unified-core.md#7-rollout), [§11 Metrics](https://github.com/opentidehq/opentide/blob/docs/unified-core-plan/docs/internal/unified-core.md#11-metrics).
- Epic [#790](https://github.com/opentidehq/opentide/issues/790): the phase issues #791 to #798 and the dependency table.
- The first steps: one repository and one Cargo workspace (UC-0.2, PR [#847](https://github.com/opentidehq/opentide/pull/847)), and the agentic scaffolding: lints, `xtask`, test profiles (UC-0.4, PR [#848](https://github.com/opentidehq/opentide/pull/848)).
