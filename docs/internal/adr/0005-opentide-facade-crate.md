---
title: "0005: The opentide facade crate"
description: "Decision D-5 of the unified core: an opentide facade crate is the Rust SDK and the only crate with a stability promise, and every binding depends on it alone."
---

# 0005: The `opentide` facade crate

| | |
|---|---|
| Status | Proposed |
| Date | 2026-11-07 (the plan's decision), recorded 2026-11-08 |
| Decision | D-5 |
| Issues | UC-5.1 [#836](https://github.com/opentidehq/opentide/issues/836), UC-5.2 [#837](https://github.com/opentidehq/opentide/issues/837), UC-5.3 [#838](https://github.com/opentidehq/opentide/issues/838) |

## Context

The unified core is split into many crates: the foundation (`opentide-core`, `-syntax`, `-highlight`, the query crates, `opentide-schema`), the domain (`opentide-workspace`, `-compile`, `-connectors`) and the applications (`opentide-cli`, `opentide-lsp`) (plan §4). Rust, Python and TypeScript users each need an API. If every binding reached into whichever internal crates it needed, there would be three APIs, and every internal crate would carry a compatibility promise.

## Decision

An `opentide` facade crate is the Rust SDK and the only crate with a stability promise. Every binding depends on it alone.

Its rationale, from the plan: one API for Rust, Python and TypeScript. Internal crates are published for the facade's sake and documented as internal, as uv, ruff, polars and biome do.

## Consequences

- **The facade is the top library layer.** It re-exports the public types and offers the features `schema`, `workspace`, `compile`, `connectors`, `cli` and `lsp`, with their docs (plan §4, "The facade API"). In the layer table ([`xtask/layers.toml`](../../../xtask/layers.toml), checked by `cargo xtask check-layers`), the facade sits above the applications and below the bindings.
- **Bindings are thin.** Every binding function is a one-line wrapper over a facade function, and logic in a binding fails review (plan §4). The bindings are `bindings/python` (PyO3 abi3), `bindings/node` (napi-rs 3) and `bindings/wasm` (wasm-bindgen), with generated `.pyi` and `.d.ts`.
- **Only the facade promises stability.** `cargo-semver-checks` runs on the facade (plan §5.4) and `missing_docs` applies to it (plan §5.5). The internal crates are published at the same lockstep version and documented as internal. The workspace lints already record this: the engine crates are published for the facade's sake, so their signatures do not change to satisfy a style lint, and the facade decides its own API conventions (`[workspace.lints.clippy]` in the root `Cargo.toml`, PR [#848](https://github.com/opentidehq/opentide/pull/848)).
- **The name.** UC-0.1 (PR [#846](https://github.com/opentidehq/opentide/pull/846)) is reserving `opentide` on crates.io with a 0.0.0 placeholder, which UC-5.1 replaces.
- **Docs.** docs.rs and a Rust page in `docs/sdk` (UC-5.1).

## Evidence

- Plan: [§1 Decisions](https://github.com/opentidehq/opentide/blob/docs/unified-core-plan/docs/internal/unified-core.md#1-decisions), [§4 Target architecture](https://github.com/opentidehq/opentide/blob/docs/unified-core-plan/docs/internal/unified-core.md#4-target-architecture) (crates and the facade API), [§5 Correctness strategy](https://github.com/opentidehq/opentide/blob/docs/unified-core-plan/docs/internal/unified-core.md#5-correctness-strategy) (5.4 and 5.5), [§6 Work plan](https://github.com/opentidehq/opentide/blob/docs/unified-core-plan/docs/internal/unified-core.md#6-work-plan) (Phase 5), [§8 Distribution](https://github.com/opentidehq/opentide/blob/docs/unified-core-plan/docs/internal/unified-core.md#8-distribution).
- PRs [#846](https://github.com/opentidehq/opentide/pull/846) (the name) and [#848](https://github.com/opentidehq/opentide/pull/848) (the layer table and the lints).
