---
title: "0016: opentide-tide folds into opentide-analysis, not into opentide-workspace"
description: "Plan §4 amended: the crates that need every query engine stay above opentide-workspace. opentide-tide (Tide YAML in the editor) merges into opentide-analysis, which already depends on it; opentide-workspace keeps no engine dependency, so opentide-compile and opentide-connectors never build a parser."
---

# 0016: opentide-tide folds into opentide-analysis, not into opentide-workspace

| | |
|---|---|
| Status | Proposed |
| Date | 2026-11-27 |
| Decision | Amends plan §4 ([`unified-core.md`](../unified-core.md#4-target-architecture)), the `opentide-workspace` row. Raised by the Rust review after the unification ([#1925](https://github.com/opentidehq/opentide/issues/1925)) |
| Issues | [#1965](https://github.com/opentidehq/opentide/issues/1965) |

## Context

Plan §4 lists `opentide-workspace` as coming from Python's `loading/`, `registry/`, `indexing/`,
`validation/` and `core/`, and from "language-server `opentide-analysis`, `opentide-tide` checks".
Read as a crate layout, that row folds both language-server crates into `opentide-workspace`.

The crates' dependencies today (`Cargo.toml`, `[dependencies]`):

| Crate | Depends on (opentide crates) |
|---|---|
| `opentide-workspace` | `opentide-core`, `opentide-schema` |
| `opentide-compile` | `opentide-core`, `opentide-schema`, `opentide-workspace` |
| `opentide-connectors` | `opentide-core`, `opentide-schema`, `opentide-workspace`, `opentide-compile` |
| `opentide-tide` | `opentide-core`, `-dataset`, `-schema`, `-highlight`, `-ecs` and all twelve query crates |
| `opentide-analysis` | `opentide-core`, `-highlight`, `-ecs`, the same twelve query crates, `opentide-tide`, and (feature `queries`) `opentide-schema`, `opentide-workspace` |

`opentide-tide` and `opentide-analysis` each depend on every query engine. `opentide-workspace`
depends on none: the query checks plug in through its narrow trait `QueryCheck` (ADR 0010), which
`opentide-analysis` implements from above (`opentide_analysis::queries::EngineQueries`). Folding either crate into `opentide-workspace`
would make `opentide-compile` and `opentide-connectors`, and everything that builds only on them,
compile every parser and catalog: about 120k lines of query-engine code (the twelve query crates' `src/`) in a build that needs none of it,
and a layering in which the deploy path changes whenever a grammar does.

The Tide object checks have already moved: they are `opentide-workspace`'s `validate` (UC-2.2,
UC-2.6), and `crates/AGENTS.md` forbids an object check in `opentide-tide` or `opentide-analysis`.
What remains in `opentide-tide` is Tide YAML in the editor: query injection (each platform block's
query handed to its engine, with positions mapped back), the UUID reference graph, outline, inlay
hints, document links, the vocabularies for hover and completion, and the snippets. Only
`opentide-analysis` and `opentide-lsp` use it (and the fuzz targets).

## Decision

1. `opentide-tide` merges into `opentide-analysis`, as a module (`opentide_analysis::tide`). The
   crate is retired.
2. `opentide-workspace` stays free of the query engines. Engines reach it only through its traits,
   implemented in `opentide-analysis`, as today.
3. `opentide-compile` and `opentide-connectors` keep depending on `opentide-workspace` alone, never
   on `opentide-analysis`.

## Consequences

- The domain layer of `xtask/layers.toml` becomes `["opentide-workspace"]`, then
  `["opentide-analysis", "opentide-compile"]`, then `["opentide-connectors"]`. The rule above is
  what keeps a crate on the deploy path from depending on `opentide-analysis`; the layer check alone
  does not forbid it (`opentide-connectors` sits above `opentide-analysis`), so the review of a
  domain crate's `Cargo.toml` holds it.
- `opentide-analysis` takes `opentide-schema` and `opentide-dataset` as unconditional dependencies,
  which it already pulls in through `opentide-tide`; no host gains a dependency. It stays I/O-free
  (`scripts/engine/check-io-free.sh`) and takes over `opentide-tide`'s `build.rs` (the compressed
  datasets and the pre-parsed vocabularies, #1743).
- `opentide-tide` is published on crates.io (releases up to 1.1.0). It is internal, with no stability
  promise (ADR 0005), so retiring it is not a facade change; its last published version gets a
  README pointing to the `opentide` crate, and the release notes (`crates/CHANGELOG.md`) say so.
- One fewer crate to publish, version and document (`docs/internal/publishing.md`'s list of
  engine crates).
- The code move is later work, in slices tracked on #1965. Until it lands, the two crates keep
  their current roles, and this ADR is the target.

## Evidence

- Plan §4, "Crates" ([`unified-core.md`](../unified-core.md#4-target-architecture)).
- [ADR 0010](./0010-one-diagnostic-model.md): validation in `opentide-workspace`, the query checks
  supplied from `opentide-analysis` through `QueryCheck` (its `EngineQueries`); its addendum keeps `opentide-analysis`
  and `opentide-tide` free of the workspace's new crates.
- [`xtask/layers.toml`](https://github.com/opentidehq/opentide/blob/development/xtask/layers.toml),
  the enforced layering; [`crates/AGENTS.md`](https://github.com/opentidehq/opentide/blob/development/crates/AGENTS.md),
  "Hard rules".
- Issue [#1965](https://github.com/opentidehq/opentide/issues/1965).
