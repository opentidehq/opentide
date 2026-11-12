---
title: "0003: The CLI is opentide-cli"
description: "Decision D-3 of the unified core: the command line is the Rust crate opentide-cli (clap); the Python console script and npm's bin call its main(argv) in-process, and standalone binaries come from the same crate."
---

# 0003: The CLI is `opentide-cli`

| | |
|---|---|
| Status | Proposed |
| Date | 2026-11-07 (the plan's decision), recorded 2026-11-08 |
| Decision | D-3 |
| Issues | Epic [#790](https://github.com/opentidehq/opentide/issues/790); UC-3.3 [#825](https://github.com/opentidehq/opentide/issues/825), UC-3.8 [#830](https://github.com/opentidehq/opentide/issues/830), UC-5.3 [#838](https://github.com/opentidehq/opentide/issues/838), UC-5.5 [#840](https://github.com/opentidehq/opentide/issues/840) |

## Context

Once all logic is Rust ([ADR 0002](./0002-all-logic-in-rust.md)), the command line has to be Rust too, and it has to reach users through PyPI and npm as well as standalone binaries. Today the CLI is Typer and Rich: importing those two alone takes 69 ms before any command runs.

maturin cannot ship a PyO3 module and a binary in one wheel ([PyO3/maturin#368](https://github.com/PyO3/maturin/issues/368)), and its guide recommends calling the CLI's `main` from the module. In the prototype, `opentide` through Python into `_native.main` took 11–12 ms end to end. A native binary started in 1.1 ms.

## Decision

The CLI is `opentide-cli` (clap). Python's console script is `opentide = "opentide._native:main"`; npm's `bin` calls the same `main(argv)`; standalone binaries come from the same crate.

## Consequences

- **One command tree for every channel.** The PyPI package, `@opentide/opentide` and the standalone binaries run the same `main(argv)`. UC-5.3's exit criterion is that `npx @opentide/opentide --json commands` is byte-identical to PyPI's (plan §6).
- **The contract does not move.** Invariants 1 and 2 of plan §3 hold: output modes, flag hoisting, the JSON envelope, exit codes, outcome lines, code frames, the crash handler, Ctrl-C, and a byte-identical `opentide --json commands` (or approved additions only). UC-3.3 (CLI framework) and UC-3.4 (renderers) are proven against the goldens.
- **`opentide-cli` is an application crate** in the layer table (plan §4). It holds the command tree, output modes, renderers, envelopes, `serve`, `mcp`, `tui` and `main(argv)`, ported from `src/opentide/cli/` and `mcp_server/`.
- **The Python runtime dependencies leave.** With the Python launcher (UC-3.8), Typer, Rich, Textual, questionary, ruamel, dulwich and structlog leave the wheel's runtime dependencies. The connectors' dependencies stay until Phase 4.
- **Distribution.** GitHub Releases carry the `opentide` and `opentide-lsp` binaries with cargo-dist installers, checksums and attestations (plan §8). One tag publishes everything (UC-5.5).
- **Startup.** The plan's target for a light command (`explain`) is 0.03 s or less, against 0.18 s today (plan §11).

## Addendum: the console script's Python entry (UC-3.8b)

2026-11-12. Decided in [#960](https://github.com/opentidehq/opentide/issues/960), in
[#973](https://github.com/opentidehq/opentide/pull/973). The decision above stands: the command
line is `opentide-cli`, run in-process from the Python package. Only how the console script
reaches it changes.

1. **The console script and `python -m opentide` are `opentide.cli.launch:main`**, a small
   Python entry, not `opentide._native:main`. It imports nothing heavy (no Typer, no `typing`)
   before it decides which implementation runs.
2. **It calls `opentide._native:main` when the run needs the engine and the engine loads.**
   A run that the environment and the root options alone give to Python (the default engine,
   `--version`, `--help`) does not load it. `_native.main` hands the arguments back to
   `opentide.cli.launch.run`, which runs a Rust command in the same process, with the GIL
   released, and gives every other run to the Python CLI in the same process.
3. **When the engine cannot be imported, the Python CLI answers every run.** The commands that
   need the engine fail with `engine_unavailable`, `OPENTIDE_ENGINE=rust` runs included. This
   keeps the rule in `AGENTS.md` ("Analysis engine"): a missing engine is `engine_unavailable`
   and never takes the Python commands down. A console script inside the extension module could
   not start at all without it.
4. **Startup.** These figures come from `cargo xtask bench --engine rust --only startup,explain`,
   10 runs per round over three rounds, on a shared 2.3 GHz Xeon (load average 3 to 6). They are
   taken through `.venv/bin/opentide` with the engine in the `develop` profile:
   - `opentide --version` (`startup`): 0.015 to 0.016 s, against the 0.020 s budget;
   - `OPENTIDE_ENGINE=rust opentide --json explain vocab_unknown`: 0.022 to 0.026 s, against
     0.030 s.

   A bare `python -c pass` took 13 to 15 ms in the same environment.

## Evidence

- Plan: [§1 Decisions](https://github.com/opentidehq/opentide/blob/docs/unified-core-plan/docs/internal/unified-core.md#1-decisions), [§2 Evidence](https://github.com/opentidehq/opentide/blob/docs/unified-core-plan/docs/internal/unified-core.md#2-evidence) (the launcher row), [§3 Invariants](https://github.com/opentidehq/opentide/blob/docs/unified-core-plan/docs/internal/unified-core.md#3-invariants), [§4 Target architecture](https://github.com/opentidehq/opentide/blob/docs/unified-core-plan/docs/internal/unified-core.md#4-target-architecture), [§6 Work plan](https://github.com/opentidehq/opentide/blob/docs/unified-core-plan/docs/internal/unified-core.md#6-work-plan) (Phase 3), [§8 Distribution](https://github.com/opentidehq/opentide/blob/docs/unified-core-plan/docs/internal/unified-core.md#8-distribution), [§11 Metrics](https://github.com/opentidehq/opentide/blob/docs/unified-core-plan/docs/internal/unified-core.md#11-metrics).
- [PyO3/maturin#368](https://github.com/PyO3/maturin/issues/368): one wheel cannot carry a PyO3 module and a binary.
- The `opentide` names on crates.io and npm are being reserved by UC-0.1, PR [#846](https://github.com/opentidehq/opentide/pull/846).
