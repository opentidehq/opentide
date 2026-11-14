---
title: "0007: The VS Code extension stays separate"
description: "Decision D-7 of the unified core: opentidehq/vscode-extension stays a separate repository and is WASI-native: it runs the opentide CLI compiled to wasm32-wasip1 under VS Code's WASI host, at one pinned version; @opentide/opentide stays the npm SDK and CLI."
---

# 0007: The VS Code extension stays separate

| | |
|---|---|
| Status | Proposed |
| Date | 2026-11-07 (the plan's decision), recorded 2026-11-08; amended 2026-11-13 (the extension is WASI-native) |
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

## Amendment (2026-11-13): the extension is WASI-native

The maintainer's decision, which replaces "consumes `@opentide/opentide`" above. The extension runs the `opentide` CLI itself, compiled to `wasm32-wasip1`, under VS Code's WASI host (`@vscode/wasm-wasi`, which runs in the desktop and on vscode.dev). It pins one release's `.wasm`, so the coupling stays one version number. `@opentide/opentide` stays the npm SDK and CLI ([ADR 0006](./0006-npm-packages.md#amendment-2026-11-13-not-for-the-vs-code-extension)); the extension does not use it.

- **One light module, the CLI's own behaviour.** The workspace arrives as preopened folders (the host's mount points), so there is no file-system bridge. The cross-repository contracts travel on stdio as they do today: `opentide serve` (JSON-RPC), `opentide lsp start` (the language server, through `@vscode/wasm-wasi-lsp`) and `opentide mcp start`. One `.wasm` serves every platform; the target is one `.vsix` of at most 15 MiB (plan §11).
- **No network under WASI.** `wasm32-wasip1` has no sockets and the WASI host gives the module no other way out, so the tenant operations (`query`, `validate query --live`, `deploy` to a tenant, `doctor --network`, `validate --check cve`'s lookups) fail with a clear error that names the native CLI. Everything else works: validate, lint, explain, info and the catalogue, generate, compile and `deploy --dry-run`, migrate, new, setup, serve, lsp and mcp, with the terminal UI refusing as it does without a terminal.
- **Held to the goldens.** CI runs `cargo xtask golden check --runner wasi`, the WASI build under wasmtime, over every golden case that needs no network. The cases it leaves out are listed, each with its reason, and only network cases may be on the list.
- **The cross-repository contracts and the licence review above are unchanged.** An EUPL-1.2 module run in-process by the MIT extension is the case the review covers.

## Evidence

- Plan: [§1 Decisions](https://github.com/opentidehq/opentide/blob/docs/unified-core-plan/docs/internal/unified-core.md#1-decisions), [§3 Invariants](https://github.com/opentidehq/opentide/blob/docs/unified-core-plan/docs/internal/unified-core.md#3-invariants), [§6 Work plan](https://github.com/opentidehq/opentide/blob/docs/unified-core-plan/docs/internal/unified-core.md#6-work-plan) (Phase 6), [§7 Rollout](https://github.com/opentidehq/opentide/blob/docs/unified-core-plan/docs/internal/unified-core.md#7-rollout), [§10 Risks](https://github.com/opentidehq/opentide/blob/docs/unified-core-plan/docs/internal/unified-core.md#10-risks), [§11 Metrics](https://github.com/opentidehq/opentide/blob/docs/unified-core-plan/docs/internal/unified-core.md#11-metrics).
- [opentidehq/vscode-extension#75](https://github.com/opentidehq/vscode-extension/issues/75): the extension in-process (UC-6.1).
- The 2026-11-13 amendment: the maintainer's decision that the extension is WASI-native (unit W1 of the unified-core epic, [#790](https://github.com/opentidehq/opentide/issues/790)); `@vscode/wasm-wasi` 1.0.1's API (mount points, stdio pipes, no sockets).
