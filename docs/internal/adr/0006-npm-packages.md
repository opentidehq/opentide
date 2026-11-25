---
title: "0006: npm packages"
description: "Decision D-6 of the unified core: on npm, @opentide/opentide is both the SDK and the CLI, with one @opentide/opentide-<platform> native package per platform (napi-rs 3; no musl, no WebAssembly fallback), @opentide/wasm for the browser, and the plain opentide name as an alias."
---

# 0006: npm packages

| | |
|---|---|
| Status | Proposed |
| Date | 2026-11-07 (the plan's decision), recorded 2026-11-08; amended 2026-11-12 (UC-5.5: the package layout and names); amended 2026-11-13 (not for the VS Code extension) |
| Decision | D-6 |
| Issues | UC-0.1 [#799](https://github.com/opentidehq/opentide/issues/799), UC-5.3 [#838](https://github.com/opentidehq/opentide/issues/838), UC-5.4 [#839](https://github.com/opentidehq/opentide/issues/839), UC-5.5 [#840](https://github.com/opentidehq/opentide/issues/840) |

## Context

TypeScript users need the SDK, and some need the CLI from npm without Python. The browser needs a WebAssembly build. The PyPI package is already one package that is both the SDK and the CLI. A split into `sdk` and `cli` packages on npm would be one native module behind two names.

## Decision

npm: `@opentide/opentide` is both the SDK and the CLI (`bin: opentide`), with one native package per platform, `@opentide/opentide-<platform>` (napi-rs 3), and `@opentide/wasm` for the browser. The plain `opentide` name is an alias. The [amendment](#amendment-2026-11-12-the-package-layout-and-names) below records the layout, the native packages' names and the platforms.

## Consequences

- **The same shape as PyPI.** One package carries the SDK and the CLI. Its `bin` calls the same `main(argv)` as Python's console script ([ADR 0003](./0003-cli-is-opentide-cli.md)), over the facade ([ADR 0005](./0005-opentide-facade-crate.md)).
- **UC-5.3 builds it.** That item ships `@opentide/opentide` (napi-rs 3), the platform packages, the `bin`, the `.d.ts`, the alias and `@opentide/wasm`, and decides the fate of `@opentide/lsp-client` and `@opentide/lsp-worker`. Its exit criterion: `npx @opentide/opentide --json commands` is byte-identical to PyPI's.
- **Conformance.** UC-5.4's cross-SDK suite runs the same corpus through Rust, Python and Node and expects identical documents.
- **Names.** UC-0.1 (PR [#846](https://github.com/opentidehq/opentide/pull/846)) is reserving `@opentide/opentide` and `opentide` with 0.0.0 placeholders. It found that the `opentide` npm organisation already exists, holding `@opentide/explorer`, which is published from `opentidehq/explorer`.
- **One tag publishes everything,** npm included (UC-5.5, plan §8).

## Amendment (2026-11-12): the package layout and names

The maintainer's decision at UC-5.5 ([#840](https://github.com/opentidehq/opentide/issues/840), PR [#1006](https://github.com/opentidehq/opentide/pull/1006)), which replaces this record's `@opentide/<platform>`.

**The standard napi-rs layout.** Users install `@opentide/opentide`: the JavaScript loader napi-rs generates (`index.js`), the declarations (`index.d.ts`) and the `opentide` bin (`cli.js`), and no native code. It lists one native package per platform under `optionalDependencies`, each at the same version. Each native package declares its `os` and `cpu` (and `libc: ["glibc"]` on Linux) and holds one file, `opentide.<platform>.node` (its `main`), with the licence. npm installs only the one whose `os`, `cpu` and `libc` match the machine; the loader requires it by name. The addon is the thin `bindings/node` crate over the one facade ([ADR 0005](./0005-opentide-facade-crate.md)).

| Native package | Target |
|---|---|
| `@opentide/opentide-linux-x64-gnu` | `x86_64-unknown-linux-gnu` |
| `@opentide/opentide-linux-arm64-gnu` | `aarch64-unknown-linux-gnu` |
| `@opentide/opentide-darwin-x64` | `x86_64-apple-darwin` |
| `@opentide/opentide-darwin-arm64` | `aarch64-apple-darwin` |
| `@opentide/opentide-win32-x64-msvc` | `x86_64-pc-windows-msvc` |
| `@opentide/opentide-win32-arm64-msvc` | `aarch64-pc-windows-msvc` |

**Names: `@opentide/opentide-<platform>`, not `@opentide/<platform>`.** A bare `@opentide/linux-x64-gnu` says nothing about what it is inside an organisation scope that also holds `@opentide/explorer`, `@opentide/lsp-client` and `@opentide/lsp-worker`, and would collide with any other native package the scope ever ships. `@opentide/opentide-<platform>` is the name napi-rs generates from the package name (`napi create-npm-dirs`, the loader it writes), so the loader, the directories under `bindings/node/npm/` and the published names cannot drift apart, and no napi-rs output is renamed by hand.

**No WebAssembly fallback.** napi-rs can build a `wasm32-wasi` package that its loader falls back to where no native package fits. opentide ships none: that build runs under WASI preview 1, which under Node.js and napi-rs has no outbound sockets, so the tenant commands (`query`, `validate query --live`, `deploy`) could not work, and a fallback that silently loses them is worse than an install that says the platform is not supported. The generated loader still probes for `@opentide/opentide-wasm32-wasi`, finds nothing and reports the load error. Revisit when napi-rs supports WASI 0.2 or 0.3, which have sockets. This is not `@opentide/wasm`, the browser build of the engine, which this record keeps.

**No musl.** The maintainer's earlier decision ([publishing](../publishing.md#the-release-train), decision 2): no `linux-*-musl` package, as there is no musllinux wheel and no musl binary. On Alpine the loader finds no package for the machine and fails with its load error.

**Versions and tests.** Every package carries the product's one version, which the release train writes in (`scripts/engine/release.py npm-version`) and checks (`release.py lockstep --npm`). Before anything is published, `scripts/engine/npm-local-registry/test.mjs` publishes the release's tarballs to a throwaway local registry and installs `@opentide/opentide` into a clean project on Linux, macOS and Windows (`publish.yml`'s `smoke-npm`), and on linux-x64-gnu in ci.yml's full set (`npm-install`): npm must choose exactly the host's native package, and the bin, the SDK and the types must work.

## Amendment (2026-11-13): not for the VS Code extension

The maintainer's decision: the VS Code extension is WASI-native ([ADR 0007](./0007-vscode-extension-stays-separate.md#amendment-2026-11-13-the-extension-is-wasi-native)). `@opentide/opentide` stays the npm SDK and CLI for Node.js, because it costs nothing more to provide, but the extension does not consume it, so no extension package carries a native module per platform. Nothing else in this record changes. The "no WebAssembly fallback" above stands: the WASI build the extension runs is the `opentide` CLI compiled to `wasm32-wasip1` and shipped as a release asset, not a napi-rs `wasm32-wasi` package that `@opentide/opentide`'s loader falls back to.

## Evidence

- Plan: [§1 Decisions](https://github.com/opentidehq/opentide/blob/docs/unified-core-plan/docs/internal/unified-core.md#1-decisions), [§6 Work plan](https://github.com/opentidehq/opentide/blob/docs/unified-core-plan/docs/internal/unified-core.md#6-work-plan) (Phase 5), [§8 Distribution](https://github.com/opentidehq/opentide/blob/docs/unified-core-plan/docs/internal/unified-core.md#8-distribution).
- PR [#846](https://github.com/opentidehq/opentide/pull/846) (UC-0.1): the npm names, the organisation, the placeholders.
- PR [#1006](https://github.com/opentidehq/opentide/pull/1006) (UC-5.5): the amendment, the release train that publishes the packages, and the local-registry install test.
- The 2026-11-13 amendment: the maintainer's decision that the extension is WASI-native (unit W1 of the unified-core epic, [#790](https://github.com/opentidehq/opentide/issues/790)).
