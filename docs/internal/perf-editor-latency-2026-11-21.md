---
title: "Editor latency: Ctrl+Space, hover and diagnostics (2026-11-21)"
description: "Why Ctrl+Space took seconds in the VS Code extension, measured per runtime tier (Python 0.28.1, native, WASI, browser engine) and in VS Code, the cause in the server's workspace diagnostics, the fix, the regression gate and what is left."
---

# Editor latency: Ctrl+Space, hover and diagnostics (2026-11-21)

Customers reported that Ctrl+Space in the VS Code extension took a very long time to show anything. This is the measurement, the cause, the fix, and what is left.

## Summary

- **The reported slowness is real and reproduces.** With the released extension (0.1.2) and the Python `opentide` 0.28.1 it installs for users, on a workspace of 1,200 objects, a completion, a hover or a keystroke that lands while the server is busy waits **up to 3 s** (in VS Code: cold completion p95 2828 ms, typed p95 2696 ms, worst 3048 ms). On 12 objects it does not happen (worst warm completion 11 ms).
- **Cause: the server, driven by a client loop.** vscode-languageclient asks the server for the diagnostics of every file again **two seconds after each answer, for as long as the editor runs** (`workspace/diagnostic`). The server answered each pull by analysing every closed object file in turn, on the one thread that also answers completions. A pull took 3.0 s (Python 0.28.1), 0.45 s (native 1.0.0-rc.2), 0.85 s (the WASI module); Ctrl+Space waited for it. The extension's own code adds about 2 to 5 ms per request (in-editor against scripted warm medians).
- **Fix (this PR, `opentide-lsp`):** for a client that watches files (VS Code does), a closed file's analysis is kept until its text, the configuration or the catalogs change, and a repeat pull with nothing changed is answered from the last report; a batch answers hovers and completions before the diagnostics requests that arrived with them; the KQL catalogs load on a start-up thread. A client that does not watch files is told nothing of what changes on disk, so nothing is kept for it and its pulls cost what they did. **Measured gate: the longest completion beside workspace pulls is 0.41 s before, 0.006 s after** (500-rule benchmark workspace, idle), and **0.63 s before, 0.24 s after a keystroke**; `cargo xtask bench` holds them to 50 ms and 0.5 s (`lsp_editor_latency`, `lsp_editor_typing_latency`). In VS Code on the 1,200-object workspace, typed completion p95 fell from 355 to 102 ms and cold completion p95 from 425 to 194 ms.
- **The same fix, built for WASI** (tier 4, node:wasi): worst warm completion 1.14 s to 0.58 s, hover p95 346 ms to 0.9 ms, first diagnostics 0.77 s to 0.60 s. The browser engine (tier 5) has no workspace pull and was never affected by it; it is flat but starts in about 2 s in the editor and holds 280 to 360 MiB.
- **Not fixed here:** while you type, every edit makes the server validate and lint the whole workspace again (about 0.1 s for the edited file's diagnostics and 0.2 s for the next workspace pull at 1,200 objects). That is `opentide-workspace`, shared with `opentide validate` and `lint`; it is the next item (below). Completions that land inside such a pull still wait up to that long (321 ms worst in VS Code).
- **Extension side:** the combination users run today (extension 0.1.2 with PyPI 0.28.x) needs a client-side mitigation, since they will not have this server fix: skip the workspace pull for a server older than the fixed one. Patch below.

## Method

**Machine.** 4 vCPU (Intel Xeon @ 2.10 GHz), 16 GiB, Linux 6.18, Node v22.23.5, VS Code 1.147.0 (stable at the time, SHA-256 checked), one container, nothing else running during a measurement. All timings are wall clock from the client's side. Absolute numbers move with the machine; compare rows of one table.

**What was measured** (each row: 6 fresh server processes, scripted; 4 fresh VS Code launches, in-editor):

| Metric | How |
|---|---|
| Start-up | spawn to the `initialize` result |
| First diagnostics | `didOpen` of a rule to its first diagnostics (pulled, as the extension does, or pushed when the server offers no pull) |
| Edit to diagnostics | one keystroke to the next diagnostics (scripted: `didChange`, then `textDocument/diagnostic`; in-editor: an edit that adds or removes a finding, until the finding appears or goes) |
| Completion | `textDocument/completion` at five positions of the rule (after `\| ` and after `where ` in the KQL query, a new key at the top level, a new key in the platform block, an ATT&CK technique value), **cold** (the first of its kind in a fresh server), **warm** (the same again, 15 times, 100 ms apart), **typed** (after a keystroke, 5 times) |
| Hover, tokens | `hover` at a KQL column and a YAML key; `semanticTokens/full`, cold and warm |
| Workspace pull | each `workspace/diagnostic` the client loop sends |
| Memory | VmHWM of the server's process tree after the run |
| Payload | items and bytes of each completion |

p50 / p95 / max are over the pooled samples of all runs and scenarios (about 450 completion samples a row). The raw samples are kept: `docs/internal/perf/data/*.json`.

**The scripted client** (`scripts/perf/lsp-bench.mjs`, node, no dependencies) talks JSON-RPC to the server directly. It declares what VS Code's client records (pytest-lsp's `visual-studio-code` capabilities) plus pull diagnostics with refresh support, because the capabilities decide what the server does: with `didChangeWatchedFiles` the server keeps its caches, without it the disk is read again for every message. **It also runs vscode-languageclient's workspace pull loop** (`lib/common/diagnostic.js`, `pullWorkspace`: a pull at start, then 2 s after each answer, with the result ids fed back), because that loop is what the server is busy with in an editor. A first version of the harness lacked it and measured a server that was never busy: completion looked like 1 ms everywhere, and the repository's own `lsp_first_diagnostics` benchmark has the same blind spot.

**In-editor** (`scripts/perf/editor/`): VS Code under Xvfb with the extension from `main` (0.1.2, `0ad2c6b`) loaded in development mode, each runtime selected through `opentide.path` (for the bare language servers the file must be named `opentide-lsp`: the extension takes the runtime's kind from the name), and an extension-host test that times `vscode.executeCompletionItemProvider` and `onDidChangeDiagnostics`, so the client, its middleware and VS Code's merge of providers are in the time. A run fails if the server it was told to use is not running (a first attempt silently measured the extension's WASM fallback).

**Workspaces.** *small*: `tests/fixtures/tide_corpus` as the CLI end-to-end suite lays it out (12 objects, 6 platforms). *large*: the same plus copies of its rules with fresh UUIDs and names, 1,200 objects (`scripts/perf/make_workspace.py`); the QA run's 1,000+. The benchmark gate uses the repository's own heavy workspace (500 rules).

**Runtimes.**

| Row | What it is |
|---|---|
| `py0.28.1` | **Before.** PyPI `opentide==0.28.1`, `opentide lsp start`: the Python package the released extension runs |
| `engine0.10.0` | **Before, browser tier.** language-server 0.10.0's `opentide-wasm-web` (the engine `pins.json` pins, SHA-256 checked), in a worker as the extension runs it, the workspace given on `initialize` |
| `native-rc2` | **After, tier 1.** `opentide-lsp` 1.0.0-rc.2 (GitHub Release asset, checksum verified) |
| `py1.0.0rc2` | Tier 1 through the PyPI wheel: `opentide lsp start` of 1.0.0rc2 |
| `wasi-rc2` | **Tier 4.** rc.2's `opentide-lsp-wasm32-wasip1.wasm` under Node's `node:wasi` (`scripts/engine/wasi-run.mjs`) |
| `engine-rc2` | **Tier 5.** rc.2's `opentide-wasm-web` in a worker |
| `native-head` | `integration/unified-core` at `8b55d0c3`, built `--release` (LTO) with symbols |
| `native-fix-a` | that plus the analysis cache, the batch order and the KQL warm-up |
| `native-fixed` | **After.** that plus the workspace report cache: this branch |
| `wasi-fixed` | this branch's `opentide-lsp` built for `wasm32-wasip1` and run the same way as `wasi-rc2` |

Not measured, and why: the WASI module under `@vscode/wasm-wasi` inside the extension host (it needs #82's extension build and its bundled module; the in-editor rows cover tier 1, Python and the engine fallback on `main`, and the node:wasi rows are the same module's cost without the extension host's own plumbing); the browser tier is not rebuilt for the "after" (it has no workspace pull, so the change does not reach it; its rc.2 row is its "after").

## Results

> **Which build.** The scripted and in-editor rows for `native-fixed` and `wasi-fixed` were measured with the build before the review fixes (no-watcher clients, the `shutdown` flush, the per-root catalog epoch). Those change nothing for a client that watches files, which the harness and VS Code are, and the single-root workspaces measured; the gate rows below were re-run on the final build.

### Scripted client: small workspace (12 objects)

Entries are p50 / p95 / max in ms.

| Tier | Start → `initialize` ms | First diagnostics ms | Edit → diagnostics ms | Completion cold ms | Completion warm ms | Completion typed ms | Hover warm ms | `semanticTokens/full` cold ms | `workspace/diagnostic` ms | RSS MiB |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| py0.28.1 | 556 / 5245 / 6797 | 237 / 318 / 324 | 3.96 / 90.6 / 108 | 4.66 / 15.1 / 20.1 | 0.74 / 8.82 / 11.0 | 1.02 / 8.12 / 11.1 | 0.96 / 1.75 / 2.03 | 5.12 / 6.49 / 6.73 | 31.3 / 85.5 / 104 | 127 |
| engine0.10.0 | 115 / 585 / 737 | 380 / 497 / 521 | 5.92 / 11.0 / 12.4 | 1.53 / 10.9 / 12.2 | 0.69 / 10.8 / 17.3 | 1.01 / 11.2 / 17.2 | 0.98 / 1.94 / 2.36 | 8.24 / 10.8 / 11.1 | 0.43 / 2.88 / 5.83 | 279 |
| native-rc2 | 1.92 / 486 / 648 | 182 / 305 / 339 | 11.4 / 98.5 / 107 | 1.98 / 7.11 / 7.88 | 1.06 / 6.73 / 17.0 | 1.07 / 6.20 / 19.4 | 0.67 / 0.85 / 1.27 | 15.7 / 16.4 / 16.4 | 19.0 / 78.4 / 89.6 | 121 |
| py1.0.0rc2 | 22.6 / 1977 / 2627 | 213 / 340 / 376 | 16.2 / 111 / 116 | 1.68 / 6.40 / 6.99 | 1.14 / 6.72 / 9.83 | 1.07 / 6.50 / 16.5 | 0.69 / 1.00 / 20.2 | 14.0 / 16.9 / 17.4 | 18.4 / 92.7 / 98.9 | 142 |
| wasi-rc2 | 138 / 559 / 696 | 360 / 371 / 371 | 15.0 / 478 / 530 | 4.38 / 10.1 / 12.3 | 1.07 / 6.02 / 9.05 | 1.10 / 6.33 / 32.0 | 0.59 / 0.75 / 6.35 | 15.0 / 21.3 / 22.5 | 24.9 / 440 / 513 | 262 |
| wasi-fixed | 122 / 127 / 128 | 319 / 340 / 346 | 13.6 / 444 / 464 | 4.02 / 12.5 / 22.4 | 1.00 / 5.37 / 11.0 | 1.06 / 6.05 / 18.5 | 0.56 / 0.78 / 1.59 | 16.3 / 21.7 / 21.9 | 19.3 / 426 / 449 | 297 |
| engine-rc2 | 129 / 495 / 611 | 385 / 531 / 533 | 19.3 / 26.7 / 29.5 | 3.42 / 12.3 / 13.0 | 1.16 / 5.97 / 7.72 | 1.32 / 5.89 / 7.36 | 0.68 / 0.90 / 2.34 | 16.0 / 17.5 / 17.8 | 0.52 / 1.47 / 1.57 | 304 |
| native-head | 1.78 / 462 / 615 | 167 / 285 / 318 | 11.5 / 94.6 / 116 | 2.01 / 5.92 / 5.97 | 1.00 / 6.13 / 9.86 | 0.97 / 6.88 / 15.8 | 0.66 / 0.90 / 4.75 | 17.3 / 17.8 / 17.9 | 18.5 / 73.0 / 98.9 | 121 |
| native-fix-a | 2.27 / 582 / 775 | 208 / 224 / 228 | 15.3 / 108 / 114 | 2.03 / 5.84 / 10.1 | 1.06 / 6.74 / 24.0 | 1.04 / 6.71 / 11.4 | 0.67 / 0.90 / 5.16 | 14.2 / 20.4 / 22.0 | 16.5 / 88.2 / 98.7 | 121 |
| native-fixed | 1.99 / 5.04 / 5.94 | 161 / 195 / 201 | 10.9 / 76.6 / 78.4 | 1.72 / 6.45 / 8.48 | 1.03 / 6.38 / 8.40 | 1.02 / 6.46 / 10.00 | 0.63 / 0.82 / 4.10 | 11.7 / 16.7 / 17.3 | 15.8 / 64.4 / 68.3 | 123 |

### Scripted client: large workspace (1,200 objects)

| Tier | Start → `initialize` ms | First diagnostics ms | Edit → diagnostics ms | Completion cold ms | Completion warm ms | Completion typed ms | Hover warm ms | `semanticTokens/full` cold ms | `workspace/diagnostic` ms | RSS MiB |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| py0.28.1 | 529 / 634 / 656 | 337 / 522 / 581 | 21.4 / 3216 / 3506 | 16.1 / 31.8 / 33.9 | 0.69 / 9.15 / 13.5 | 22.5 / 3011 / 3386 | 0.96 / 2.11 / 3038 | 6.45 / 7.34 / 7.44 | 2976 / 3204 / 3479 | 162 |
| engine0.10.0 | 228 / 267 / 268 | 360 / 469 / 492 | 21.8 / 26.3 / 32.5 | 16.2 / 28.9 / 31.6 | 0.64 / 6.93 / 11.8 | 16.6 / 25.8 / 32.3 | 0.76 / 1.89 / 2.65 | 8.32 / 9.32 / 9.40 | 0.45 / 0.58 / 2.50 | 298 |
| native-rc2 | 2.08 / 2.39 / 2.40 | 251 / 280 / 288 | 97.4 / 655 / 684 | 3.39 / 8.59 / 10.2 | 1.11 / 7.43 / 526 | 3.50 / 413 / 515 | 0.66 / 0.97 / 520 | 90.2 / 104 / 104 | 441 / 559 / 588 | 161 |
| py1.0.0rc2 | 25.1 / 27.3 / 27.5 | 293 / 340 / 349 | 117 / 664 / 848 | 4.35 / 10.9 / 11.4 | 1.15 / 9.45 / 592 | 3.58 / 388 / 489 | 0.67 / 1.19 / 502 | 89.4 / 110 / 113 | 473 / 601 / 694 | 182 |
| wasi-rc2 | 137 / 155 / 157 | 770 / 820 / 829 | 201 / 1603 / 1783 | 4.31 / 13.6 / 15.1 | 1.19 / 712 / 1142 | 2.85 / 10.6 / 22.8 | 0.60 / 346 / 892 | 222 / 591 / 695 | 849 / 1334 / 1588 | 317 |
| wasi-fixed | 117 / 131 / 135 | 603 / 632 / 636 | 193 / 1473 / 1508 | 4.02 / 10.7 / 13.5 | 1.12 / 408 / 579 | 2.63 / 7.83 / 10.8 | 0.58 / 0.89 / 402 | 174 / 180 / 181 | 483 / 1235 / 1304 | 323 |
| engine-rc2 | 218 / 249 / 254 | 528 / 557 / 559 | 82.4 / 103 / 114 | 4.69 / 14.2 / 16.2 | 1.39 / 6.90 / 10.7 | 3.78 / 10.8 / 12.6 | 0.67 / 0.87 / 1.14 | 75.9 / 97.9 / 99.3 | 0.56 / 3.81 / 37.1 | 362 |
| native-head | 1.95 / 2.22 / 2.27 | 244 / 255 / 257 | 101 / 676 / 832 | 3.13 / 10.8 / 11.9 | 1.11 / 7.72 / 571 | 3.52 / 392 / 513 | 0.65 / 1.44 / 448 | 111 / 130 / 132 | 448 / 559 / 687 | 162 |
| native-fix-a | 1.94 / 2.57 / 2.66 | 254 / 281 / 286 | 107 / 614 / 696 | 4.43 / 10.9 / 11.6 | 1.17 / 8.16 / 437 | 3.90 / 202 / 453 | 0.68 / 1.47 / 229 | 90.3 / 121 / 131 | 232 / 520 / 591 | 164 |
| native-fixed | 2.62 / 5.43 / 5.49 | 231 / 265 / 267 | 102 / 648 / 706 | 3.62 / 11.4 / 12.1 | 1.19 / 8.23 / 228 | 3.56 / 204 / 355 | 0.67 / 0.96 / 205 | 90.0 / 110 / 115 | 230 / 502 / 619 | 169 |

**Reading the large table.** The *Workspace pull* column is the whole story of the old stacks: 3.0 s for Python 0.28.1, 0.44 s for rc.2 and `head`, 0.85 s in WASI. Every other request that arrives during a pull waits for it, so the worst completion, hover and typed completion sit at the pull's length (`py0.28.1`: typed completion up to 3.4 s, hover 3.0 s; `native-rc2`: 0.5 s; `wasi-rc2`: 0.7 to 1.1 s), while their p50 stay at 1 ms. The browser engine has no workspace pull (nothing to wait for) and is flat, at the cost of a 0.5 s first diagnostics and 360 MiB. `native-fixed` removes the idle-state stall (next section) and cuts the median pull from 0.45 to 0.23 s (the pulls that follow an edit still pay the per-edit validate, cause 3 below, so its p95 is 0.50 s against 0.56 s). `wasi-fixed`, the same code built for `wasm32-wasip1`: worst warm completion 1,142 to 579 ms, hover p95 346 to 0.9 ms, first diagnostics 770 to 603 ms, cold tokens 222 to 174 ms; its post-edit pulls stay at 1.2 s p95 because the validate is 2 to 3 times slower there.

### The gate: completion beside a pull

`cargo xtask bench --engine rust --only lsp_editor_latency,lsp_editor_typing_latency`: ten completions, each 2 ms after a `workspace/diagnostic` of the 500-rule heavy workspace, after two settling pulls (the server's own catalogs arrive after the first pull and make the next analyse every file once). *Idle*: nothing changed since the last pull (the user reading, or pressing Ctrl+Space two seconds after the last edit). *Typing*: a keystroke (`didChange`), the pull of that document and the workspace pull come first, as an editor sends them; the completion waits for the server to validate the workspace again. Median of 7 runs, 4 vCPU.

| Server | Idle: longest completion wait | Idle: median pull | Typing: longest completion wait | Typing: median workspace pull |
|---|---:|---:|---:|---:|
| `native-head` (before) | **0.408 s** | 0.390 s | **0.634 s** | 0.574 s |
| `native-fixed` (this branch) | **0.006 s** | 0.006 s | **0.237 s** | 0.214 s |

Budgets in `tests/bench/budgets.toml`: `lsp_editor_latency` 0.05 s and `lsp_editor_typing_latency` 0.5 s. `bench --check` fails both for `native-head` (`median 0.408 s is over the target 0.050 s + 10%`, `median 0.634 s is over the target 0.500 s + 10%`) and passes both for this branch. The typing number is the per-edit validate (cause 3): the budget stops it getting worse, and an incremental validate would lower it. The oracle (0.23.0) is not measured.

### In VS Code 1.147.0, large workspace

Entries are p50 / p95 / max in ms.

| Runtime (in VS Code 1.147.0) | Launches ok | First diagnostics ms | Edit → diagnostics ms | Completion cold ms | Completion warm ms | Completion typed ms | Server RSS MiB |
|---|---:|---:|---:|---:|---:|---:|---:|
| py0.28.1 | 4/4 | 1148 / 1280 / 1303 | 87.2 / 2788 / 2853 | 12.8 / 2828 / 2874 | 3.20 / 24.2 / 3048 | 29.0 / 2696 / 2836 | 384 |
| engine0.10.0 | 4/4 | 1949 / 2005 / 2014 | 75.6 / 96.6 / 98.9 | 7.82 / 15.2 / 15.9 | 2.95 / 13.1 / 39.2 | 22.3 / 32.5 / 38.4 | - |
| native-rc2 | 4/4 | 444 / 1159 / 1280 | 143 / 354 / 379 | 43.3 / 378 / 402 | 5.76 / 27.5 / 358 | 74.2 / 318 / 425 | 196 |
| native-head | 4/4 | 398 / 995 / 1100 | 144 / 320 / 348 | 42.2 / 425 / 432 | 5.47 / 44.5 / 360 | 69.6 / 355 / 448 | 201 |
| native-fixed | 4/4 | 660 / 967 / 976 | 139 / 321 / 377 | 39.2 / 194 / 214 | 4.98 / 32.7 / 321 | 72.5 / 102 / 171 | 205 |

`py0.28.1` is the released combination. Its cold p95 of 2.8 s is the first Ctrl+Space after open: the server is in its first pull. `engine0.10.0` is what the extension falls back to with no opentide installed: no stalls, 2 s to first diagnostics (the extension reads 1,200 files through `vscode.workspace.fs` in 1.1 to 1.6 s before the engine starts). The native rows, before and after, are the same server stack with and without this branch.

### Payload and content (small workspace)

| Tier | after `\| ` | after `where ` | YAML key | platform key | ATT&CK technique |
|---|---:|---:|---:|---:|---:|
| py0.28.1 | 0 / 0.0 KiB | 0 / 0.0 KiB | 1 / 0.3 KiB | 8 / 2.0 KiB | 370 / 138.5 KiB |
| engine0.10.0 | 0 / 0.0 KiB | 0 / 0.0 KiB | 1 / 0.3 KiB | 8 / 2.0 KiB | 370 / 138.5 KiB |
| native-rc2 | 54 / 15.8 KiB | 229 / 54.8 KiB | 1 / 0.3 KiB | 8 / 2.0 KiB | 370 / 138.5 KiB |
| py1.0.0rc2 | 54 / 15.8 KiB | 229 / 54.8 KiB | 1 / 0.3 KiB | 8 / 2.0 KiB | 370 / 138.5 KiB |
| wasi-rc2 | 54 / 15.8 KiB | 229 / 54.8 KiB | 1 / 0.3 KiB | 8 / 2.0 KiB | 370 / 138.5 KiB |
| wasi-fixed | 54 / 15.8 KiB | 229 / 54.8 KiB | 1 / 0.3 KiB | 8 / 2.0 KiB | 370 / 138.5 KiB |
| engine-rc2 | 54 / 15.8 KiB | 229 / 54.8 KiB | 1 / 0.3 KiB | 8 / 2.0 KiB | 370 / 138.5 KiB |
| native-head | 54 / 15.8 KiB | 229 / 54.8 KiB | 1 / 0.3 KiB | 8 / 2.0 KiB | 370 / 138.5 KiB |
| native-fix-a | 54 / 15.8 KiB | 229 / 54.8 KiB | 1 / 0.3 KiB | 8 / 2.0 KiB | 370 / 138.5 KiB |
| native-fixed | 54 / 15.8 KiB | 229 / 54.8 KiB | 1 / 0.3 KiB | 8 / 2.0 KiB | 370 / 138.5 KiB |

The ATT&CK technique list is 370 items and 138 KiB a request, each with its documentation inline, although the server implements `completionItem/resolve`. It costs 4 to 18 ms, not seconds, so it is not the complaint, but it is the largest payload by far and moving enum documentation to resolve is a cheap follow-up (not done: it changes the text clients show). **The 0.10.0 engine and Python 0.28.1 return no items after `| ` or `where ` in a rule's KQL query** (0 items; rc.2 and later return 54 and 229): Ctrl+Space there would show "No suggestions", which users may read as broken too.

## Where the time goes (profiles)

Details and the call trees: [`perf/profiles.md`](perf/profiles.md). Reproduce: `scripts/perf/lsp-script.mjs` under `valgrind --tool=callgrind`, and `OPENTIDE_LSP_TIMING=1` (new, below) for wall time per request and phase.

1. **Workspace pull, before: 35% of all instructions of the session** are one handler, and almost all of that is `opentide_analysis::analyze` once per closed file (28% `analyze_lines`, of which 18% the queries of each rule (`analyze_injections`), 6% semantic-token highlighting nobody asked for, 3% injection extraction). 2,399 analyses for 2 pulls of 1,199 files: nothing is kept between pulls.
2. **Start-up work done on first use, inside the first requests:** the Tide field catalog build (`models::build`, 24 to 31% of a short session) and the KQL catalogs (the Azure Monitor tables parsed from TOML, 10 to 24%). They explain the 90 ms cold `semanticTokens/full` and a first diagnostics of 160 to 250 ms. The field catalog was already built on a warm-up thread, which the first request waits for; the KQL catalogs were not.
3. **Per edit:** the timing trace shows 190 ms for the workspace's `validate` (once per edit, then cached) and 92 ms for the edited file's own findings, because `opentide lint`'s filename check reads every object file of the folder even for one file (`lint_with`'s `every`), and the validate of one file resolves the workspace.
4. **Completions and hovers themselves are cheap:** p50 0.2 to 1 ms for hover, 0.8 ms for completion (130 requests, max 10 ms), 4 ms for the technique list.

## Root causes, by layer

| # | Layer | Cause | Effect | State |
|---|---|---|---|---|
| 1 | Server (`opentide-lsp`, and 0.28's server) | `workspace/diagnostic` analyses every closed file per pull, uncached, on the single request loop | A hover, completion or keystroke waits 0.45 s (native) to 3 s (Python 0.28.1), every 2 s for as long as the editor runs | **Fixed** (cache, report cache, batch order) |
| 2 | Client library | vscode-languageclient repeats the workspace pull 2 s after every answer, forever (`diagnostic.js:303-318`, `:841-842`, 10.1.2) | Turns cause 1 into a stall at a steady rate | By design; the extension has no switch (E1) |
| 3 | Server (`opentide-workspace`) | Per edit: `validate` of the workspace and `lint` of one file read every object file | 0.1 s for the edited file's diagnostics and 0.2 s for the next pull at 1,200 objects; grows with the workspace | **Open** (follow-up) |
| 4 | Server start-up | Catalogs built on first use | Cold first diagnostics 160 to 250 ms; cold tokens 90 ms | Partly (KQL catalogs warm up beside the models) |
| 5 | Runtime tier 4 (WASI) | The same code 2 to 3 times slower (no threads: the workspace index is built on one thread; `node:wasi` file access) | Pull 0.85 s, first diagnostics 0.77 s, 317 MiB | The fix applies (`wasi-fixed`: worst warm completion 1.14 s to 0.58 s, first diagnostics 0.77 s to 0.60 s); post-edit pulls still 1.2 s p95 |
| 6 | Runtime tier 5 (browser engine) | No filesystem: the extension feeds 1,200 files through `vscode.workspace.fs` before it starts | 1.1 to 1.6 s of the 2 s to first diagnostics; 280 to 360 MiB | Extension side (E2) |
| 7 | Extension | Client plumbing | 2 to 5 ms per request | Nothing to do |

The customer-reported case is **1 + 2** on the Python 0.28.x server: three seconds of every ten, for as long as a 1,000-object workspace is open. A workspace of a dozen objects never shows it.

## The fixes (`perf/lsp-completion-latency`)

1. **A closed file's analysis is kept** (`crates/opentide-lsp/src/session.rs`: `DiskFile::analysis`, `closed_analysis`). It depends on the file's text, the Elastic configuration and the installed catalogs and datasets, and on nothing else (`opentide_analysis::analyze` reads no other object), so it is keyed by a new `env_epoch`, bumped by every cause of `generation` except an edit of, or a change to, an object file. Typing in one rule leaves the other 1,199 alone. A catalog arriving, `visibility.toml` or an Elastic or other configuration file changing (a watcher event, or an open buffer) bumps it. **Only for a client that declares `workspace.didChangeWatchedFiles`**: for one that does not, nothing tells the server what changed on disk (it resolves the configuration again with each batch and no counter moves), so nothing is kept and each pull reads the disk as it did before.
2. **A repeat pull is answered from the last report** (`workspace_report`, keyed by `(generation, env_epoch)`, same condition), which also makes the `resultId` comparison free.
3. **A batch answers `workspace/diagnostic` and `textDocument/diagnostic` last** (`protocol.rs`, `DEFERRED`): a hover or completion queued with them goes first. They are answered before a `shutdown` or `exit` in the same batch (not refused for the server being shut down by then), and are `ContentModified` when the batch edits or closes their document later; cancellation is unchanged.
3a. **The catalog epoch moves when a root's own catalog does** (`CatalogSightings`): requests that alternate between roots install each root's catalog in turn, which is not a catalog that changed. Before, each switch bumped the epoch and the caches of a multi-root workspace never hit.
4. **The KQL catalogs load on a start-up thread** beside the models (`server.rs`, through the public `analyze_query`, so it holds whatever the dataset loaders become). A/B, 20 runs each, interleaved twice, small workspace: first diagnostics p50 169 / 166 ms to 162 / 163 ms, p95 235 / 226 to 192 / 203 ms. Small, consistent, in the tail; the field catalog build, not this, is the critical path.
5. **`OPENTIDE_LSP_TIMING=1`** writes `opentide-lsp: timing <span> <ms>` to stderr for each request and the phases of a pull and of an open document's analysis (`timing.rs`; off it is one atomic load; no clock on WebAssembly targets).
6. **A budgeted regression gate** (`xtask/src/bench/lsp.rs`, `lsp_editor_latency`, `tests/bench/budgets.toml`). It fails for the code before the fix.

Tests (each fails with its fix disabled): `a_workspace_pull_analyses_each_closed_file_once` (a pull, a repeat, a keystroke in an open object, a configuration change), `a_workspace_pull_with_nothing_changed_is_answered_from_the_last_report`, `without_a_watcher_a_workspace_pull_follows_a_configuration_written_on_disk` and `a_client_that_does_not_watch_files_is_never_served_a_kept_report` (the no-watcher client), `a_batch_answers_diagnostics_after_hovers_and_completions`, `a_diagnostics_request_before_shutdown_in_one_batch_is_answered`, `a_deferred_diagnostics_request_for_a_document_closed_later_in_the_batch_is_outdated`, the unit test `switching_between_roots_is_not_a_catalog_that_changed`, and, for the watchers, `a_moved_object_folders_file_changed_on_disk_is_followed_by_the_next_pull`, `the_folders_a_workspace_reads_are_watched_and_watched_again_when_they_move`, `a_client_without_relative_patterns_is_asked_to_watch_by_a_path_glob`, `a_parents_configuration_folder_is_watched_and_followed` and `a_state_shard_written_on_disk_makes_the_next_pull_be_made_again`, and, from the second review, `the_layered_folder_is_the_resolved_roots_parents`, `a_nested_root_does_not_take_the_outer_roots_configuration_event`, `a_brace_above_the_workspace_is_never_watched_by_a_folder_above_it`, `a_parents_visibility_toml_is_a_layered_configuration_file`, `a_parents_configuration_change_goes_to_the_root_it_is_layered_into` (both layers resolve) and `no_watcher_is_registered_before_the_client_is_initialized`.

**What a pull reads from disk (the question of a stale file).** The kept analysis of a closed file is compared with `file.text == text`, but both come from the same `DiskFile` (`closed_objects` hands out the text it holds), so that test only guards against the entry being replaced mid-pull. It does not re-read the disk. For a client that watches files, a file's text is read when the server starts or when its event arrives (`refresh_object`, `refresh_folder`) and not on a pull: a file changed on disk **without an event** is not seen until the next event, and this was already so before this work (the per-file entry existed, the workspace's findings were cached per generation). For a client that does not watch files, nothing is kept and each batch reads the disk again. Watching the folders the workspace reads closes the gaps where a change had no event to carry it. The crate's suite (43 unit, 44 end-to-end, 37 protocol and the rest), xtask's (292 and its integration tests), `cargo fmt --check` and `cargo clippy -D warnings` on `opentide-lsp` and `xtask` pass.

## Follow-ups

1. **Make the per-edit validate incremental** (`opentide-workspace`): the cross-file checks and the filename lint need the objects' names and ids, not their query text; an edit that leaves `uuid`, `name`, `schema` and the references alone need not redo them. That removes the 0.1 to 0.2 s that remains while typing and the scaling with workspace size. A policy alternative: serve closed files' findings from the last report until a save or a close (they are not what the user is editing), which needs `didSave` support.
2. **Move enum documentation to `completionItem/resolve`** when the client declares `resolveSupport` (138 KiB to about 25 KiB for the technique list).
3. **Wait for the root's own catalog before the first pull** (it arrives after, and every file is analysed twice at start-up: the first two pulls cost 0.55 and 0.4 s).
4. **Rebuild the WASI and browser artifacts** from this branch (the release train does) and re-run `scripts/perf/run-matrix.sh wasi-fixed`.
5. **The repository's `lsp_first_diagnostics` benchmark** (not `lsp_editor_latency`, which declares both) declares no file watching and no pull capability, so it measures a server that reads the disk again per message and is never pulled: align it with the editor (`workspace.didChangeWatchedFiles`, pull diagnostics, the workspace loop).

## Extension-side findings (for the extension's owner: not changed here)

**E1. A mitigation for servers older than the fix, the combination users have today** (`src/core/services/languageClient.ts:193-199`, `clientOptions`; `startServer`). vscode-languageclient 10.1.2 runs `pullWorkspace()` at registration and again 2 s after every answer (`lib/common/diagnostic.js:303-318`, `841-842`) whenever the server advertises `workspaceDiagnostics`, and its per-document behaviour then relies on the workspace result (`:268`). The extension sets no middleware for it. For a server without the fix, answer the workspace pull empty and keep the per-document pulls (which carry the open files' diagnostics):

```ts
// src/core/services/languageClient.ts, in startServer, next to `synchronize`
import { satisfies } from "../runtime/version"; // however the repo compares versions
...
middleware: {
  // an opentide-lsp from before the release that carries this fix analyses every file of the workspace on each of the client's
  // workspace pulls (every 2 s), on the thread that answers completions.
  provideWorkspaceDiagnostics: (ids, token, report, next) =>
    serverHasCheapWorkspacePulls(runtime) ? next(ids, token, report) : { items: [] },
},
```

and merge it with the engine tier's `middleware: { workspace: { didChangeWatchedFile: ... } }` at `:304`. The cost: closed files' problems (an `invalid_ref` in a file nobody opened) disappear from the Problems panel for those servers. Make it a setting (`opentide.diagnostics.workspace`, default `auto`: on for a fixed server) if that matters. Measured effect on `py0.28.1`: the pull is the whole of the stall (3.0 s p50, 1,200 objects). The version to compare with is the first release carrying this change.

**E2. The engine tier reads the workspace slowly** (`src/engine/workspace.ts:75-110`, `collectDocuments`; the log line `engine: read 1200 object file(s), 802 KiB, in 1629 ms`). 32 reads at a time, then a `setTimeout(0)` yield per batch, through the extension-host to renderer round trip of `vscode.workspace.fs.readFile`: 1.1 to 1.6 s of the engine tier's 2 s to first diagnostics. Tried on a local checkout of `main` (not pushed): `CONCURRENCY` 32 to 256 in `src/engine/feed.ts:34` took the engine tier's first diagnostics from about 1,950 ms to about 1,730 ms (4 launches each, `data/extension/e2-engine-concurrency256.json`), so batching is a small part of it and the host's per-file `readFile` round trip is most of it. A desktop-only reader that uses `node:fs` for `file:` folders (the web bundle must not import Node built-ins, so it belongs in `src/core/services/languageClient.ts`, passed to `WorkspaceFeed`) would skip that round trip; not tried.

**E3. File watching: the exact set the server reads.** The extension now watches `**/objects/**`, `**/.opentide/configurations/**` and `**/.opentide/schemas/**`. From the code: the server (and the `validate` it runs for the editor) reads from disk, for each root, (1) `objects/**/*.yaml` and `*.yml` (`server.rs` `collect_objects`) and the object folders that `.opentide/configurations/paths.toml` moves elsewhere (`checks.rs`), (2) every file of `.opentide/configurations/` (`platforms/*.toml`, `deployment.toml`, `visibility.toml`, `lint.toml`, `paths.toml`, `sharing/`, ...), and those of the *parent folder's* `.opentide/configurations/` too, which the configuration layers over the root's (`opentide-workspace/src/config.rs:223-227`, not when the root is itself a Tide workspace), and (3) `.opentide/states/deployment/*.json`, whose shards `validate` checks (`deployment_state_*` findings; `state.rs`). It does **not** read `.opentide/schemas/` (the field catalogs are generated in memory from the models and the resolved configuration; the only mention is that a TOML under `.opentide/schemas/` is not taken for a configuration file), nor `.opentide/lsp/catalogs/`, `templates`, `exports` or `inflight`. What the server asks the client to watch (`handlers.rs` `initialized`, `session.rs` `sync_watchers`): the fixed globs `**/objects`, `**/objects/**`, `**/.opentide/configurations/**/*.toml`, `**/.opentide/states/deployment/*.json` and the folders `**/.opentide/states` and `**/.opentide/states/deployment` (a deleted folder is one event), and a second registration for the configuration folder layered in from the root's parent (made as soon as the client has said `initialized`, without a workspace: a layer that does not resolve is the one being mended) and for each object folder `paths.toml` moved outside `objects/` (known once the workspace has loaded, kept while the configuration does not resolve). Folders are spelled as the editor spells the root (the workspace's resolved paths are mapped back: a symbolic link, macOS's `/var`, a Windows short name), as a `RelativePattern` or, for a client without `relativePatternSupport`, as a glob on the path (`[`, `*`, `?` escaped; a folder with a brace in its name by the folder above it, since LSP globs cannot escape a brace, but never one above the root's parent: such a folder is not watched, with a warning in the log, rather than the filesystem or a drive). The layered folder is the *resolved* root's parent's, compared with the workspace's resolved paths, and is left out when it is another root's own configuration folder (nested roots `/w` and `/w/child`); nothing is registered before `initialized`. The registration is replaced (`unregisterCapability`, then a new id) when the set changes, and nothing is sent while it is the same. Events route to what they affect: a moved folder's to `RootChecks::changed` and `touch_object()` (the workspace's findings, no analysis reads that folder), a layered configuration's to `changed` and `touch()` (the analyses read configuration too), a state shard's, or a deleted `states/` folder's, to `changed` and `touch_object()`; `visibility.toml` is the datasets' only for the root whose own `.opentide/configurations/visibility.toml` it is (a parent's is a layered configuration file), and a layered folder that is also an outer root's own configuration folder tells that root too. **A state shard's findings are not shown by the server**: `validate` attributes them to the shard file, which is neither an open document nor an object the pull lists, so no `deployment_state_*` finding appears in a document or a pull (a gap that predates this work, left as a follow-up; the watch keeps the findings it would show current). These are registrations of the server's own, independent of the extension's `fileEvents` globs: the extension need not add any of them. (The old `**/{objects,.opentide}/**` was wider than any of this and included `.opentide/exports` and `.opentide/inflight`, outputs of the extension's own commands.)

**E4. Nothing else found.** The client's own overhead is 2 to 5 ms a request in these runs (in-editor warm p50 against scripted warm p50), the diagnostics are pulled on change (not debounced beyond the library's), and the runtime resolution is off the request path. A runtime named other than `opentide`/`opentide-lsp` falls back to the WASM engine without saying so in the notification, which cost this investigation one run.

## Reproduce

```sh
python3 scripts/perf/make_workspace.py /tmp/ws-small
python3 scripts/perf/make_workspace.py /tmp/ws-large --objects 1200
node scripts/perf/lsp-bench.mjs --workspace /tmp/ws-large --runs 6 --warm 15 --pause 100 \
      --label mine --out mine.json -- target/release/opentide-lsp --stdio
OUT=docs/internal/perf/data WORK=<dir with the artifacts> scripts/perf/run-matrix.sh        # every tier
node scripts/perf/summarize.mjs docs/internal/perf/data                                      # the tables
xvfb-run -a scripts/perf/editor/run-matrix.sh                                                # in VS Code
cargo xtask bench --engine rust --only lsp_editor_latency                                    # the gate
OPENTIDE_LSP_TIMING=1 opentide-lsp --stdio                                                   # per-request trace on stderr
```

Variance: rows are 6 launches; the p95 of a 6-run row moves by about 10% between repeats (first diagnostics of `native-head` on the small workspace was 167 ms in one matrix and 169 in the A/B, p95 285 and 235), so differences under 10% are not claims. The in-editor rows are 4 launches each.
