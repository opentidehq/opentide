---
title: WASI cold start (#1767)
description: Where the WASI language server's start to first diagnostics goes, under wasmtime and Node's WASI, what was cut, and what is left.
---

# WASI cold start (#1767)

The VS Code extension runs the language server as WASI, so its start to first diagnostics
(`scripts/perf/lsp-bench.mjs`: spawn, `initialize`, `didOpen` of a rule, the first pull) is what a user
feels first. #1759's budgeted job holds it under wasmtime 38; the WASI scenarios missed #1746's targets
on CI runners (small 192.6 / 240.2 ms against 192, large 419.4 / 522.3 ms against 350).

All figures here: one 4 vCPU machine (not CI's), release builds with the release profile's LTO,
wasmtime 38.0.3 and Node 22 (`scripts/engine/wasi-run.mjs`, `--no-turbo-fast-api-calls`), 12 runs of each
build alternating after a warm-up run, medians. The machine is noisy (a median moves 10 to 15% between
sessions): compare builds measured together only.

## Where the time goes

A start has three parts, and a host with no threads pays all of them in line:

| Part | What | Measured |
|---|---|---|
| Module load | wasmtime's cache holds the compiled module zstd-compressed and decompresses it on every start (a 49 MB `.cwasm` for the 15.3 MB module: 150 ms of the 170 ms of `opentide-lsp --version`); Node compiles each function the first time it runs | `initialize` result at 125 to 200 ms (wasmtime), 90 to 110 ms (Node) |
| First request | what native hides on warm-up threads and a threaded workspace load: decoding the datasets, building the KQL catalog, loading the workspace, the first validation | small workspace 70 to 90 ms, large 270 ms (wasmtime) |
| After the first answer | the field catalog (`models::build`, 160 to 190 ms) is built in line, but after the first diagnostics are sent (no thread to put it on); it delays the next request, not this one | not in the figure |

`OPENTIDE_LSP_TIMING=1` now works under WASI (`wasmtime run -S inherit-env`; the browser build, which has no
clock, keeps it off). For a rule with a KQL query on the small workspace the first request is 64 ms of
`analysis: the engine` (the KQL catalog is most of it) and 29 ms of `validate: the open files`; on the large
one, 41 and 106 ms, and 135 ms of workspace load (a thousand objects parsed on one thread).

Callgrind of the same sequence on a native build with the warm-up threads off (a proxy for WASI's single
thread): the KQL catalog was 56% of the first request (276M of 490M instructions): 114M of it TOML parsed at
run time (the core operators, functions, plugins and types, the hand-written Sentinel and Defender rows), 99M
the Azure Monitor tables' decode, the rest the rows built from them.

## What changed

1. **The KQL catalog's rows are pre-parsed at build time** (`crates/opentide-kql/src/rows_model.rs`,
   `build.rs`): the core and hand-written rows were the only KQL data still parsed from TOML on the first query
   (#1746 pre-parsed the Azure Monitor tables and the other languages' catalogs). Natively the first
   request goes from 490M to 393M instructions, `Catalog::for_workspace` from 276M to 179M. A test holds each
   pre-parsed row to the row read item by item from the TOML.
2. **The WASI language server is built with opt-level `s`** (`[profile.wasi-lsp]`, `build-wasm.sh wasi`): the
   module is 22% smaller (15.3 to 11.9 MB, the compiled module 49.5 to 36.5 MB), which is what both hosts pay
   on every start. Validation, which runs in the code, takes about 15 ms longer; the module load saves 40 to
   50 ms. Native builds keep `release`.
3. `OPENTIDE_LSP_TIMING` works under WASI.

## Before and after

Start to first diagnostics, medians (ms), small / large workspace:

| Host | Before | After | Change |
|---|---:|---:|---:|
| wasmtime 38 | 244 / 408 | 201 / 389 | -18% / -5% |
| Node 22 WASI | 313 / 429 | 271 / 371 | -13% / -14% |
| native (no regression) | 70 / 99 | 62 / 94 | -11% / -5% |

On CI's runner class the same ratios take the small scenario from 192.6 / 240.2 to about 158 / 198 ms. The
large one reaches about 400 / 497 ms: still above its 350 ms target, which stays waived.

## What is left

- **Large workspace**: the first request spends 135 ms loading a thousand objects on one thread and 106 ms in the
  first validation (the graph over every object, for one file), which no data change removes.
- **The KQL catalog is still about 40% of the first request** (179M instructions): the Azure Monitor tables'
  decode (99M) and the 40,000 column rows built from it (65M). Only the tables a query names are read:
  decoding the reference per table and building a table's columns the first time something asks for them would
  take most of it away. It reaches into `Catalog::columns`, which `apply_declared` and the completions read
  directly, so it is a change of its own.
- **Compiling the module, for the extension** (a separate repository; a recommendation to measure there): under
  Node's WASI the module is compiled by V8 (30 ms for this module here, Liftoff first, each function again at
  its first call, which is most of the 40 ms the first request spends over wasmtime's). Node 22 has no
  persistent code cache for a `WebAssembly.Module` (V8's code cache is for JavaScript scripts), so the compile
  repeats whenever the extension host restarts. Within one extension-host process a compiled module is reused
  for every instance: compile it once, when the extension activates and before the first document opens, and
  instantiate it for each server start, so that no start but the first compiles at all and the first does it
  while VS Code is still loading the workspace. Starting the server itself on activation moves the module load
  and the workspace load off the first document's wait the same way.
