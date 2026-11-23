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
- **The KQL catalog's reference, once a query names a table**: the table's columns are decoded and turned into
  rows (below); a query that names a table of a big family decodes its shard of 32 tables, 20 KB at most.
- **Compiling the module, for the extension** (a separate repository; a recommendation to measure there): under
  Node's WASI the module is compiled by V8 (30 ms for this module here, Liftoff first, each function again at
  its first call, which is most of the 40 ms the first request spends over wasmtime's). Node 22 has no
  persistent code cache for a `WebAssembly.Module` (V8's code cache is for JavaScript scripts), so the compile
  repeats whenever the extension host restarts. Within one extension-host process a compiled module is reused
  for every instance: compile it once, when the extension activates and before the first document opens, and
  instantiate it for each server start, so that no start but the first compiles at all and the first does it
  while VS Code is still loading the workspace. Starting the server itself on activation moves the module load
  and the workspace load off the first document's wait the same way.

## The field catalog is built without copying each field (#1745 item 3)

A root's Tide field catalog (`models::build`: `fields.json` and `deprecations.json`, which hover, completion
and highlighting read) is generated from the models for the root's configuration. Natively a thread builds it;
under WASI it is built in line, before the request that first reads it once the workspace has loaded: the first
semantic tokens of the opened rule, 170 to 190 ms after the first diagnostics under wasmtime.

Callgrind of one build for the Tide corpus's configuration (native, 770M instructions): `field_row` 372M, of
which `clean_enum` 206M; the schema transforms 180M (the vocabulary offers' one-time decode 121M); `annotate`
116M; and freeing the copies all of it made. Two changes, in `opentide-schema`'s `generate/catalog.rs`:

1. **A field's keywords are read through a view** (`Spec`): its own, then those of the definition its `$ref`
   names, the `$ref` itself hidden, as the merged copy (`effective`) had them. The copy held a vocabulary
   field's enum values and docs (hundreds for an ATT&CK field) and an object field's whole subtree, and was made
   several times a field: for its enum, its type, its const, its `minItems`, and once more for each branch.
2. **An enum of more than 40 values keeps no docs** (`ENUM_DOC_MAX`, which `field_row` already applied): their
   docs are no longer shortened first. Each is a vocabulary entry's whole description.

The catalogs are byte for byte the same: the bundled configuration's (the language server's
`the_default_catalogs_are_the_bundled_ones` and `cargo xtask codegen --check`) and the corpus configuration's
(compared before and after). The `datasets` bench counts the build from a fresh process
(`tide-field-catalog`, the offers' decode included): 383M to 209M instructions, 849k to 471k allocations
(`tests/bench/instructions.toml`). Natively the first build in a process goes from 194 to 102 ms, a later one
from 91 to 127 ms to 49 to 53 ms; under wasmtime `catalog: fields_catalog` (`OPENTIDE_LSP_TIMING=1`) from 167
to 95 ms.

Spawn to the first `semanticTokens/full` of the rule (`didOpen`, the pull of its diagnostics, then the tokens),
15 runs of each build alternating, medians (ms), small / large workspace:

| Host | Before | After |
|---|---:|---:|
| wasmtime 38 | 428 / 743 | 393 / 691 |
| Node 22 WASI | 546 / 655 | 434 / 614 |

What is left of the build under WASI: the offers' decode on first use (a vocabulary dataset), the model schemas
(`schemars`) and the transforms of four revisions. Building only the opened document's revision would not save
much: a rule workspace's pull analyses the closed files of both rule revisions soon after.

## The KQL catalog reads a table's columns when asked for (follow-up to #1767)

The first KQL request still decoded all 943 Azure Monitor tables (27,237 columns) and built about 40,000 column
rows from them: 99M and 65M instructions of the 393M the request took natively, for a query that names one or
two tables. The build script (`crates/opentide-kql/build.rs`) now writes the tables' heads (name, docs,
categories, citation: 35 KB) as one blob and their columns in 30 shards of 32 tables (299 KB in all, 22 KB the
largest); a head says where its table's columns are (`ColumnsAt`). `Catalog` keeps the profile's hand-written
rows, settled at build time (`rows_model::profile_rows`), and for each table a `OnceLock` that builds the
reference's rows (the ones the hand-written rows do not repeat, a column the reference lists twice with two types
untyped, an advanced hunting table's `Timestamp`) the first time `Catalog::columns_for_table` asks for them,
which decodes the table's shard once. `apply_declared` builds a table's rows before it edits them in place, so a
workspace's declared columns find the same column the eager build found. Completion with no table named reads the
hand-written columns only, as it did.

A test keeps the old algorithm as an oracle and holds every table's columns, built lazily, equal to the eager
build for both profiles, with and without a workspace's declarations (a column the reference lists, one it does
not, one a hand-written row has, a table with no reference columns, a table the workspace invents, a pattern, a
column two sources declare).

Start to first diagnostics, medians (ms), small / large workspace, alternating the build of #1768 and this
one on the same machine (WASI built with `--profile wasi-lsp`, 12 runs; Node small 25 runs, wasmtime 38):

| Host | #1768 | This change | Change |
|---|---:|---:|---:|
| wasmtime 38 | 209 / 423 | 189 / 382 | -10% / -10% |
| Node 22 WASI | 266 / 446 | 243 / 436 | -9% / -2% |
| native (no regression) | 64 / 94 | 49 / 81 | -23% / -14% |

The machine is noisier than for the first table (the #1768 build measured 201 / 389 under wasmtime then): read
the changes, not the milliseconds. The module is 11.93 MB (11.86 MB).

## The command line's WASI module is built at opt-level `s` (#1774)

The VS Code extension runs the language server from the command line's WASI module (`opentide lsp start`,
`opentide.wasm`, `build-wasm.sh cli`), not from `opentide-lsp.wasm`, so #1768's `wasi-lsp` profile (opt-level `s`)
does not reach it. That module was already size-optimised, at opt-level `z`, the smallest of the three. Asked whether `s` (or `3`)
would serve it better, the same module was built at each level
(`CARGO_PROFILE_WASI_OPT_LEVEL`, wasi-sdk 25 with `-Oz`, `-Os` and `-O3` for `ring`, the cargo output, without the
release's `wasm-opt` step) and measured on one machine, alternating the builds, medians in ms (wasmtime 38 with its
compiled-module cache warm; Node 22's WASI, which compiles the module on every start, as the extension host does):

| Build | Raw | gzip -9 | wasmtime: `--version` / `lsp` small / large / `validate` | Node: `--version` / `lsp` small / large / `validate` |
|---|---:|---:|---|---|
| `z` (shipped) | 18.9 MB | 8.35 MB | 198 / 267 / 515 / 884 | 100 / 258 / 438 / 851 |
| `s` | 22.1 MB | 9.32 MB | 234 / 279 / 486 / 733 | 114 / 263 / 372 / 635 |
| `3` | 28.8 MB | 11.1 MB | 321 / 362 / 539 / 731 | 123 / 298 / 408 / 702 |

(`lsp` is start to the first diagnostics of a rule with a KQL query on the small workspace and on the 1,000-object
one; `validate` is `opentide validate --json` on the 1,000-object workspace; 6 to 12 runs each, so differences of
under about 10% are noise.)

`z` is the smallest and has the quickest `--version` and small-workspace start; `s` is 17% larger and 14 to 18%
slower to `--version`, and wins in code that runs longer: `validate` is 17 to 25% faster and the large
workspace's first diagnostics 6 to 15% sooner (Node, the extension's host: 438 to 372 ms, which is the gap #1767
left for a thousand-object workspace). The module's real users are the extension's language server and MCP, not
`--version`, which a start pays once, so **`[profile.wasi]` is opt-level `s`** (and `ring`'s C is built with
`-Os`): +1 MB gzipped in the `.vsix` (8.35 to 9.32 MB, the budget being 15 MiB), a small workspace's start the same
within noise, `3` larger and slower to start still.

`wasm-opt` does not help it: on the `s` module `-Oz` takes 22.1 to 19.6 MB (`-Os` 19.8 MB) and `validate` goes
from 788 to about 1,075 ms under Node (+36%), so `build-wasm.sh`'s optional step stays off. Not measured: a
per-package split (engine crates at `s`, the rest at `z`).

The command line's WASI module is not a release asset today (`engine-release-build.yml` ships
`opentide-lsp-wasm32-wasip1.wasm` and the browser build; the extension builds the module from the repository), so
no release size budget in `tests/bench/sizes.toml` covers it: `build-wasm.sh cli`'s 15 MiB gzip check does.
