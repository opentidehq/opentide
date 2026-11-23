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
(`tide-field-catalog`, the offers' decode included): 383M to 209M instructions, 849k to 471k allocations.
On top of #1808, which adds each vocabulary field's references and drops the search hints from its enum, it is
395M to 222M, 873k to 488k (`tests/bench/instructions.toml`). Natively the first build in a process goes from 194 to 102 ms, a later one
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

## Paths resolved in one lookup, the disk read once a batch (#1767, the target met)

The large workspace's WASI start still missed its 350 ms target (an EPYC 7763 of the runner class: 493 ms).
This round profiled the module itself: `wasmtime run --profile guest` (a build of `--profile wasi-lsp` with
`CARGO_PROFILE_WASI_LSP_STRIP=none`, sampled every 0.2 ms) and a script that sums each function's inclusive
time, beside callgrind of a native build for instruction counts.

### Where the time went

Spawn to the first diagnostics of a rule (the corpus copied to 1,000 objects), wasmtime 38, before:

| Part | ms |
|---|---:|
| Module load and instantiation, before `initialize` is answered (`opentide-lsp --version`: 131 ms; Node 84 ms, 27 of them Node's own start) | 125 to 135 |
| The server's walk of the object files for the editor's index (`DiskObjects::refresh`, `yaml_files`) | 63 |
| The workspace's discovery (`scan_with`) and path resolution (`OsFs::resolve`) | 86 |
| The YAML parse of 1,000 objects (`node::load`, one thread) | 77 to 86 |
| `validate` for the opened file | 33 to 43 |
| lint for the opened file (`editor_lint`), which scans the object folders again | 47 to 83 |
| The engine's analysis of the rule (Tide YAML, its KQL query) | 19 |

Two costs that native hosts do not have stood out, both of the disk:

- **Listing a folder** of a thousand files takes 27 ms under wasmtime (Node 6 ms, native 0.3 ms), and the
  first request listed `objects/rules` three times: the walk for the editor's index, the workspace's discovery,
  and lint's scan.
- **`canonicalize`** takes 0.28 ms under wasmtime (Node 0.02 ms), and `OsFs::resolve` made one per component of
  a path, each walking its own prefix again. The first workspace pull of the 1,000 objects took 7.7 s of guest
  time under wasmtime, 6.2 s of it in `canonicalize`: resolving the file of each finding (`checks::by_file`) and
  of each object (`RootChecks::resolve`). On a single-threaded host that pull holds every request behind it.

### What changed

1. **`OsFs::resolve` resolves a path that exists, and names no `.` or `..`, in one `canonicalize`**
   (`crates/opentide-workspace/src/fs.rs`): every prefix of such a path exists, and resolving them one by one
   ends where resolving the whole does; a test holds the two equal through linked folders, linked files, links
   to links and a relative link that climbs. The walk stays for a path that does not exist yet and one with
   `..`. `OsFs::read_dir` no longer calls `metadata` on every entry: an entry's own type answers for anything but
   a link, which is still followed.
2. **Each root reads the disk through a `Disk`** (`crates/opentide-lsp/src/checks.rs`) that keeps what a folder
   lists and a file holds until it is forgotten: at the start and the end of each batch, before each
   notification, and when a change is reported to the root's checks. A read that began before a forget is not
   kept (the native workspace loads on a thread of its own). The server's walk reads through it
   (`server::yaml_files_in`), so the workspace's load and lint list and read what the walk just did. A test
   changes a file on disk between two messages of one batch, after a request read it and before the watcher's
   event: the workspace's diagnostics are the new text's (it fails when the forget before a notification is
   taken out).

### Before and after

Spawn to the first diagnostics, the cold-start client (`scripts/perf/lsp-bench.mjs`, VS Code's capabilities),
alternating the builds, 15 runs each, medians (ms):

| Host, workspace | Before | Paths (1) | Paths and disk (1 + 2) |
|---|---:|---:|---:|
| wasmtime 38, small | 227 | 201 | 207 |
| wasmtime 38, large | 501 | 545 | 391 |
| Node 22 WASI, small | 278 | 283 | 287 |
| Node 22 WASI, large | 433 | 452 | 419 |

The small workspace and Node move within this machine's noise (about 10% between runs). The first workspace pull
of the 1,000 objects, 7 runs: wasmtime 6.9 to 8.1 s before, 2.2 to 2.7 s after (1); Node 1.75 s to 1.44 s.

`scripts/perf/cold-start.sh` (10 runs, p50, the job's own measurement), before and after both, and the field
catalog's change beside them (which takes no time off this path): native 46.6 / 78.5 ms to 36.0 / 58.9 ms,
WASI under wasmtime 219.2 / 395.4 ms to 179.2 / 300.8 ms (small / large). On the EPYC 7763 the job measured
the baseline 1.25 times slower than this machine, which puts the large WASI start at about 375 ms there, under
the 385 ms the check allows (the target and `policy.regression`), and the EPYC 9V74 and 9V45 at about 320 and
250 ms. `tests/bench/lsp-cold-start.toml` no longer waives `wasi_large`.

### The extension's host (Node's WASI)

The VS Code extension compiles the module once per extension host (`WebAssembly.compile`) and starts each server
from it ([the handoff](./vscode-wasi.md)). Measured on Node 22.23 for the 11.9 MB `wasi-lsp` module: reading
it 8 to 14 ms, `WebAssembly.compile` 26 to 34 ms (lazy: each function is compiled by Liftoff at its first call,
which the first request pays), instantiating 5 to 11 ms. Compiling it eagerly costs more, not less (Liftoff 160
ms, TurboFan 2.9 s). Node 22 has no supported way to keep a compiled `WebAssembly.Module` between processes:
`v8.serialize` of one gives a two-byte placeholder, and `module.enableCompileCache()` covers JavaScript only. So
the extension's levers stay those above: compile once when the extension activates, and start the server then,
before the first document opens, so that the module load and the workspace's load are not in the first
document's wait. A smaller module is the server's own lever: 8.3 MB of it is code.

### What is left

- **The module's size.** Under wasmtime about 125 ms of every start is loading the compiled module from its cache
  (`--version` takes 131 ms); under Node, its compile and each function's first. The code is the engine itself:
  every query language's parser, `schemars`, the YAML stack.
- **The large workspace's first request** is now one listing of each folder, 1,000 reads, the YAML parse and
  the first `validate`: what checking the opened file against the workspace costs.
- **Semantic tokens before the workspace.** A document's tokens come from the engine's analysis alone, but
  `semanticTokens/full` goes through `Session::analysis`, which also loads the workspace and runs `validate`.
  Answering them from the engine part would bring the first highlighting before the first diagnostics. Their
  captures read the field catalog's enum values (`in_enum`), which a root's configuration changes, so it wants a
  `workspace/semanticTokens/refresh` when a root's own catalog replaces the compiled-in one: whether one is sent
  then today (`Sighting::First` only bumps the epoch) is to check first.

## The datasets' decode before first diagnostics (zstd, `ruzstd`)

Since #1743 every dataset is a zstd blob that `ruzstd` decodes on first use (`opentide-dataset`). The question
was how much of the WASI cold start that decode is, and whether a faster pure-Rust codec (sirocco's DEFLATE,
`lz4_flex`) would be worth comparing if it were more than about 10%.

Measured with a temporary timer around `opentide_dataset::decode` (not committed). The run is the cold-start
sequence (spawn, `initialize`, `didOpen` of `rule-0001-sentinel-kql.yaml`, its pulled diagnostics) on
`make_workspace.py`'s small (`--objects 0`) and large (`--objects 1000`) workspaces, 7 runs each, medians, on
this branch. It counts every decode that finished before the diagnostics' answer.

| Host | Workspace | Start to first diagnostics | Datasets decoded | Compressed → decoded | Decode time | Share |
|---|---|---:|---:|---:|---:|---:|
| Node 22 WASI | small | 216 ms | 35 | 218 kB → 1.35 MB | 11.5 ms | 5.3% |
| Node 22 WASI | large | 314 ms | 35 | 218 kB → 1.35 MB | 11.4 ms | 3.6% |
| native | small | 37 ms | 41 | 1.09 MB → 7.27 MB | 30.0 ms of CPU | on the warm-up threads |
| native | large | 58 ms | 43 | 1.09 MB → 7.28 MB | 36.9 ms of CPU | on the warm-up threads |

Per dataset under Node's WASI (small workspace; the large one is within 0.1 ms of it): `tide-choices` 1.8 ms,
`tide-fields` 1.6, `kql-core-rows` 1.5, `kql-azure-monitor-heads` 1.3, `kql-asim` 1.1, `highlights/spec.toml`
1.0 (0.8 kB, but the first decode, so it includes Node compiling the decoder's functions), `vocab/lean/att&ck`
0.8, `sentinel/attack-v18.json` 0.6, the bundled configuration's TOML files 0.5 together,
`kql-azure-monitor-columns-24` 0.4, `kql-sentinel-rows` 0.4. Everything else is under 0.05 ms.

Natively, the warm-up threads also decode the vocabularies (13.8 ms, 565 kB → 2.6 MB) and the ATT&CK offers
(11.1 ms, 296 kB → 3.3 MB) beside the first request. That accounts for the 30 to 37 ms of decode CPU against
37 to 58 ms of wall time. A WASI host decodes neither before first diagnostics.

**Conclusion:** decode is 3.6 to 5.3% of the WASI cold start under Node, below the 10% at which a codec
comparison was planned, so sirocco and `lz4_flex` were not benchmarked. Even a decoder that took no time at
all would save about 11 ms of 216 to 314. The module load and the first request's own work are where the time
goes (above).
