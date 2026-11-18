---
title: "0013: How a language catalog is shipped, loaded and shared"
description: "One pattern for every engine catalog (#1071): generated TOML compiled in, read item by item through opentide_core::catalog (never a whole document), built once per process in a OnceLock that rayon workers share, repeated values interned, and static tables only where a measurement shows they pay."
---

# 0013: How a language catalog is shipped, loaded and shared

| | |
|---|---|
| Status | Proposed |
| Date | 2026-11-18 |
| Issues | [#1071](https://github.com/opentidehq/opentide/issues/1071) (validate's peak RSS), [#1142](https://github.com/opentidehq/opentide/issues/1142) (process-global state) |

## Context

Each query language's engine carries catalogs: functions, fields, tables, macros and the like,
generated from the vendor's reference by a sync script under `scripts/engine/`. Until now each crate
loaded them its own way. Most parsed every file with `toml::from_str` inside a `OnceLock`.

That costs memory out of all proportion to the data. `toml` builds a whole `toml_edit` document,
with every key, span, decoration and string, before it deserialises. That document takes several
times the catalog it holds:

| Catalog | File | Whole-document parse | Catalog kept |
|---|---:|---:|---:|
| KQL Azure Monitor reference | 3.4 MB | ~25 MiB transient (#1503) | ~6 MiB |
| Falco `fields.toml` | 244 KB | 5–6 MiB transient, `validate`'s peak (#1071) | < 1 MiB |

The document is freed as soon as the catalog is built. But catalogs build lazily, the first time a
query of their language is analysed, so on a busy run the build lands at the run's peak. On a rayon
pool several languages' catalogs can build at once, so their temporary documents stack. Freed memory
also stays in the allocator's per-thread arenas.

[#1503](https://github.com/opentidehq/opentide/pull/1503) read the KQL reference item by item and
cut `validate`'s peak by 40 MiB. This ADR makes that one pattern for every catalog, so that a new
language does not repeat the mistake.

## Decision

### 1. Source format: generated TOML, in one restricted form

A catalog is a TOML file under `data/catalogs/<language>/`, written by the language's sync script,
never by hand. The script writes it in the form the loader reads:

- comments and blank lines anywhere outside an item;
- an optional **preamble** before the first array: `key = value` lines, each on one line (Falco's
  `classes = [...]`, `syscalls = [...]`);
- then **top-level arrays of tables**:
  - each item starts at a line `[[name]]`;
  - its sub-tables are `[name.<sub>]` or `[[name.<sub>]]`;
  - its values fit on their line.

Headers are bare names, at the start of the line, with nothing after them. No value is a `"""` or
`'''` string; a script writes strings with JSON escaping (`json.dumps`), which TOML reads as basic
strings.

TOML stays because the files are reviewed in pull requests and diffed when upstream changes;
JSON or a binary form would lose that. The engine crates `include_str!` the files (they stay I/O-free).

### 2. Loading: item by item, through `opentide_core::catalog`

A crate reads a catalog with two functions:

- `opentide_core::catalog::array_items::<T>(text, "name")`: the items of `[[name]]`, each
  deserialised on its own, so only one item's TOML document is alive at a time;
- `opentide_core::catalog::preamble::<T>(text)`: the preamble.

No engine crate calls `toml::from_str` on a whole catalog file. Both functions refuse, with the
line, any text not in the form above, rather than reading it differently from `toml`'s reading of
the whole file. Each catalog crate has a test that its compiled-in files read item by item are, field
for field, what `toml::from_str` reads from the whole files (by `Debug`). A sync script that drifts
from the form fails that test in CI, not a user's run.

### 3. Sharing: built once per process, in a `OnceLock`, shared by every thread

- A catalog is a `static CATALOG: OnceLock<Catalog>` (or one per profile), read through
  `Catalog::cached()`.
- `OnceLock::get_or_init` runs the build once: the first caller builds, and every other thread blocks
  until it is done, then shares the result. No catalog is built twice in a process, and none once per
  thread.
- **Rayon.** The build is plain parsing: it must not call into rayon (no `par_iter` inside
  `get_or_init`), take a lock, or read another catalog that could be waiting on this one. A pool
  thread that blocks in `get_or_init` is then only waiting for a build that is making progress on
  another thread, so it cannot deadlock. The build runs on whichever thread first needs the catalog.
  Another pool thread that needs it waits rather than building a second copy, so no temporary document
  is duplicated across threads.
- What a run varies (a workspace's declared datasets, columns) is never put into the shared catalog.
  It is passed per call: a thread-scoped `opentide_analysis::Datasets` (#1142), or a derived catalog
  in a small keyed cache built outside its lock (`opentide_kql::Catalog::for_workspace`).

### 4. Interning repeated values

A value that repeats across many rows costs an allocation per row when it is a `String`.

- **A closed set** (a type name among about ten, a kind, a flag) is an `enum` or a `&'static str` from
  a fixed table, deserialised from the string.
- **An open set that repeats** (a table name or citation shared by thousands of column rows, a
  description shared between a reference and the profiles built from it) is an `Arc<str>`, made once
  and cloned, never copied (#1503's `ColumnRow`).
- Small catalogs (Falco: about 600 fields) keep `String`s; interning them saves less than it costs to
  read. Intern when a measurement (massif, the bench's peak RSS) shows the catalog's heap is worth it.

### 5. Static tables: only where they pay

Generating a catalog as Rust statics at build time (`cargo xtask codegen`) costs no heap at all, and
only the pages a query touches become resident. It is the end state for a catalog large enough to
matter: today only KQL's (#1071 item 2).

It costs generated code to review, and the build-time step itself. Do it when a measurement shows
the item-by-item heap is still a large share of a command's peak, not before.

### 6. How a new language plugs in

1. **Data.** The sync script writes `data/catalogs/<language>/*.toml` in the form of §1, with its
   provenance in comments at the top.
2. **Code.** The crate's `catalog.rs`:
   - `include_str!`s the files;
   - defines the row types (`#[derive(Debug, Deserialize)]`);
   - builds `Catalog` in `Catalog::cached()` with `array_items` and `preamble`;
   - indexes it (by name, by class) once, in the same build.
3. **Tests.** The equality test of §2, and a test that `cached()` loads with the expected counts.
4. **The add-language skill** lists these steps (`.agents/skills/add-language/SKILL.md`, step 6), and
   `catalogs` describes the format.

## Consequences

- **The temporary memory of a catalog build is one item's document,** not the file's: Falco's build
  peak goes from 5–6 MiB to almost nothing, and catalogs building at once on several threads no
  longer stack whole documents.
- **The format is checked.** A generator that writes a multi-line string, a commented header or an
  indented table fails the equality test.
- **The rollout.** Falco is the reference (this ADR's PR). CQL, YARA, ES|QL, YARA-L, EQL, SPL,
  Exabeam, Lucene (Carbon Black) and the KQL core files follow, one PR at a time, each measured.
- **Not covered:** the Tide vocabularies (`src/opentide/data/vocabulary/`), read by opentide-schema
  with their own reader, follow separately (#1071 item 6). So does the ECS catalog, which is JSON
  read with `serde_json`, which streams and builds no document.

## Evidence

- #1503: the KQL Azure Monitor and ASIM catalogs read item by item. `validate`'s peak RSS went from
  143.8 / 144.7 MiB to 111.3 / 109.9 MiB (`cargo xtask bench`, 4 vCPU).
- #1071's breakdown at `b13fbcb7b`: the Falco `fields.toml` document is 5–6 MiB of the 53.4 MiB
  heap peak, alive where the peak happens.
- This ADR's PR: Falco's numbers, measured with `RAYON_NUM_THREADS=1` and with the default thread
  count, are in its description.
