---
title: "0014: The analysis performance pattern"
description: "How every language's analysis stays fast (#1571): no per-call copy of what is shared, indexes and prepared data built once per catalog, memos keyed by the catalog's identity and bounded by it, borrowed specs, cheap lower bounds before expensive measures, single-pass walks; measured with callgrind instructions and wall time, and held by work counts, not clocks."
---

# 0014: The analysis performance pattern

| | |
|---|---|
| Status | Proposed |
| Date | 2026-11-18 |
| Decision | #1571 (faster than the vendors, more correct, in every language) |
| Issues | [#1571](https://github.com/opentidehq/opentide/issues/1571), [#1570](https://github.com/opentidehq/opentide/pull/1570), [#1573](https://github.com/opentidehq/opentide/pull/1573), [#1424](https://github.com/opentidehq/opentide/issues/1424); catalog loading is [ADR 0013](./0013-language-catalogs.md) |

## Context

An editor analyses a query on every keystroke, and `validate` analyses thousands of rules. Either way
the work is many short analyses. The cost that matters is therefore the cost per call on a query of
a few hundred bytes, after the catalogs are loaded, not parsing speed on a large file.

`cargo bench -p opentide-analysis --bench analyze` showed KQL and Falco costing 8 to 10 times the
other languages on corpus queries under 100 bytes. Profiling the warm loop with callgrind showed the
time was not in parsing. It went on setup repeated on every call:

| Language | Per-call cost found | Share of a short query |
|---|---|---|
| KQL | Every pipeline stage recorded deep copies of its input and output schemas (`Schema::clone`, a hundred-odd columns of `String`s) | 29% |
| KQL | Each table reference rebuilt the table's schema from the catalog | 19% |
| KQL | The semantic tokens hashed every column of the named tables, and scanned all 27k catalog columns for hand-written ones | 25% |
| KQL | Operator, function and plugin names were found by scanning the catalog rows, once per name | 10% |
| KQL | Each unknown table lower-cased and folded the catalog's table names again, then measured the edit distance to each | 30% (Sentinel set) |
| KQL | A node's range without trivia walked every token of the node, for most nodes | 16% of allocations |
| Falco | Every default list was expanded again for each condition | most of the call |
| All | `HighlightSpec::load` cloned the spec's maps on every analysis | a few % |

#1570 and #1573 removed these with no output change. Those PRs were held by the corpus gates, the
snapshots, and differentials over the corpora, fuzz inputs and random mutants. The numbers below are
release builds on one machine.

| Measure | Before | After | Kusto.Language 12.4.1 |
|---|---:|---:|---:|
| KQL, analysis corpus, median per file | 339 µs | 42 µs | |
| Falco, analysis corpus, median per file | 257 µs | 13 µs | |
| Other languages, analysis corpus | | 10–30% faster | |
| KQL, 20 Azure-Sentinel detections (708 characters), full analysis | 927 µs | ~270 µs | 287 µs |
| KQL, same set, parse alone (unchanged by these PRs) | ~41 µs | ~41 µs | 50 µs |
| KQL, 10,000 analyses in one process (the vendor harness: time, peak memory) | | 3.0 s, 27.6 MiB | 4.7 s, 207 MiB |
| KQL, a one-line query (`SecurityEvent \| take 10`) | 292 µs | 9.3 µs | 8.7 µs |

Kusto's figures are ParseAndAnalyze with the schema, plus GetDiagnostics, plus classifications, on
.NET 8. Ours are `opentide_analysis::analyze` with the Sentinel profile, which also runs the column
pass, the performance checks and the semantic tokens.

The one-line query is the remaining gap: 0.6 µs, mostly fixed cost per call.

## Decision

Every language's analysis follows these rules. A review asks for the measurement behind any
exception.

### 1. Nothing shared is copied per call

- A catalog, a spec, a schema or a list that several calls or stages read is borrowed, or shared
  behind `Arc`. It is never cloned.
- `HighlightSpec::shared()` borrows the compiled-in spec. `load()` returns a copy and is only for a
  caller that keeps one.
- A value that stages pass along and sometimes change is copy-on-write: `Arc<Vec<Arc<T>>>` and
  `Arc::make_mut` (KQL's `Schema::columns`). Changing one element then copies pointers, not the
  elements' strings.
- A name repeated across many values (a column's table, an ASIM schema) is one `Arc<str>`, not a
  `String` per value.
- Inside a call, prefer borrowing (`&'static str` captures, `&str` keys) to allocating. A lookup does
  not lower-case a name that is already lower case.

### 2. Indexes and prepared data are built once per catalog

- Anything derived from a catalog alone is built once, on first use: a name index, a set of
  hand-written names, `suggest::Candidates` prepared for suggestions, the expanded default lists.
  Built per call or per name, it is a scan of the catalog each time.
- Where it lives:
  - On a profile's bundled catalog (`Catalog::cached`), it is a `static OnceLock`, one per
    profile. The code checks it has the bundled catalog with `std::ptr::eq(catalog,
    Catalog::cached(profile))`.
  - A catalog that is not the bundled one (a workspace's declared columns) takes the plain path,
    until the catalog itself carries the index. That is ADR 0013's and #1071's area.
- A lookup through the index returns exactly what the scan returned: the first row, the same case
  rule. A test compares the two over every catalog name.

### 3. Memos are keyed by what they read, and bounded

- A per-call result that depends only on the catalog and a name, such as a table's or an ASIM
  parser's schema, is kept per thread. It is keyed by profile and name, and only for the bundled
  catalog.
- A memo keeps found values only. A name that resolves to nothing is looked up again, so the memo
  stays bounded by the catalog. A memo of `None` grew without bound as an editor typed (55 MB over
  200,000 names).
- A memo of a whole computation keyed by its input keeps the last input only: the parse, the column
  pass for hover, a Falco block's lists. It holds what makes a key's identity safe, such as the
  `CatalogRef` it ran against, so a dropped catalog's address cannot be reused by another.
- A memo reads no global state outside its key. Declared datasets, for example, are read by the
  table check, which is not memoised.

### 4. A cheap bound before an expensive measure

- Before an edit distance, compare lengths. Then compare the multiset difference of the characters
  (`suggest::bag_distance`). It is a proven lower bound of both the OSA and the Levenshtein distance:
  an insertion or deletion changes it by one, a substitution by at most one, a transposition not at
  all.
- Only a candidate within both bounds is measured. Of 1,000 table names, an unknown name now
  measures a few.
- A test holds the cut result to the uncut one, and a work count holds the number of distances
  measured.

### 5. Walk once, from where the answer is

- Find a node's ends from its ends: `first_token` and `last_token`, inward past trivia. Do not walk
  all its tokens. Where rowan's token steps stop (at an empty node, as broken input leaves), fall
  back to the full walk.
- Gather what several checks need in one pass over the tree or the tokens. A scan of the source for
  a byte uses `memchr`, as the lexers already do.
- No quadratic in the size of a query: a work count or a linear-growth test holds each loop that
  could be one (#1424, #1459).

### 6. How to measure

- **Instructions.** callgrind on the warm loop only: `--toggle-collect` on a function that runs the
  calls after a warm-up, so catalog loading is out. Use a build with symbols: the `develop` profile
  with `CARGO_PROFILE_DEVELOP_DEBUG=line-tables-only`. Read `callgrind_annotate --inclusive=yes`
  first, then `--tree=caller` on `malloc` or the hot function to find who calls it. Instruction
  counts are deterministic: compare them before and after, with 1 thread.
- **Wall time.** A release build with LTO (the release profile), 1 thread, the default case count:
  - warm up for at least 3 s;
  - run at least 15 rounds and at least 5 s;
  - alternate the inputs, so that no one-input memo serves a call;
  - report the median per call.

  Note the machine's load: record parse alone beside each figure as the calibration.
- **Vendor numbers** come from the vendor's own library on the same inputs. Name the version and
  the calls included.
- **Before and after**, from the same machine, in the pull request body.

### 7. Held by work counts, not clocks

- A speed-up is held by a test that counts work, such as `bodies_read`, pipelines scanned, names
  compared, distances measured or column passes. The test must fail on the old code: put the old
  path back and watch it fail before merging.
- A timed check compares growth (n against 4n, best of three, alternated), never an absolute time.
- No output change is shown with an equivalence test against the old path (`range_by_walking`, an
  uncut ranking, a scanned catalog), and with a differential over the corpora in the pull request.

## Consequences

- **For a new language.** It starts from the pattern: the add-language skill's done-when lists it.
  Its first benchmark run is checked for setup repeated per call, before any parser tuning.
- **For the existing languages.** They apply the pattern one by one, worst first by profile (#1571,
  step 4).
- **Throughput gate.** The throughput benchmark (#1571, step 3) gates per-language instruction
  counts, parse-only and full analysis. A regression shows as instructions, not seconds.
- **API changes.** A shared type changes the public API: `opentide_kql::schema::Schema::columns`
  and `Origin` (crates/CHANGELOG, Breaking). Engine crates other than the facade have no stability
  promise, but each such change is listed with its upgrade step.
- **Memory.** Memos per thread cost memory per thread, bounded by the catalog: about 9 MB per
  Sentinel thread if every table is referenced. A server with a rayon pool pays it per worker.
- **Not here.** Catalog loading and its memory are ADR 0013 (#1071). A catalog with declared columns
  still bypasses the bundled-only memos until it carries its own.

## Evidence

- [#1570](https://github.com/opentidehq/opentide/pull/1570): KQL and Falco per-call setup. Its body
  has the callgrind table, the corpus benchmark before and after, and two adversarial reviews with
  differentials of 11,250 KQL and 15,750 Falco sections.
- [#1573](https://github.com/opentidehq/opentide/pull/1573): the bag-distance cut, inward ranges and
  `Arc<Column>`. KQL drops below Kusto on the Sentinel set. Its review checked `range` on 764k nodes
  and `ranked` on 40k candidate sets.
- [#1424](https://github.com/opentidehq/opentide/issues/1424) and
  [#1459](https://github.com/opentidehq/opentide/pull/1459): quadratic and exponential loops found
  and held by work counts.
- `crates/opentide-analysis/benches/analyze.rs`: the per-language corpus benchmark (CI, not gated).
