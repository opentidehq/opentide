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
time was not in parsing. It went on setup repeated on every call. Each share is of the profile
before the PR that removed it:

| Language | Per-call cost found | Share | Removed in |
|---|---|---|---|
| KQL | Every pipeline stage recorded deep copies of its input and output schemas (`Schema::clone`, a hundred-odd columns of `String`s) | 29% | #1570 |
| KQL | Each table reference rebuilt the table's schema from the catalog | 19% | #1570 |
| KQL | The semantic tokens hashed every column of the named tables, and scanned all 27k catalog columns for hand-written ones | 25% | #1570 |
| KQL | Operator, function and plugin names were found by scanning the catalog rows, once per name | 10% | #1570 |
| KQL | Each unknown table lower-cased and folded the catalog's table names again | 30% (Sentinel set) | #1570 |
| KQL | Then measured the edit distance to each candidate of a near length | 17% (Sentinel set) | #1573 |
| KQL | A node's range without trivia walked every token of the node, for most nodes | 16% of allocations | #1573 |
| Falco | Every default list was expanded again for each condition | most of the call | #1570 |
| All | `HighlightSpec::load` cloned the spec's maps on every analysis | a few % | #1570 |

#1570 and #1573 removed these with no output change. Those PRs were held by the corpus gates, the
snapshots, and differentials over the corpora, fuzz inputs and random mutants. The numbers below are
release builds on one machine.

| Measure | Before #1570 | After #1570 | After #1573 | Kusto.Language 12.4.1 |
|---|---:|---:|---:|---:|
| KQL, analysis corpus, median per file | 339 µs | 42 µs | | |
| Falco, analysis corpus, median per file | 257 µs | 13 µs | | |
| Other languages, analysis corpus | | 21–33% faster | | |
| KQL, 20 Azure-Sentinel detections averaging 708 characters, full analysis | 927 µs | 376 µs | ~270 µs | 287 µs |
| KQL, same set, parse alone (these PRs do not change it) | 35.6 µs | 33.9 µs | ~41 µs (a busier machine) | 50 µs |
| KQL, a one-line pair (`SecurityEvent \| take 10` and `take 11`, alternated) | 292 µs | 9.2 µs | 9.3 µs | 8.7 µs |

Kusto's figures are ParseAndAnalyze with the schema, plus GetDiagnostics, plus classifications, on
.NET 8. Ours are `opentide_analysis::analyze` with the Sentinel profile, which also runs the column
pass, the performance checks and the semantic tokens. The orchestrating session's vendor harness
also ran 10,000 analyses of the Sentinel set in one process each: 3.0 s and 27.6 MiB peak for
opentide, 4.7 s and 207 MiB for Kusto.Language. Those figures include each runtime's start-up (and
.NET's JIT), which the per-call medians above do not.

The one-line pair is the remaining gap: 0.6 µs a call. It is not profiled yet.

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
  rule. A test compares the two over every name of the catalog, in each case
  (`the_name_indexes_find_what_a_scan_finds` in `opentide-kql`).

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
- A memo reads no mutable or scoped state outside its key. Immutable process statics (the bundled
  catalog, ASIM's schemas) are fine; declared datasets (`opentide_core::datasets`, which a thread
  can scope) are not, and the table check that reads them is not memoised.

### 4. A cheap bound before an expensive measure

- Before an edit distance, compare lengths. Then compare the multiset difference of the characters
  (`suggest::bag_distance`). It is a proven lower bound of both the OSA and the Levenshtein distance:
  an insertion or deletion changes it by one, a substitution by at most one, a transposition not at
  all.
- Only a candidate within both bounds is measured: in the test, an unrelated name measures at most
  20 of 1,000 candidates, where it measured all 1,000. The bound needs ASCII: `bag_distance` returns
  `None` for any other text, and nothing is cut there.
- A test holds the cut result to the uncut one, and a work count holds the number of distances
  measured.

### 5. Walk once, from where the answer is

- Find a node's ends from its ends: `first_token` and `last_token`, inward past trivia. Do not walk
  all its tokens. Where rowan's token steps stop (at an empty node, as broken input leaves), fall
  back to the full walk.
- Gather what several checks need in one pass over the tree or the tokens. A scan of the source for
  a byte uses `memchr` (`opentide_core::catalog` does).
- No quadratic in the size of a query: a work count or a linear-growth test holds each loop that
  could be one (#1424, #1459).

### 5a. One walk for the checks and the highlight (addendum, Lucene)

rowan allocates a cursor for every node and token a walk visits, and frees it after. A language
whose checks walk the tree and whose highlight walks it again pays for every element twice; on
Lucene's short queries that, and the per-node vectors around it, was most of the call.

- **One preorder walk over every element.** Nodes and tokens, in document order, from one stack
  and a scratch vector reused for each node's children. The walk hands each named element to the
  checks, with its ancestors, and each token to the highlight. The walk is
  `opentide_parse::walk_once`, with `opentide_parse::Ancestors` for a language that keeps the
  ancestors in its own type; Lucene's `tree::walk_once` shows the use: it calls the checks exactly
  as the named-only walk did, and meets the tokens exactly as `descendants_with_tokens` did, which
  a test holds over the short samples and every prefix of them. A new language's single walk uses it, not a copy.
- **Only where the highlight reads the same text.** A dialect that checks a rewritten text
  (Carbon Black's joined lines) keeps its own highlight pass.
- **Find one child without collecting all.** A search for the first child of a kind is a lazy
  iterator that stops there, not a vector of every child.
- **Trim a range once.** A node's span and text compute its trimmed range once, not once per end.
- **Kinds before text.** A check that needs two siblings of given kinds tests the kinds before it
  reads either's text.
- **Held by element visits.** A test counts the elements the walks visit in one analysis and
  holds it to the tree's element count: the two-walk path visits more.

### 5b. A fast hasher for maps keyed by user input (addendum, KQL)

SipHash, std's default, cost about a seventh of a KQL analysis: the column pass's maps, the
keyword table and the catalog's name lookups each hash a name per use.

- **foldhash's `fast::RandomState`** (`foldhash::HashMap`, `foldhash::HashSet`, the workspace's
  `foldhash` dependency) is the engine's hasher for maps on a hot path. It is about as fast as Fx
  (foldhash's own benchmarks; Fx leads on some short keys).
- **What its seed is.** One seed per process, mixed from ASLR addresses, the clock and a heap
  address, not the operating system's random source, and one per map. foldhash calls itself
  minimally DoS-resistant: it defeats collisions prepared ahead of time, not an attacker who
  can watch timings and adapt. On `wasm32-unknown-unknown` (the browser host) there is no clock
  and the addresses are fixed, so the seed there is close to fixed.
- **Never a fixed-seed hasher for keys a query names.** A map keyed by the query's own names
  (columns, `let` names, functions) under a hasher whose collisions can be worked out once and
  reused (FxHash, foldhash's `FixedState`) lets a crafted rule make the analysis quadratic.
- **Known exceptions.** rowan's token cache (`NodeCache`, which every parser's
  `GreenNodeBuilder` uses through opentide-parse) hashes token text with Fx; it is rowan's, not
  ours. Measured (#1616): 70,000 names crafted to share their low 17 hash bits, in a 980 KB
  query, parse in 2.05 s against 0.093 s for ordinary names (about 22×); a seeded `NodeCache`
  brings it to 1.02×. #1616 tracks the fix. KQL's catalog name lookups (`lib.rs`) still use
  SipHash until #1609 lands; their keys are catalog names, not the query's.

### 6. How to measure

- **Instructions.** callgrind on the warm loop only: `--toggle-collect` on a function that runs the
  calls after a warm-up, marked `#[inline(never)]` so the optimiser keeps it, so catalog loading
  is out. Use a build with symbols: the `develop` profile
  with `CARGO_PROFILE_DEVELOP_DEBUG=line-tables-only`. Read `callgrind_annotate --inclusive=yes`
  first, then `--tree=caller` on `malloc` or the hot function to find who calls it. Instruction
  counts are deterministic: compare them before and after, with 1 thread.
- **Wall time.** A release build with LTO (the release profile), on 1 thread:
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
- **Throughput gate.** The throughput benchmark (#1571, step 3, to come) is to gate per-language
  instruction counts, parse-only and full analysis, so that a regression shows as instructions, not
  seconds.
- **API changes.** A shared type changes the public API: `opentide_kql::schema::Schema::columns`
  and `Origin` (crates/CHANGELOG, Breaking). Engine crates other than the facade have no stability
  promise, but each such change is listed with its upgrade step.
- **Memory.** Memos per thread cost memory per thread, bounded by the catalog: about 9 MB per
  Sentinel thread if all 973 tables are referenced (measured in #1570's first review). A server with
  a rayon pool pays it per worker.
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
- `crates/opentide-analysis/benches/analyze.rs`: the per-language corpus benchmark, run by hand.
