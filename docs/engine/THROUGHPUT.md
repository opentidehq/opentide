---
title: "Throughput"
description: "How fast each language's parse and analysis run, in wall time and in instructions, how that is measured and held (cargo xtask throughput, ADR 0014), and how it compares with the vendors' own libraries."
---

# Throughput

Each language is measured in two modes, on two input sets:

- **Modes:** `parse` (the language's own parse alone) and `analyze` (`opentide_analysis::analyze`:
  the parse, every check, the semantic tokens).
- **`corpus`:** `crates/testdata/corpus/<lang>/`, short queries. These give the per-call floor an
  editor pays on every keystroke.
- **`external`:** the real public rules under `crates/testdata/conformance/external/`, plus the
  accepted queries of a reference parser's `cases.tsv`. These give bytes a second on realistic input.

[ADR 0014](../internal/adr/0014-analysis-performance.md) is the pattern that keeps these numbers
down, and says how to measure them.

## Wall time

`cargo bench -p opentide-analysis --bench throughput`: a release build with LTO, 1 thread, a
warm-up, then at least 15 rounds and 1 s, the median. The numbers below come from one 4-vCPU Linux
machine on 2026-11-18. Time varies with the machine and its load, so compare runs on one machine
only.

| Language | Corpus, parse µs/call | Corpus, analyze µs/call | External, parse MB/s | External, analyze MB/s | External files, bytes |
|---|---:|---:|---:|---:|---|
| KQL | 5.8 | 40.1 | 21.4 | 3.7 | 15, 39,092 |
| ES\|QL | 6.2 | 28.0 | 21.6 | 5.6 | 12, 2,844 |
| EQL | 4.8 | 15.1 | 26.0 | 9.1 | 12, 2,978 |
| Kibana KQL | 4.2 | 16.8 | 7.5 | 3.6 | 55, 650 |
| Lucene | 4.5 | 15.7 | 29.8 | 10.3 | 18, 2,716 |
| SPL | 10.4 | 31.4 | 16.7 | 4.5 | 14, 12,328 |
| CQL | 21.4 | 25.6 | 10.3 | 9.0 | 45, 55,062 |
| Falco | 11.0 | 15.5 | 11.2 | 0.2 | 241, 30,955 |
| YARA | 31.7 | 46.7 | 4.1 | 3.0 | 50, 206,242 |
| Exabeam | 20.2 | 41.0 | 5.9 | 3.8 | 16, 2,550 |
| YARA-L | 14.4 | 27.1 | 21.3 | 10.0 | 79, 243,055 |

How to read the table:

- **Two-column ratio.** Where the external parse rate is high and the analyze rate low, the time
  goes on analysis, not parsing. Most of it is per-call setup, which ADR 0014 removes. Falco's
  analysis of its external rules (0.2 MB/s) is the outlier to look at next.
- **Parse entry points.** SPL, CQL, Falco, YARA, Exabeam and YARA-L are measured through their
  crates' `debug_kinds`, which also names every kind. Their parse figure is an upper bound until
  each crate gives the benchmark a plain parse.
- **Small inputs.** Kibana KQL's external queries are short (650 bytes in all), so its MB/s is
  dominated by the per-call floor.

## Adding a language

A language joins the benchmark with one row in the bench's `LANGUAGES` table: its id, extensions,
corpus, external directories and parse entry point. The bench's `--count LANG MODE SET` runs one
pass after its warm-up, inside a function of its own, for an instruction count with callgrind
(ADR 0014 §6).

## Against the vendors

The vendors' own libraries, on the same inputs, through the same calls where a library offers them.
Release builds on one machine. The method is in
[ADR 0014](../internal/adr/0014-analysis-performance.md) §6.

| KQL: 20 Azure-Sentinel detections averaging 708 characters | opentide | Kusto.Language 12.4.1 (.NET 8) |
|---|---:|---:|
| Parse alone | 41 µs | 50 µs |
| Full analysis (Kusto: ParseAndAnalyze with the schema, plus GetDiagnostics, plus classifications) | ~270 µs | 287 µs |
| One-line query pair (`SecurityEvent \| take 10` and `take 11`) | 9.3 µs | 8.7 µs |
| 10,000 analyses in one process, time and peak memory, runtime start-up included | 3.0 s, 27.6 MiB | 4.7 s, 207 MiB |

The other languages' vendor comparisons follow as each is measured (#1571).

## Orders of magnitude

What the numbers mean against other parsers, as rough orders of magnitude, not as measurements.
None of these parsers was run here.

- **Hand-written parsers** (rust-analyzer's, Ruff's) parse tens of MB/s, building lossless trees as
  `opentide-parse` does. The parse rates above (4 to 30 MB/s, most around 20) are in that range for
  languages whose tokens are short.
- **ANTLR-generated parsers** (the JVM and .NET runtimes most vendor tools embed) usually run an
  order of magnitude slower, and pay a fixed cost per call: building the lexer, the parser and their
  caches. The per-call floors above (5 to 30 µs to parse a short query) are what that cost is set
  against.
