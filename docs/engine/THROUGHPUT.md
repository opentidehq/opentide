---
title: "Throughput"
description: "How fast each language's parse and analysis run, in wall time and in instructions, how that is measured and held (the throughput bench, cargo xtask throughput, ADR 0014), and how it compares with the vendors' own libraries."
---

# Throughput

Each language is measured in two modes, on two input sets:

- **Modes:** `parse` (the language's own parse alone) and `analyze` (`opentide_analysis::analyze`:
  the parse, every check, the semantic tokens).
- **`corpus`:** `crates/testdata/corpus/<lang>/`, short queries. These give the per-call floor an
  editor pays on every keystroke.
- **`external`:** the real public rules under `crates/testdata/conformance/external/`, plus the
  accepted queries of a reference parser's `cases.tsv`. These give bytes a second on realistic input.
  A text is a file or one `cases.tsv` row. Exabeam's external set leaves out its `.rule.exabeam`
  files, which belong to the Correlation Rule profile, not the Search profile the bench analyses.

[ADR 0014](../internal/adr/0014-analysis-performance.md) is the pattern that keeps these numbers
down, and says how to measure them.

## Wall time

`cargo bench -p opentide-analysis --bench throughput`: a release build with LTO, 1 thread, and
ADR 0014 §6's method: a 3 s warm-up, then at least 15 rounds and 5 s, the median. The numbers below come from one 4-vCPU Linux
machine on 2026-11-18. Time varies with the machine and its load, so compare runs on one machine
only.

| Language | Corpus, parse µs/call | Corpus, analyze µs/call | External, parse MB/s | External, analyze MB/s | External texts, bytes |
|---|---:|---:|---:|---:|---|
| KQL | 5.7 | 38.4 | 21.6 | 3.5 | 15, 39,092 |
| ES\|QL | 6.2 | 28.2 | 21.0 | 5.4 | 12, 2,844 |
| EQL | 6.7 | 17.9 | 26.8 | 8.9 | 12, 2,978 |
| Kibana KQL | 4.4 | 17.1 | 7.1 | 2.9 | 55, 650 |
| Lucene | 4.8 | 16.2 | 8.8 | 3.4 | 335, 6,654 |
| SPL † | 10.3 | 32.4 | 17.1 | 4.5 | 14, 12,328 |
| CQL † | 21.5 | 25.8 | 10.6 | 9.0 | 45, 55,062 |
| Falco † | 10.6 | 15.4 | 11.4 | 0.2 | 241, 30,955 |
| YARA † | 31.4 | 47.0 | 4.0 | 3.0 | 50, 206,242 |
| Exabeam † | 20.1 | 41.6 | 6.6 | 3.7 | 4, 794 |
| YARA-L † | 14.4 | 26.4 | 22.3 | 10.3 | 79, 243,055 |

How to read the table:

- **Two-column ratio.** Where the external parse rate is high and the analyze rate low, the time
  goes on analysis, not parsing. That cost grows with the input: KQL spends about 700 µs on an
  external rule against a 40 µs floor on a corpus query, Falco about 640 µs a rule. It is the
  analysis's own work on long input, not per-call setup, and it is what step 4 of #1571 goes after.
- **Parse entry points (marked †).** SPL, CQL, Falco, YARA, Exabeam and YARA-L are measured through
  their crates' `debug_kinds`, which also formats every kind's name (a quarter to two fifths of its
  time) and, for YARA, parses twice. Their parse figure is a lower bound on speed until each crate
  gives the benchmark a plain parse.
- **Small inputs.** Kibana KQL's and Lucene's external queries are short (12 and 20 bytes on
  average), and Exabeam's set is 794 bytes, so their MB/s is dominated by the per-call floor.

## Instructions: the gate

`cargo xtask throughput --check` builds the same bench with its symbols kept, then counts each
language's instructions with callgrind (valgrind required). For every language, mode and input set
it runs the bench's `--count`: two warm-up passes, then one pass inside a function of its own,
which callgrind alone counts (`--toggle-collect`). Each count is held to
[`tests/bench/instructions.toml`](../../tests/bench/instructions.toml):

- **Over budget.** A count more than 3% over its budget fails, and so does a count with no budget.
- **Under budget.** A count more than 3% under is reported, with a request to record the budgets
  again (`cargo xtask throughput --record`), so that the gain is kept.

Instruction counts are deterministic for a build and an input, which time is not: two runs of one
build differ by under 1% (hash seeds, the routine chosen by CPU feature). CI's `throughput` job runs
the check when any crate the analysis is built from changes, and on every push. A change that
raises a count on purpose records the budgets again and gives the reason in its pull request.

## Adding a language

A language joins the bench and the gate with one row in the bench's `LANGUAGES` table: its id,
extensions, corpus, external directories, the file names to leave out, and its parse entry point.
Then `cargo xtask throughput --record --language <name>` adds its budgets: a record merges into
the file, so the other languages' budgets stay as they are.

## Against the vendors

The vendors' own libraries, on the same inputs, through the same calls where a library offers them.
Release builds on one machine. The method is in
[ADR 0014](../internal/adr/0014-analysis-performance.md) §6.

| KQL: 20 Azure-Sentinel detections averaging 708 characters (not this bench's input set) | opentide | Kusto.Language 12.4.1 (.NET 8) |
|---|---:|---:|
| Parse alone | 41 µs | 50 µs |
| Full analysis (Kusto: ParseAndAnalyze with the schema, plus GetDiagnostics, plus classifications) | ~270 µs | 287 µs |
| One-line query pair (`SecurityEvent \| take 10` and `take 11`) | 9.3 µs | 8.7 µs |
| 10,000 analyses in one process, time and peak memory, runtime start-up included | 3.0 s, 27.6 MiB | 4.7 s, 207 MiB |

Caveats, from ADR 0014:

- opentide's parse figure (~41 µs) was taken on a busier machine; before #1573, on a quieter one, it
  was 34 µs. None of these rows can be set against the wall-time table above, which is another
  machine and another input set.
- The 10,000-analysis row comes from the orchestrating session's vendor harness and includes each
  runtime's start-up (and .NET's JIT), which the per-call rows do not.

The other languages' vendor comparisons follow as each is measured (#1571).

## Orders of magnitude

What the numbers mean against other parsers, as rough orders of magnitude, not as measurements.
None of these parsers was run here.

- **Measured here:** only Kusto.Language, above. Kusto.Language is hand-written C#, not generated,
  and opentide's KQL parse is about a fifth faster on the same detections.
- **Not measured here:** the other vendors' parsers. They are a mix: Lucene's classic query parser
  is JavaCC-generated, Elastic's ES|QL and EQL parsers are ANTLR-generated, and others are closed.
  Whether a generated parser's fixed cost per call (building the lexer, the parser and their caches)
  outweighs opentide's per-call floor (5 to 30 µs to parse a short query) is a hypothesis each
  language's comparison tests, not a result.
