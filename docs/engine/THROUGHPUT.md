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
| Datadog ‡ | 3.9 | 8.7 | 17.3 | 9.1 | 2,895, 148,278 |

How to read the table:

- **Two-column ratio.** Where the external parse rate is high and the analyze rate low, the time
  goes on analysis, not parsing. That cost grows with the input: KQL spends about 700 µs on an
  external rule against a 40 µs floor on a corpus query, Falco about 640 µs a rule. It is the
  analysis's own work on long input, not per-call setup, and it is what step 4 of #1571 goes after.
- **Parse entry points (marked †).** Every language's parse is now its crate's plain `parses`
  (#1584). The † parse figures above were taken before that, through `debug_kinds`, which also
  formats every kind's name (a quarter to two fifths of its time) and, for YARA, parsed twice: they
  understate those languages' parse speed until the table is next recorded. YARA's `parses` drains
  `yara-x-parser`'s events and builds no tree, where the other languages' build their rowan tree,
  so its parse figure is not like for like with theirs.
- **Datadog (‡)** was measured on 2026-11-26, on another machine, when the language was added;
  Lucene measured 5.2, 11.6, 10.3 and 4.2 on the same run, so the row compares with the
  others to within that machine's difference. Its external set is Datadog's 2,895 published
  queries (`published.jsonl`, one text per query, 51 bytes on average).
- **Small inputs.** Kibana KQL's and Lucene's external queries are short (12 and 20 bytes on
  average), and Exabeam's set is 794 bytes, so their MB/s is dominated by the per-call floor.

## Instructions: the gate

`cargo xtask throughput --check` also counts the first use of each embedded dataset, in the `datasets` bench (`crates/opentide-analysis/benches/datasets.rs`, held under `[datasets]`: [docs/internal/datasets.md](../internal/datasets.md)). It builds the same bench with its symbols kept, then counts each
language's instructions with callgrind (valgrind required). For every language, mode and input set
it runs the bench's `--count`: two warm-up passes, then one pass inside a function of its own,
whose instructions callgrind alone counts (`--toggle-collect`). Each pass is counted three times (`--runs`), and
the lowest is held to [`tests/bench/instructions.toml`](../../tests/bench/instructions.toml):

- **Over budget.** An instruction count more than 3% over its budget fails, an allocator-call
  count more than 2 calls over fails, and so does a count with no budget, or a budget no pass
  counted any more.
- **Under budget.** A count further under than that is a warning that asks for the budgets to be
  recorded again (`cargo xtask throughput --record`), so that the gain is kept.

Instruction counts do not depend on the machine's load, which time does. Only the bench binary's
own instructions are counted: glibc (malloc, the string routines) and the loader are left out. Their
counts move with the glibc version, with the CPU glibc picks a routine for, and with the allocation
order each process's hash seeds give: counted with them, one run of a pass differed from the next by
1.5%, and CI's runner from a local run by up to 3.3%. Without them, runs differ by under 0.1%.

What an allocation costs inside malloc and free is then out of the instruction count, so each pass
has a second budget, `<mode>_<set>_allocations`: how many times the counted pass enters `malloc`,
`calloc`, `realloc` or the aligned allocators, whoever called them. Callgrind counts it as the
number of times each allocator's first instruction runs (`--dump-instr=yes`), not from its call
arcs: whether callgrind records `__rust_alloc`'s tail jump into `malloc` as a call of its own
depends on where the code lies. On #1624, the arcs over the warm-up and counted passes of CQL's
and Falco's corpus analyses rose by 7,312 and 10,049 while their allocations fell. An instruction
runs as often however it is reached, and the count covers the counted pass alone, as the
instructions do. On #1624's base and head it is the same for every CQL and Falco parse and falls
by 96 to 741 for each analysis, as #1624's own change does.

The new budgets are a third of the old for a parse, which does no one-time work, and lower still
for an analysis: the arc count also took in the warm-up's one-time work (catalogs, compiled
queries) wherever it allocated through a call site the counted pass shares, and every Rust
allocation goes through the same few. glibc's calls between its own allocators count too
(`posix_memalign` with a small alignment and `realloc` of a null pointer go through `malloc`), but
Rust's system allocator makes neither, so one Rust allocation is one entry.

The count does not vary from run to run (ten runs of Exabeam's corpus analysis gave one count).
From machine to machine, the earlier arc count varied once by one call (Exabeam's corpus analysis,
on CI's runner), so it is held within 2 calls, not a percentage: every input set has more analyses
than that, and one allocation more a call fails the check. When the check fails, CI uploads the
callgrind profiles (`target/throughput/`), which `callgrind_annotate --inclusive=yes` traces to a
function. Each pass is counted three times (`--runs`): a record writes the highest, a check takes
the lowest. The budgets file names the valgrind, glibc and architecture it was recorded on, and a
check elsewhere warns. CI's `throughput` job is pinned to
`ubuntu-24.04` (glibc 2.39, valgrind 3.22), where the budgets are recorded, so that its valgrind
counts as it did there.

CI's `throughput` job runs the check when any crate the analysis is built from changes, when the
bench, the budgets or the command change, and on every push; the table goes to the step summary. A
change that raises a count on purpose records the budgets again and gives the reason in its pull
request.

## The language server's cold start

The time from spawning the language server to the first diagnostics of a rule it was asked to open
(`start_to_first_diag_ms`), as an editor sees it on start-up, is held in the nightly by bench.yml's
`Benchmarks (language server cold start)` job (#1754). The scripted client of
`scripts/perf/lsp-bench.mjs` (VS Code's recorded capabilities, pull diagnostics) measures four
scenarios, 10 runs each, every run a fresh server (`scripts/perf/cold-start.sh`):

| Scenario | Server | Workspace | Target (#1746) | EPYC 9V74 | EPYC 7763 |
|---|---|---|---:|---:|---:|
| `native_small` | `opentide-lsp`, `--release` | the Tide corpus | 62 ms | 42.5 ms | 55.8 ms |
| `native_large` | `opentide-lsp`, `--release` | 1,000 object files | 127 ms | 66.5 ms | 90.6 ms |
| `wasi_small` | `opentide-lsp.wasm` (`wasm32-wasip1`, `--profile wasi-lsp`) under wasmtime | the Tide corpus | 192 ms, waived | 192.6 ms | 240.2 ms |
| `wasi_large` | the same | 1,000 object files | 350 ms, waived | 419.4 ms | 522.3 ms |

The workspaces are `scripts/perf/make_workspace.py`'s: the Tide corpus as the CLI E2E suite lays it
out, and the corpus's rules copied up to 1,000 object files. The WASI module runs under wasmtime
(`wasmtime run --dir / -S inherit-env`, the version bench.yml installs), the host #1746 measured
with. `WASI_HOST=node` runs it under Node's WASI (`scripts/engine/wasi-run.mjs`) for comparing two
builds on one machine; Node's own start and its compile of the module add about 100 ms, so those
numbers are not comparable with the budgets (on a 4-vCPU Xeon: 276 and 395 ms where #1746 measured
192 and 350 under wasmtime).

`scripts/perf/check_cold_start.py` holds each p50 to `tests/bench/lsp-cold-start.toml` with the
rules of every other benchmark budget, `tests/bench/budgets.toml`'s `[policy]`, which it reads:

- **The target.** The p50s #1746 measured after its fix on one 4-vCPU Xeon
  ([docs/internal/datasets.md](../internal/datasets.md), "Language server") are the targets. A p50
  more than `regression` (10%) above its target fails, when the difference is also above
  `noise_floor_s` (20 ms). The runner class measures WASI above #1746's figures, so those two
  targets carry a `target_waiver`, as `budgets.toml` waives a target the runners miss. The summary
  still shows them.
- **The CPU's own figure.** Each p50 is also held to the one recorded on the report's CPU model
  (`[[cpu_baseline]]`, from CI runs of the job: the table's last two columns) + `regression`. On a
  CPU model recorded nowhere, it is held to the slowest recorded + `cross_cpu_regression` (20%).
  GitHub's runners of one class come on several CPUs: the 7763 measured 1.25 to 1.36 times the
  9V74 here.

A scenario with no report or no reference, a report with failed runs or another run count, and a
report no scenario budgets fail too. Re-record the figures only from a CI run of the job, in a
change of its own that says why. Add a `[[cpu_baseline]]` when a run's summary names an
unrecorded CPU. The reports, every sample kept, are the run's `bench-lsp-cold-start` artifact.
To measure locally:

```bash
cargo build --release -p opentide-lsp
cargo build --profile wasi-lsp -p opentide-lsp --target wasm32-wasip1
scripts/perf/cold-start.sh /tmp/cold-start target/release/opentide-lsp \
  target/wasm32-wasip1/wasi-lsp/opentide-lsp.wasm
python3 scripts/perf/check_cold_start.py tests/bench/lsp-cold-start.toml /tmp/cold-start
```

Numbers from a machine other than CI's runner class (`ubuntu-24.04`, 4 vCPU) are for comparing two
builds on that machine, not for the budgets.

## Adding a language

A language joins the bench and the gate with one row in the bench's `LANGUAGES` table: its id,
extensions, corpus, external directories, the file names to leave out, and its parse entry point.
Then `cargo xtask throughput --record --language <name>` adds its budgets: a record merges into
the file, so the other languages' budgets stay as they are.

## One walk per analysis

ADR 0014 §5a: one walk of the tree serves a language's checks and its highlight. KQL, ES|QL,
Lucene and Kibana KQL walk with `opentide_parse::walk_once`; EQL, SPL, CQL and YARA-L walk once
with preorder walks of their own, written before it. Exabeam and Falco already walked their rowan
tree once, for the highlight, and their checks read a parse of their own. That second parse is the
cost left in both, and moving the checks onto the tree is its own change.

## Against the vendors

The vendors' own libraries, on the same inputs, through the same calls where a library offers them.
Release builds on one machine. The method is in
[ADR 0014](../internal/adr/0014-analysis-performance.md) §6.

Measured by the orchestrating session's vendor harness on integration 947ad05a1 (2026-11-19), both
libraries on the same machine in one run, release builds, µs per call:

| KQL: 20 Azure-Sentinel detections averaging 708 characters (not this bench's input set) | opentide | Kusto.Language 12.4.1 (.NET 8) |
|---|---:|---:|
| Parse alone | 33.8 µs | 43.2 µs |
| Full analysis (Kusto: ParseAndAnalyze with the schema, plus GetDiagnostics, plus classifications) | 188.6 µs | 254.7 µs |
| Kusto without the classifications (ParseAndAnalyze plus GetDiagnostics) | 188.6 µs | 207.0 µs |

| KQL: one-line query pair (`SecurityEvent \| take 10` and `take 11`) | opentide | Kusto.Language 12.4.1 (.NET 8) |
|---|---:|---:|
| Parse alone | 1.33 µs | 1.85 µs |
| Full analysis (as above) | 6.25 µs | 8.15 µs |
| Kusto without the classifications | 6.25 µs | 6.85 µs |

opentide's analysis always includes its highlight (the semantic tokens), so it is the full row on
both lines. An earlier run, on another machine, had the one-line pair at 9.3 µs against Kusto's
8.7 µs; measured on one machine, opentide is now ahead.

| KQL, the earlier run (another machine) | opentide | Kusto.Language 12.4.1 (.NET 8) |
|---|---:|---:|
| 10,000 analyses in one process, time and peak memory, runtime start-up included | 3.0 s, 27.6 MiB | 4.7 s, 207 MiB |

Caveats:

- None of these rows can be set against the wall-time table above, which is another machine and
  another input set.
- The 10,000-analysis row includes each runtime's start-up (and .NET's JIT), which the per-call rows
  do not, and has not been measured again since.

The other languages' vendor comparisons follow as each is measured (#1571).

## Orders of magnitude

What the numbers mean against other parsers, as rough orders of magnitude, not as measurements.
None of these parsers was run here.

- **Measured here:** only Kusto.Language, above. Kusto.Language is hand-written C#, not generated,
  and opentide's KQL parse takes about a fifth less time on the same detections.
- **Not measured here:** the other vendors' parsers. They are a mix: Lucene's classic query parser
  is JavaCC-generated, Elastic's ES|QL and EQL parsers are ANTLR-generated, and others are closed.
  Whether a generated parser's fixed cost per call (building the lexer, the parser and their caches)
  outweighs opentide's per-call floor (5 to 30 µs to parse a short query) is a hypothesis each
  language's comparison tests, not a result.
