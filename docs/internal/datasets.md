---
title: Embedded datasets
description: How opentide compiles its vocabularies, catalogs and templates into every binary compressed, the blob format and the pure-Rust decoder, what is pre-parsed at build time, and what it costs.
---

# Embedded datasets

Every binary carries data: the ATT&CK and actors vocabularies, `malapi`, the Falco, KQL, SPL, ES|QL, EQL, CQL, Exabeam, YARA and YARA-L catalogs, the Tide field catalog, the setup templates, the explain pages, the pins. Before [#1743](https://github.com/opentidehq/opentide/issues/1743) they were `include_str!`d as plain text, 11 MB of security vocabulary in the `.rdata` of every executable. Antivirus engines read it as the binary's own: ClamAV `Win.Coinminer.Generic-7150608-0` on the Falco miner-domain lists, hunting rules on the ATT&CK text (`sekurlsa::`, `InjectDLL`), a cloud verdict on a large unsigned executable full of stealer, miner and injection vocabulary ([the investigation](av-false-positives-2026-11-21.md)).

They are now **compressed at build time and decoded once per process, on first use**. This is compression, not obfuscation: no XOR (a byte XOR trips another rule, `SUSP_XORed_Mozilla_Oct19`), no key, no encryption, no packer. Code is not compressed: section entropy stays well below the 7.0 "packed" threshold ([measured below](#measurements)).

## The crate

[`opentide-dataset`](../../crates/opentide-dataset/AGENTS.md) (foundation tier 0) holds the container, the decoder and, behind the `encode` feature, the encoder.

```text
"OTD" | version (1 byte, 1) | kind (1 byte) | raw length (u32, little endian) | one zstd frame
```

| Kind | Holds | Read by |
|------|-------|---------|
| 0, text | The dataset's own text, UTF-8: a TOML or JSON file, a Markdown page, a template | `opentide_dataset::text!("<path>")`: a `&'static str`, decoded once |
| 1, pre-parsed | A model the crate's `build.rs` parsed once, serialised with [postcard](https://docs.rs/postcard) | `opentide_dataset::compiled_value::<T>(name, blob!(name))`: the model, decoded once |

- **One frame per dataset.** A command decodes only the datasets it reads, and each dataset's decode is paid once per process (a `OnceLock` in the macro, or the loader's own, as before).
- **zstd at level 19** (the window no larger than the dataset). Level 22 gains under 2% for several times the build time. The datasets the benchmark read (16.9 MB of text) become 1.7 MB.
- **The decoder is `ruzstd`, pure Rust**, so `wasm32-unknown-unknown` and `wasm32-wasip1` build it with no C toolchain. The encoder is libzstd (C), used only in build scripts: a build dependency is compiled for the host, never for a shipped target. `lz4_flex` (also pure Rust) decodes 4 to 5 times faster, but its compressor, which is all a build script can use of it, leaves the datasets 2.7 times larger (4.6 MB), so the binaries would grow; at 4 to 5 ms for the largest dataset the decoder's speed is not what a command waits for.
- **Every blob is checked where it is written.** `Datasets` decodes what it wrote and compares it with its input before the build goes on, so a blob that does not round-trip never ships. A blob read from elsewhere is an error value (`DatasetError`), never a panic.

A crate that compiles a dataset in lists nothing: its `build.rs` is one line (`Datasets::for_crate("data/catalogs")?.text_from_sources()?`), which encodes every file its sources name with `opentide_dataset::text!("<path>")`. `scripts/engine/release.py vendor` reads the same literal to put the files inside a published crate. Files are embedded as committed: `.gitattributes` marks `data/catalogs`, `highlights` and `src/opentide/data` `-text`, so a Windows checkout no longer embeds the catalogs with CRLF line endings (the same source gave a different binary per OS).

## What is pre-parsed

A parse at run time is what a dataset costs most. Where a model is plain data, the build parses the TOML once and stores the model (postcard), and the first reader decodes it with no TOML parse:

| Dataset | Pre-parsed model | Why |
|---------|------------------|-----|
| The Tide vocabularies (`src/opentide/data/vocabulary/*.vocab.toml`, thirty-four files) | `opentide-tide`'s `Vocab` list (`vocab_model.rs`) | The editor's hover and completion on a technique, an actor or a TLP level read them, all thirty-four at once, with a whole-document TOML parse of each |
| The Azure Monitor Logs table reference (3.4 MB) and the ASIM schemas and parsers | `opentide-kql`'s `tables_model.rs` | The first KQL query of a Sentinel or Defender workspace read them |
| The Tide field catalog (`data/catalogs/tide/generated/fields.json`, 1.1 MB) | `opentide-highlight`'s `tide_model.rs`: every string once, the fields by place in that table, and the lists of enum values (440 KB of the file, repeated for each revision of each schema that has them) as a blob of their own, decoded when a field's list is first read | The first Tide document of a process parsed all of it |
| The CQL, Falco, Exabeam, ES\|QL, SPL, YARA and YARA-L catalogs (`data/catalogs/<language>/*.toml`) | Each crate's `catalog_model.rs` | The first query or rule of the language read them item by item (ADR 0013), the larger part of its first answer |

Not pre-parsed: the small catalogs read once and cheaply (EQL, Carbon Black's Lucene fields, the ECS fields), which are stored as compressed text.

The bundled vocabularies are stored as compressed text parsed by their loader, with their descriptions split off and decoded when one is asked for. Moving another dataset to a pre-parsed model is a change of its crate: put its model in a file that depends on `serde` and nothing else of the crate, `#[path]`-include it from `build.rs`, write it with `Datasets::value`, and measure with the bench below.

## Measurements

One machine (4 vCPU Intel Xeon @ 2.10 GHz, 15 GiB, Linux 6.18), release builds with the release profile's LTO, before (`integration/unified-core` at ef3ec6d) and after, built and run on the same machine within hours of each other, with the raw samples kept. Medians; a command is run 15 times after two warm-ups (`--version` 45), a dataset's first use in a fresh process 15 times, the language server by the scripted client of `scripts/perf/lsp-bench.mjs` (10 runs, 20 warm requests, the Tide corpus and a 1,000-object workspace).

### Artifacts

| Artifact (Linux, release) | Before | After | Change |
|---|---:|---:|---:|
| `opentide` | 51,816,976 | 42,661,408 | -9,155,568 (-18%) |
| `opentide-lsp` | 29,413,552 | 20,126,336 | -9,287,216 (-32%) |
| `_native` (the Python extension module) | 56,659,664 | 46,255,608 | -10,404,056 (-18%) |
| `opentide_wasm.wasm` (browser) | 24,627,305 | 14,770,325 | -9,856,980 (-40%) |
| `opentide-lsp.wasm` (WASI) | 24,714,988 | 15,449,051 | -9,265,937 (-37%) |

Section entropy (bits per byte, `scripts/av/entropy.py`): code is not compressed, and no code section is near 7.0. The read-only data section now holds the compressed blobs beside the tables and strings:

| Binary | whole file | code (`.text`, `code`) | read-only data (`.rodata`, wasm `data`) |
|---|---:|---:|---|
| `opentide`, before | 6.52 | 6.24 | 5.51 (14.0 MB) |
| `opentide`, after | 6.44 | 6.24 | 7.41 (4.6 MB) |
| `opentide-lsp`, before | 6.47 | 6.24 | 5.26 (12.2 MB) |
| `opentide-lsp`, after | 6.54 | 6.24 | 7.64 (2.9 MB) |
| `_native`, before | 6.50 | 6.23 | 5.51 (14.0 MB) |
| `_native`, after | 6.40 | 6.23 | 7.41 (4.6 MB) |
| `opentide-lsp.wasm`, before | 5.99 | 5.45 | 5.24 (12.2 MB) |
| `opentide-lsp.wasm`, after | 6.11 | 5.44 | 7.55 (2.9 MB) |

The code sections and every whole file stay below 7.0 (the gate fails above it). The data sections do not: more than half of what is left in `.rodata` is the compressed datasets, which are incompressible by construction, so its average is above 7.0. (The investigation's in-place experiment kept the PE layout by zero-padding the compressed regions, which lowers a section's entropy; its `.rdata` read 6.55.) If an antivirus verdict turns out to depend on a data section's entropy, the blobs can be stored base64-encoded (entropy 6.0, a third larger, a few hundred microseconds to decode): the container's `kind` byte leaves room for it. The release gate's ClamAV, YARA and Defender results say whether that is needed; it was not done on a guess.

### Commands

| Command | Before | After | Change |
|---|---:|---:|---:|
| `opentide --version` | 2.22 ms | 2.03 ms | -9% (noise) |
| `opentide --version`, page cache dropped before each run (12 runs) | 5.2 ms | 5.8 ms | +0.6 ms (noise) |
| `opentide validate`, `tests/fixtures/tide_corpus` | 165 ms, 56 MiB | 78 ms, 50 MiB | -53%, -11% RSS |
| `opentide validate`, a 1,000-object workspace (`cargo xtask corpus generate`) | 352 ms, 84 MiB | 228 ms, 77 MiB | -35%, -8% RSS |

### First use of each dataset

`cargo bench -p opentide-analysis --features queries --bench datasets`: a dataset is read once per process, so each case is a fresh process. Wall time is the median of 15; instructions are callgrind's, in the bench's own code, deterministic (`[datasets]` in `tests/bench/instructions.toml`).

| First use of | Before ms | After ms | Change | Instructions before | after | Change |
|---|---:|---:|---:|---:|---:|---:|
| vocab-attack | 7.8 | 6.3 | -20% | 29.3 M | 29.3 M | -0% |
| vocab-actors | 11.1 | 8.7 | -22% | 41.1 M | 43.9 M | +7% |
| vocab-malapi | 3.0 | 2.2 | -24% | 9.8 M | 10.4 M | +6% |
| vocab-all | 33.3 | 24.7 | -26% | 117.3 M | 123.9 M | +6% |
| tide-vocab-attack | 36.6 | 15.6 | -58% | 145.9 M | 85.4 M | -41% |
| kql-sentinel | 137.1 | 40.4 | -71% | 621.2 M | 169.4 M | -73% |
| kql-defender | 92.5 | 24.0 | -74% | 463.3 M | 106.6 M | -77% |
| spl | 4.3 | 4.7 | +10% | 20.0 M | 23.9 M | +20% |
| esql | 5.3 | 6.0 | +13% | 24.5 M | 27.3 M | +11% |
| eql | 0.7 | 0.7 | +9% | 1.8 M | 2.3 M | +29% |
| lucene-carbon-black | 0.7 | 0.7 | -5% | 1.8 M | 2.3 M | +26% |
| falco | 13.8 | 14.2 | +3% | 64.5 M | 72.7 M | +13% |
| cql | 9.2 | 12.8 | +39% | 43.6 M | 48.7 M | +12% |
| exabeam | 7.8 | 7.8 | -1% | 35.2 M | 43.6 M | +24% |
| yara | 4.8 | 4.9 | +2% | 22.1 M | 25.1 M | +14% |
| yaral | 4.3 | 5.1 | +19% | 19.3 M | 24.3 M | +26% |
| tide-yaml | 3.4 | 7.5 | +120% | 16.6 M | 32.2 M | +94% |

The parsed-at-build datasets are faster (KQL's Sentinel and Defender catalogs 70% and 74% sooner, the Tide vocabularies the editor reads 57%). The vocabularies are not slower: their descriptions are decoded only when one is asked for. The language catalogs, which are only compressed, pay the decode: under 1 ms for most, 4 ms for the CQL catalog's 0.9 MB, and about 4 ms more for the first Tide YAML analysis, which reads the 1.1 MB Tide field catalog. Moving one of those to a pre-parsed model is a change of its crate (see above).

### Language server

| Language server | Start to first diagnostics, p50 | Completion on an ATT&CK technique, cold / warm p50 | Peak RSS |
|---|---:|---:|---:|
| native, Tide corpus | 156 ms to 63 ms (-59%) | 6.0 / 5.8 ms to 5.6 / 5.6 ms | 121 to 118 MiB |
| native, 1,000 objects | 215 ms to 131 ms (-39%) | 8.6 / 6.6 ms to 7.4 / 6.2 ms | 156 to 153 MiB |
| WASI under wasmtime, Tide corpus | 349 ms to 208 ms (-40%) | 5.6 / 6.0 ms to 5.1 / 5.3 ms | 121 to 101 MiB |
| WASI under wasmtime, 1,000 objects | 500 ms to 345 ms (-31%) | 9.2 / 7.1 ms to 8.6 / 7.4 ms | 123 to 112 MiB |

The WASI module's own start under wasmtime (`opentide-lsp.wasm help`): 153 ms, 121 MiB before, 132 ms, 95 MiB after (a smaller module compiles and maps faster). Hover and completion that do not read a dataset first are within noise of each other in every row of the raw data (`hover:kql-column`, `hover:yaml-key`, `completion:kql-after-where`, ...).

### The decoder

`ruzstd` (pure Rust) decodes about 250 to 350 MB/s here: 4 to 7 ms for the 1.45 MB ATT&CK vocabulary, 7 ms for the 3.4 MB Azure Monitor reference. `lz4_flex` decodes 4 to 6 times faster (1 ms for ATT&CK) but its compressor leaves the datasets 2.7 times larger than zstd's level 19 (4.6 MB against 1.7 MB for the 16.9 MB of text the benchmark read), which the binaries and the wheels would carry: a pre-parsed or lazily decoded dataset made decode time a small part of a command, and size is what is paid by every download, so zstd is the format. `FrameDecoder::decode_all_to_vec` and the streaming decoder are within 5% of each other.


## Checks

- `scripts/av/markers.py` (pytest, `tests/test_scripts/test_av_markers.py`, and [the release gate](publishing.md#the-antivirus-gate)): none of `moneropool`, `sekurlsa`, `Login Data`, `Invoke-Mimikatz`, `jndi:ldap` in plain text, ASCII case folded and as UTF-16, in any artifact, archives opened. A source distribution (the sdist, a `.crate`) keeps the datasets as the TOML sources the build compresses, and the tests' sources name the techniques they detect: the text source files of a `.tar.gz` or `.crate` (and its `data`, `assets`, `tests` directories) are exempt from the markers, and the YARA gate skips them; every compiled artifact and every binary member is held to both.
- `cargo xtask throughput --check` holds the first use of each dataset to `tests/bench/instructions.toml` (`[datasets]`, within 3%); `cargo bench -p opentide-analysis --features queries --bench datasets` prints the wall time and the resident-set growth of each. `scripts/av/sizes.py` holds each artifact to `tests/bench/sizes.toml`.
- The crates' tests hold what was pre-parsed to what the whole file holds, item for item (`opentide-kql` `tables.rs`, `opentide-tide` `vocabs.rs`), and `opentide-schema`'s tests hold every compiled-in file to the file on disk.
