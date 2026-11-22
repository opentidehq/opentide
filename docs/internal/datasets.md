---
title: Embedded datasets
description: How opentide compiles its vocabularies, catalogs and templates into every binary compressed, the blob format and the pure-Rust decoder, what is pre-parsed at build time, and what it costs.
---

# Embedded datasets

Every binary carries data: the ATT&CK and actors vocabularies, the Falco, KQL, SPL, ES|QL, EQL, CQL, Exabeam, YARA and YARA-L catalogs, the Tide field catalog, the setup templates, the explain pages, the pins. Before [#1743](https://github.com/opentidehq/opentide/issues/1743) they were `include_str!`d as plain text, 11 MB of security vocabulary in the `.rdata` of every executable. Antivirus engines read it as the binary's own: ClamAV `Win.Coinminer.Generic-7150608-0` on the Falco miner-domain lists, hunting rules on the ATT&CK text (`sekurlsa::`, `InjectDLL`), a cloud verdict on a large unsigned executable full of stealer, miner and injection vocabulary ([the investigation](av-false-positives-2026-11-21.md)).

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
| The Tide vocabularies (`src/opentide/data/vocabulary/*.vocab.toml`, thirty-three files) | `opentide-tide`'s `Vocab` list (`vocab_model.rs`) | The editor's hover and completion on a technique, an actor or a TLP level read them, all thirty-four at once, with a whole-document TOML parse of each |
| The Azure Monitor Logs table reference (3.4 MB) and the ASIM schemas and parsers | `opentide-kql`'s `tables_model.rs` | The first KQL query of a Sentinel or Defender workspace read them |
| The Tide field catalog (`data/catalogs/tide/generated/fields.json`, 1.1 MB) | `opentide-highlight`'s `tide_model.rs`: every string once, the fields by place in that table, and the lists of enum values (440 KB of the file, repeated for each revision of each schema that has them) as a blob of their own, decoded when a field's list is first read | The first Tide document of a process parsed all of it |
| The CQL, Falco, Exabeam, ES\|QL, SPL, YARA and YARA-L catalogs (`data/catalogs/<language>/*.toml`) | Each crate's `catalog_model.rs` | The first query or rule of the language read them item by item (ADR 0013), the larger part of its first answer |

Not pre-parsed: the small catalogs read once and cheaply (EQL, Carbon Black's Lucene fields, the ECS fields), which are stored as compressed text.

The offers of the bundled vocabularies (#1755) are pre-parsed too, but by the schema crate's own build script: what a field that names a vocabulary offers (its values, a Markdown dropdown and a plain description for each) is a function of the bundled document alone, and `models::build` made it again for every revision of every object that names the vocabulary. `crates/opentide-schema/build.rs` compiles the offer's own code (`src/vocab/offer.rs`, with the vocabulary documents and the Markdown clean-up it reads) and writes one blob for each reference the schemas ask for (`OFFERED`: sixteen, 580 KB compressed in all, the ATT&CK techniques and the actors most of it), decoded when a field first asks. A workspace's own vocabularies, a data root's, an unlisted reference and a field that asks for unwrapped hints are worked out at run time, as before (`Vocabularies::memoized`). `the_build_makes_the_offers_the_catalog_asks_for` fails when the schemas ask for an offer the build does not make, or the build makes one nothing asks for; `what_the_build_made_is_what_is_worked_out_at_run_time` compares each blob with a fresh run-time offer; the field catalog's bytes are held by `tests/catalog.rs`.

The bundled vocabularies are stored as compressed text parsed by their loader, with their descriptions split off and decoded when one is asked for. Moving another dataset to a pre-parsed model is a change of its crate: put its model in a file that depends on `serde` and nothing else of the crate, `#[path]`-include it from `build.rs`, write it with `Datasets::value`, and measure with the bench below.

## Measurements

One machine (4 vCPU Intel Xeon @ 2.10 GHz, 15 GiB, Linux 6.18), release builds with the release profile's LTO, before (`integration/unified-core` at ef3ec6d) and after, built and run on the same machine within hours of each other, with the raw samples kept. Medians; a command is run 15 times after two warm-ups (`--version` 45), a dataset's first use in a fresh process 15 times, the language server by the scripted client of `scripts/perf/lsp-bench.mjs` (10 runs, 20 warm requests, the Tide corpus and a 1,000-object workspace).

### Artifacts

| Artifact (Linux, release) | Before | After | Change |
|---|---:|---:|---:|
| `opentide` | 51,816,976 | 41,222,368 | -10,594,608 (-20%) |
| `opentide-lsp` | 29,413,552 | 18,695,136 | -10,718,416 (-36%) |
| `_native` (the Python extension module; measured before the terminal UI came back to it) | 56,659,664 | 44,818,808 | -11,840,856 (-21%) |
| `opentide_wasm.wasm` (browser) | 24,627,305 | 13,809,876 | -10,817,429 (-44%) |
| `opentide-lsp.wasm` (WASI) | 24,714,988 | 14,551,975 | -10,163,013 (-41%) |

Section entropy (bits per byte, `scripts/av/entropy.py`): code is not compressed, and no code section is near 7.0. The read-only data section now holds the compressed blobs beside the tables and strings:

| Binary | whole file | code (`.text`, `code`) | read-only data (`.rodata`, wasm `data`) |
|---|---:|---:|---|
| `opentide`, before | 6.52 | 6.24 | 5.51 (14.0 MB) |
| `opentide`, after | 6.45 | 6.24 | 7.41 (4.6 MB) |
| `opentide-lsp`, before | 6.47 | 6.24 | 5.26 (12.2 MB) |
| `opentide-lsp`, after | 6.57 | 6.26 | 7.64 (2.9 MB) |
| `_native`, before | 6.50 | 6.23 | 5.51 (14.0 MB) |
| `_native`, after | 6.41 | 6.24 | 7.41 (4.6 MB) |
| `opentide-lsp.wasm`, before | 5.99 | 5.45 | 5.24 (12.2 MB) |
| `opentide-lsp.wasm`, after | 6.15 | 5.45 | 7.56 (2.9 MB) |

The code sections and every whole file stay below 7.0 (the gate fails above it). The data sections do not: more than half of what is left in `.rodata` is the compressed datasets, which are incompressible by construction, so its average is above 7.0. (The investigation's in-place experiment kept the PE layout by zero-padding the compressed regions, which lowers a section's entropy; its `.rdata` read 6.55.) If an antivirus verdict turns out to depend on a data section's entropy, the blobs can be stored base64-encoded (entropy 6.0, a third larger, a few hundred microseconds to decode): the container's `kind` byte leaves room for it. The release gate's ClamAV, YARA and Defender results say whether that is needed; it was not done on a guess.

### Commands

| Command | Before | After | Change |
|---|---:|---:|---:|
| `opentide --version` | 2.22 ms | 2.06 ms | -7% (noise) |
| `opentide --version`, page cache dropped before each run (9 runs each, alternating) | 9.4 ms | 9.0 ms | -0.4 ms (noise) |
| `opentide validate`, `tests/fixtures/tide_corpus` | 165 ms, 56 MiB | 78 ms, 48 MiB | -53%, -14% RSS |
| `opentide validate`, a 1,000-object workspace (`cargo xtask corpus generate`) | 352 ms, 84 MiB | 230 ms, 74 MiB | -35%, -12% RSS |

### First use of each dataset

`cargo bench -p opentide-analysis --features queries --bench datasets`: a dataset is read once per process, so each case is a fresh process. Wall time is the median of 15; instructions are callgrind's, in the bench's own code, deterministic (`[datasets]` in `tests/bench/instructions.toml`).

| First use of | Before ms | After ms | Change | Instructions before | after | Change | RSS growth before KiB | after KiB |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| vocab-attack | 6.2 | 6.2 | +0% | 29.3 M | 29.3 M | -0% | 4676 | 4052 |
| vocab-actors | 8.2 | 9.0 | +10% | 41.1 M | 43.9 M | +7% | 4564 | 4636 |
| vocab-malapi (removed since, #1753) | 2.0 | 2.2 | +10% | 9.8 M | 10.4 M | +6% | 2376 | 2988 |
| vocab-all | 23.9 | 24.0 | +0% | 117.3 M | 123.9 M | +6% | 10240 | 8652 |
| tide-vocab-attack | 34.3 | 15.5 | -55% | 145.9 M | 85.4 M | -41% | 10668 | 6780 |
| kql-sentinel | 116.8 | 39.7 | -66% | 621.2 M | 169.4 M | -73% | 20024 | 17108 |
| kql-defender | 82.1 | 25.2 | -69% | 463.3 M | 106.6 M | -77% | 13916 | 10680 |
| spl | 4.0 | 1.3 | -69% | 20.0 M | 5.8 M | -71% | 3544 | 3864 |
| esql | 5.1 | 1.2 | -77% | 24.5 M | 4.7 M | -81% | 4448 | 3888 |
| eql | 0.6 | 0.7 | +8% | 1.8 M | 2.3 M | +29% | 2452 | 3076 |
| lucene-carbon-black | 0.6 | 0.7 | +18% | 1.8 M | 2.3 M | +26% | 2108 | 2820 |
| falco | 12.6 | 3.2 | -75% | 64.5 M | 11.9 M | -82% | 4724 | 3644 |
| cql | 8.5 | 1.6 | -81% | 43.6 M | 6.8 M | -84% | 3836 | 3264 |
| exabeam | 6.4 | 2.2 | -65% | 35.2 M | 12.9 M | -63% | 3492 | 3164 |
| yara | 4.4 | 1.1 | -76% | 22.1 M | 4.9 M | -78% | 3260 | 3288 |
| yaral | 4.3 | 1.2 | -72% | 19.3 M | 6.8 M | -65% | 3468 | 3184 |
| tide-yaml | 3.2 | 2.1 | -33% | 16.6 M | 8.8 M | -47% | 5720 | 4468 |

Each case is measured by interleaving the two builds, one after the other, 15 rounds, in a fresh process each (`cargo bench -p opentide-analysis --features queries --bench datasets`; the raw samples of this run are kept with the PR). Run to run, a case moves by up to 10% (vocab-actors measured -1.7% over 41 rounds and +10% over 15), so read the large changes: every language catalog and the Tide field catalog are now parsed once at build time and are 33 to 81% faster to first use, KQL's Sentinel and Defender catalogs 66% and 69%, the Tide vocabularies the editor reads 55%. The bundled vocabularies (a lean document decoded and read item by item, descriptions decoded when one is asked for) and the small catalogs stored only as compressed text (EQL, Carbon Black's Lucene fields) are within noise in time, 5 to 29% more instructions (the decoder), and for the smallest of them 0.6 to 0.7 MiB more resident memory on first use: the decoder's code pages and its buffers. Every other case grows less than before.

### Language server

| Language server | Start to first diagnostics, p50 | Completion on an ATT&CK technique, cold / warm p50 | Peak RSS |
|---|---:|---:|---:|
| native, Tide corpus | 156 ms to 62 ms (-60%) | 6.0 / 5.8 ms to 6.1 / 5.7 ms | 121 to 114 MiB |
| native, 1,000 objects | 215 ms to 127 ms (-41%) | 8.6 / 6.6 ms to 8.0 / 6.2 ms | 156 to 149 MiB |
| WASI under wasmtime, Tide corpus | 349 ms to 192 ms (-45%) | 5.6 / 6.0 ms to 5.1 / 5.0 ms | 114 to 98 MiB |
| WASI under wasmtime, 1,000 objects | 500 ms to 350 ms (-30%) | 9.2 / 7.1 ms to 8.4 / 6.9 ms | 123 to 107 MiB |

The WASI module's own start under wasmtime (`opentide-lsp.wasm help`): 153 ms, 121 MiB before, 132 ms, 90 MiB after (a smaller module compiles and maps faster). Hover and completion that do not read a dataset first are within noise of each other in every row of the raw data (`hover:kql-column`, `hover:yaml-key`, `completion:kql-after-where`, ...).

### The decoder

`ruzstd` (pure Rust) decodes about 250 to 350 MB/s here: 4 to 7 ms for the 1.45 MB ATT&CK vocabulary, 7 ms for the 3.4 MB Azure Monitor reference. `lz4_flex` decodes 4 to 6 times faster (1 ms for ATT&CK) but its compressor leaves the datasets 2.7 times larger than zstd's level 19 (4.6 MB against 1.7 MB for the 16.9 MB of text the benchmark read), which the binaries and the wheels would carry: a pre-parsed or lazily decoded dataset made decode time a small part of a command, and size is what is paid by every download, so zstd is the format. `FrameDecoder::decode_all_to_vec` and the streaming decoder are within 5% of each other.


## Licences

Every dataset compiled in is redistributed in every binary, wheel, crate, npm package and WebAssembly build, so each needs a licence that allows it and the attribution that licence asks for. [`NOTICE`](../../NOTICE) holds the attribution; the licence and notice files it cites ship beside it at the paths it names: in the wheel through `license-files` (`pyproject.toml`, held by `tests/test_package/test_layout.py`), in each crate, each npm package of `@opentide/opentide` and the browser zip through `scripts/engine/release.py` (`vendor`, `legal`; `build-packages.yml` checks every tarball); for the standalone binaries, the GitHub Release attaches them one after another as `THIRD-PARTY-DATA-LICENSES.txt` (`legal-bundle`, an asset `check-assets` requires). Audited for [#1753](https://github.com/opentidehq/opentide/issues/1753) (2026-11), from each upstream's licence file or terms page:

| Dataset | Upstream | Licence | Attribution required | Status |
|---|---|---|---|---|
| ATT&CK vocabularies (`att&ck*`, `mitigations`, `datasources`, the ATT&CK groups of `actors`) | MITRE ATT&CK STIX data | ATT&CK Terms of Use: "a non-exclusive, royalty-free license to use ATT&CK® for research, development, and commercial purposes" | Reproduce "© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation." and the licence in any copy | In `NOTICE`, verbatim |
| `actors` (MISP actors) | MISP/misp-galaxy `clusters/threat-actor.json` | CC0 1.0 or BSD-2-Clause (dual, `LICENSE.md`) | None under CC0; credited | In `NOTICE` |
| `malapi` (removed) | malapi.io | **None found**: no licence or terms of use found, no public source repository | — | **Removed** ([#1753](https://github.com/opentidehq/opentide/issues/1753)): the owner decided opentide has no dependency on it; `vocab sync` skips it |
| Falco catalog (`data/catalogs/falco/`) | falcosecurity/libs, falco, plugins, rules | Apache-2.0; the driver's event table MIT or GPL-2.0-only (used under MIT) | Licence text and upstream NOTICE | In `NOTICE`, `LICENSE.txt`, `LICENSE-MIT.txt`, `NOTICE` |
| ECS fields (`data/catalogs/ecs/`) | elastic/ecs | Apache-2.0 | Licence text and upstream NOTICE | Shipped |
| Azure Monitor tables (`kql/azure-monitor/`) | MicrosoftDocs/azure-monitor-docs | CC BY 4.0 | Credit, licence link, changes indicated | In `NOTICE` |
| KQL core (`kql/core/`) | MicrosoftDocs/dataexplorer-docs | CC BY 4.0 (`LICENSE`; code samples MIT) | Credit, licence link, changes indicated | In `NOTICE` (added by #1753) |
| ASIM (`kql/asim/`) | Azure/Azure-Sentinel | MIT | Copyright and licence | In `NOTICE` |
| Defender and Sentinel tables (`kql/defender/`, `kql/sentinel/`) | Microsoft Learn pages, cited per entry | Not confirmed (names and types are facts) | — | Named in `NOTICE`; descriptions to be confirmed as written here |
| SPL (`spl/`) | Splunk documentation, cited per entry; CIM data models from splunk/pytest-splunk-addon (Apache-2.0) | Splunk docs: not confirmed (names are facts); CIM: Apache-2.0 | CIM: licence text | Named in `NOTICE`; descriptions to be confirmed as written here |
| ES\|QL, EQL (`esql/`, `eql/`) | elastic/elasticsearch documentation | AGPL-3.0, SSPL or Elastic License 2.0 (the repository's `LICENSE.txt`) | — (facts only; ES\|QL descriptions written here) | Named in `NOTICE`; EQL descriptions to be confirmed as written here |
| CQL (`cql/`) | CrowdStrike reference (facts), logscale-community-content (Unlicense), others | Unlicense, MIT, Apache-2.0, LGPL-2.1 (names only) | Licence texts | Shipped |
| Exabeam (`exabeam/`) | ExabeamLabs/CIMLibrary | Apache-2.0 | Licence text and NOTICE | Shipped |
| YARA (`yara/`) | VirusTotal/yara-x, VirusTotal/yara | BSD-3-Clause | Copyright, conditions, disclaimer in binary distributions | Shipped |
| YARA-L (`yaral/`) | Google Security Operations documentation | CC BY 4.0 | Credit, licence link | In `NOTICE`, `yaral/NOTICE` |
| Bitdefender, Carbon Black (`bitdefender/`, `carbon_black/`) | Vendor pages and MIT repositories, facts only | — (no text copied) | — | In `NOTICE` and each `NOTICE` |
| Time zones (`tz/`) | IANA tzdata | Public domain | — | In `NOTICE`, `tz/NOTICE` |
| Tide field catalog, schemas, templates, explain pages, the other vocabularies | opentide and opentidehq/specifications | opentide's own (EUPL-1.2); the specifications' as that repository states | — | Not re-audited here |

## Checks

- `scripts/av/markers.py` (pytest, `tests/test_scripts/test_av_markers.py`, and [the release gate](publishing.md#the-antivirus-gate)): none of `moneropool`, `sekurlsa`, `Login Data`, `Invoke-Mimikatz`, `jndi:ldap` in plain text, ASCII case folded and as UTF-16, in any artifact, archives opened. A source distribution (the sdist, a `.crate`) keeps the datasets as the TOML sources the build compresses, and the tests' sources name the techniques they detect: the text source files of a `.tar.gz` or `.crate` (and its `data`, `assets`, `tests` directories) are exempt from the markers, and the YARA gate skips them; every compiled artifact and every binary member is held to both.
- `cargo xtask throughput --check` holds the first use of each dataset (and the first hover on an ATT&CK technique) to `tests/bench/instructions.toml` (`[datasets]`, within 3%); `cargo bench -p opentide-analysis --features queries --bench datasets` prints the wall time and the resident-set growth of each. `scripts/av/sizes.py` holds each artifact to `tests/bench/sizes.toml`.
- The crates' tests hold what was pre-parsed to what the whole file holds, item for item (`opentide-kql` `tables.rs`, `opentide-tide` `vocabs.rs`, `opentide-highlight`'s `the_stored_catalog_is_the_whole_file`, and each language crate's `the_stored_catalogs_are_the_whole_files`), and `opentide-schema`'s tests hold every compiled-in file to the file on disk.
