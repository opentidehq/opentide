# opentide-dataset — agent guide

The embedded datasets (the catalogs, the vocabularies, the pins, the templates), compressed at build
time and decoded once per process, on first use (#1743). I/O-free, no `unsafe`, no workspace dependency;
the format and the measurements are in [`docs/internal/datasets.md`](../../docs/internal/datasets.md).

| Item | What |
|------|------|
| `text!("<path>")` | The text of the file `<path>` under the assets root (`data/catalogs/...`, `src/opentide/data/...`, `highlights/...`), decoded on first use and shared (`&'static str`) |
| `value!(Type, "<name>")`, `blob!("<name>")` + `compiled_value` | A **pre-parsed** dataset: a model the crate's `build.rs` parsed once and serialised with postcard |
| `decode`, `text`, `value`, `raw_len`, `DatasetError` | The container's reader: errors as data, for tools and tests |
| `build` (feature `encode`) | The encoder, for a `build.rs`'s `[build-dependencies]` only: `Datasets::for_crate(marker)`, `text_from_sources()`, `text`, `value` |

## Place

foundation, tier 0 (`xtask/layers.toml`). Every crate that compiles a dataset in depends on it, and its
`build.rs` on it with `features = ["encode"]`. The encoder's `zstd` (libzstd, C) is a **build** dependency:
it is compiled for the host and never for a shipped target, so `wasm32-unknown-unknown` and `wasm32-wasip1`
build with no C toolchain (the decoder, `ruzstd`, is pure Rust).

## Rules

- **Never `include_str!` a dataset.** A dataset is `opentide_dataset::text!("<path>")` (the path under the
  assets root, written with that exact prefix: `Datasets::text_from_sources` finds every use by scanning
  `src/`), and the crate's `build.rs` is `Datasets::for_crate("<a directory of the root>")?.text_from_sources()?`.
  A new use needs nothing else; `scripts/engine/release.py vendor` reads the same literal. A plain-text dataset
  puts the words of a security vocabulary in every binary, which is what antivirus heuristics flagged
  (`scripts/av/markers.py` fails the build of any artifact that carries one).
- **Compression, not obfuscation.** No XOR, no key, no encryption, no packer; code is never compressed. A
  byte XOR trips another rule (`SUSP_XORed_Mozilla_Oct19`, the investigation's V7). zstd at level 19, one
  frame per dataset, so a command decodes only what it reads.
- **The build checks its own blobs.** `Datasets` decodes every blob it writes and compares it with its input
  before the build goes on; `compiled_text` and `compiled_value` carry the one `expect` for a blob that
  cannot fail to decode. A damaged blob read from elsewhere is an error (`DatasetError`), never a panic.
- **Pre-parse only a model that is plain data.** The crate's `build.rs` includes the model's file with
  `#[path]`, so that file may depend on `serde` and the parser and on nothing else of the crate
  (`opentide-tide`'s `vocab_model.rs` is the example). Measure first: `cargo bench -p opentide-analysis
  --features queries --bench datasets` and `cargo xtask throughput` (`[datasets]` in
  `tests/bench/instructions.toml`).
- Text files are embedded as committed (`.gitattributes` `-text` on `data/catalogs`, `highlights` and
  `src/opentide/data`): the same bytes on every OS.
