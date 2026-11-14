# Vendored crates

Crates this repository carries a patched copy of, for the WASI build of the command line (ADR
0007's amendment), wired in by `[patch.crates-io]` in the root
`Cargo.toml`. Each is upstream's published crate with the smallest change opentide needs, its
licence files kept. They are not workspace members (`exclude` in the root `Cargo.toml`), and the
crates opentide publishes to crates.io depend on upstream's version: a patch applies only to builds
from this repository.

## memmap2 0.9.12

- **Upstream:** [`memmap2` 0.9.12](https://crates.io/crates/memmap2) (MIT OR Apache-2.0),
  <https://github.com/RazrFalcon/memmap2-rs>.
- **Why:** gix reads git's loose objects (gix-odb), packs (gix-pack) and the index (gix-index)
  through memmap2. WASI preview 1 has no mmap, so upstream's `stub.rs` refuses every map there,
  and the WASI build of the command line (ADR 0007's amendment) would read every repository as
  having no commits: changed objects, promotion and change detection would not work.
- **The change:**
  - `src/lib.rs`: on `target_os = "wasi"` the platform module is the new `src/wasi.rs` instead of
    `src/stub.rs` (two `cfg_attr` lines).
  - `src/wasi.rs`, new: read-only and private maps are the file's bytes read into the heap, an
    anonymous map is zeroed heap, and shared writable and executable maps stay `Unsupported`.
  - `Cargo.toml`: a `[lints.rust]` table that allows `mismatched_lifetime_syntaxes`, which a
    newer rustc reports in upstream's code. As a path dependency its warnings are not capped,
    and CI builds with `-Dwarnings`.
  - Every other file is upstream's, byte for byte: Linux, macOS and Windows build the same code.
- **Cost:** a heap map holds the whole mapped range, and it is a snapshot (a later write to the
  file does not show in it). gix maps whole pack files, so a WASI run's memory grows with the
  repository's packs.
- **Upstream:** a WASI backend belongs in memmap2. An issue to file, proposing `src/wasi.rs` as
  a read-into-heap fallback behind `target_os = "wasi"`; when a release has one, drop this copy
  and the patch.

To update: copy the new upstream release's `src/`, licences and `Cargo.toml` here, then reapply the
change above (`diff -ru <registry>/memmap2-<version>/src vendor/memmap2/src` shows it).

## filetime 0.2.29

- **Upstream:** [`filetime` 0.2.29](https://crates.io/crates/filetime) (MIT/Apache-2.0),
  <https://github.com/alexcrichton/filetime>.
- **Why:** gix-index reads the index file's modification time with
  `FileTime::from_last_modification_time`, whose wasm backend is `unimplemented!()`: on WASI,
  reading a checkout's index (`generate docs --changed`, changed objects) would panic, which
  aborts the module.
- **The change:** `src/wasm.rs` only. On `target_os = "wasi"`, `from_last_modification_time`,
  `from_last_access_time` and `from_creation_time` read std's `Metadata::modified`, `accessed`
  and `created`, which WASI has; other wasm targets keep upstream's `unimplemented!()`. Every
  other file is upstream's.
- **Upstream:** an issue to file, proposing the same for `target_os = "wasi"`; when a release has
  it, drop this copy and the patch.
