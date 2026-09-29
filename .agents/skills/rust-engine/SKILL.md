---
name: rust-engine
description: Change the OpenTide Rust workspace (edition 2024, rust-version 1.85). Covers I/O-free engine crates, thiserror 2 versus anyhow, serde, toml 0.8, uuid, regex, OnceLock catalogs, clippy -D warnings, and the Cargo.lock that must not be pruned. Use when editing crates/, Cargo.toml, Cargo.lock, or any Rust test.
license: EUPL-1.2
metadata:
  author: OpenTideHQ
---

# Rust engine

The workspace is edition **2024**, `rust-version` **1.85**, toolchain channel `stable` with `rustfmt` and `clippy` (`rust-toolchain.toml`). CI exports `RUSTFLAGS=-Dwarnings` and runs `cargo clippy --workspace --all-targets -- -D warnings`. A warning is a failed build.

Read `references/crates.md` before adding a dependency or a new crate. Read `references/edition-2024.md` before writing `unsafe`, `extern`, or a function that returns `impl Trait`.

## Layout

| Crate | May call `std::fs` in `src/` | Error type | Role |
| --- | --- | --- | --- |
| `opentide-core` | no | `thiserror` | `LanguageId`, ranges, `codes` |
| `opentide-highlight` | no | `thiserror` | HighlightSpec, semantic tokens |
| `opentide-syntax` | no | strings at the query boundary | tree-sitter 0.25 bindings |
| `opentide-kql` | no | `Diagnostic` | KQL catalog, HIR, profiles (`thiserror` is declared and unused) |
| `opentide-spl` | no | `Diagnostic` | SPL catalog |
| `opentide-tide` | no | `Diagnostic` | Tide YAML, UUID graph, injection |
| `opentide-analysis` | no | — | `WorkspaceHost` orchestrator |
| `opentide-lsp` | yes | `anyhow` | stdio host and CLI |
| `opentide-wasm` | no (host is JS) | `JsValue` | `highlight` / `legend` only |

`scripts/check-io-free.sh` greps `use std::fs` and `std::fs::` under those engine `src/` trees. `build.rs` and `tests/` may touch the filesystem. `opentide-lsp` and `main.rs` are the native host.

New engine code takes bytes or strings from the caller. It does not open paths, environment variables, or the network. Catalog text is `include_str!` at compile time. `WorkspaceHost` is how analysis sees a workspace (`MemoryWorkspace` in tests).

## Dependencies

Versions live in the workspace `[workspace.dependencies]` table. Path crates use `opentide-core.workspace = true`, never a second version number. Do not `cargo add` a crate into one member without putting the version in the workspace table.

Pinned stack (do not bump in passing):

| Crate | Locked | Where it is allowed |
| --- | --- | --- |
| `serde` 1 / `serde_json` 1 | lockfile | derive on engine types; JSON at the host boundary |
| `toml` 0.8 | 0.8.23 | catalog files and `highlights/spec.toml` |
| `serde_yaml` 0.9 | lockfile | Tide YAML only. Do not migrate to `serde_yml` |
| `thiserror` 2 | 2.0.20 | library errors |
| `anyhow` 1 | 1.0.104 | `opentide-lsp` binary only |
| `clap` 4 | derive | `opentide-lsp` CLI only |
| `regex` 1 | lockfile | compile once |
| `uuid` 1 (`v4` feature) | 1.26 | Tide object ids in `opentide-tide` |
| `tree-sitter` | 0.25.10 | `opentide-syntax` and the query engines. See `tree-sitter` |
| `lsp-types` | 0.97.0 | declared on `opentide-lsp`, unused by the hand-rolled loop. See `lsp-host` |
| `insta` 1 | dev-dependency | declared, no `assert_snapshot!` yet |

`Cargo.lock` deliberately keeps crates that are not all referenced by the current graph. `cargo build` / `cargo test` rewrite the lock and drop those entries. CI does not pass `--locked`. If a command rewrites `Cargo.lock`, restore the committed file (`git checkout -- Cargo.lock`) unless the change intentionally adds a dependency. `scripts/cloud-agent-install.sh` does this restore after warming the build.

## Types agents get wrong

`LanguageId` is `kql`, `spl`, or `opentide-yaml`. `LanguageId::parse` also accepts `kusto`, `opentide-kql`, `opentide-spl`, `yaml`, and `tide`. It returns `None` for `sql`. Serde uses kebab-case plus the aliases in `crates/opentide-core/src/lib.rs`. A new variant needs `as_str`, `parse`, and `Display` updated together.

Diagnostic codes are constants in `opentide_core::codes`. Add a constant. Do not invent a second string at the call site. Issue identity for Tide objects is `{code, field_path, severity}` plus a real `Range`.

LSP `character` is a UTF-16 code unit count. `é` is one unit; an emoji outside the BMP is two. Ranges **sent** to the client go through `span_to_range` / `offset_to_position` in `opentide-core`, which uses `char::len_utf16`.

Two older inbound converters do not match that. Do not add a third, and do not "fix" one of them in a drive-by:

- `offset_at` in `crates/opentide-lsp/src/server.rs` treats `character` as a **byte** index into the line (capped by the line's byte length). Incremental `didChange` uses it.
- `position_to_offset` (the lsp server and `opentide-kql`) counts Unicode scalar values (`col += 1` per `char`).

A change to any of the three needs a fixture containing `é` and a non-BMP character, and the other two call sites reviewed in the same change. Do not index the source with `position.character` as a byte index in new code; call one of these helpers.

`uuid::Uuid::parse_str` plus `get_version_num() == 4` is the object-id check (`is_uuidv4`). Do not add another parser. A 36-character hex UUID that is not version 4 is a different future check (configuration `organisation_uuid`) and does not belong in this function.

## Errors

`opentide-core` and `opentide-highlight` use `thiserror` 2. Query and Tide engines return `opentide_core::Diagnostic` instead of a second error enum. Do not add `thiserror` to a crate that already returns `Diagnostic`.

```rust
#[derive(Debug, thiserror::Error)]
pub enum HighlightError {
    #[error("highlight spec: {0}")]
    Spec(String),
    #[error("unknown capture '{0}' (not in highlights/spec.toml)")]
    UnknownCapture(String),
}
```

`#[error("...")]` is the display text. `anyhow` stays in the binary (`Context` on I/O). Do not return `anyhow::Error` from an engine crate. Do not `unwrap()` catalog parses on a request path that should surface a diagnostic. `expect` on `include_str!` data is acceptable because a bad catalog fails the build's tests, not a user document.

`clap` 4: `#[derive(Parser)]` on `Cli`, `#[command(subcommand)]` for `analyze` / `highlight` / `generate-highlights`. `--stdio` and `--listen` are flags checked **before** the subcommand. A new subcommand must print plain JSON or text. It must not write `Content-Length` frames.

## Regex and OnceLock

Catalogs and the highlight spec load through `std::sync::OnceLock` (`Catalog::cached`, `HighlightSpec::load`). Parse each profile once per process. Do not re-parse TOML on every keystroke.

`regex::Regex::new` is expensive and fallible. New regexes go in a `OnceLock<Regex>` (or a function-scoped `OnceLock`) and the pattern is a tested string. Do not call `Regex::new` inside a loop over diagnostics. Existing call sites that still compile per call are not a reason to copy that shape.

## Tests

- Engine unit tests sit next to the code (`#[cfg(test)]`) or in `crates/<crate>/tests/*.rs`.
- Integration tests may use `PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")` to find `testdata/`.
- Assert diagnostic **codes** (and field paths when the contract says so). Do not snapshot an entire struct with `insta` unless the user asked. `insta` is a dev-dependency and nothing calls it.
- `cargo test --workspace` is the default. Name the test binary when iterating: `cargo test -p opentide-kql --lib`.
- `cargo fmt --all` before finishing. rustfmt is not optional.

## What not to add

- `tower-lsp`, `lsp-server`, or a second JSON-RPC stack. See `lsp-host`.
- `std::fs` in an engine `src/` tree. Pass the text in.
- `async` / `tokio` in the engine. The server is a blocking stdio loop.
- A new `LanguageId` without the `add-language` skill.
- `unsafe` except the existing tree-sitter FFI and a documented invariant. Edition 2024 requires `unsafe extern` and `#[unsafe(no_mangle)]`. See `references/edition-2024.md`.
