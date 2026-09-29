# Crates and dependencies

## Workspace members

`Cargo.toml` members, in dependency order of the product (not the member list):

```
opentide-core
  opentide-highlight
  opentide-syntax          (cc build of vendored parser.c)
    opentide-kql
    opentide-spl
      opentide-tide
        opentide-analysis
          opentide-lsp     (bin)
          opentide-wasm    (cdylib + rlib)
```

`opentide-kql` and `opentide-spl` must not depend on `opentide-tide` or `opentide-analysis`. Tide injects into them. Analysis depends on all three engines. A cycle means the layer is wrong.

Shared package metadata (`version`, `edition`, `rust-version`, `license`, `repository`) is `[workspace.package]`. New crates set `version.workspace = true` and the other `*.workspace = true` keys. License is EUPL-1.2.

## Adding a dependency

1. Put `name = { version = "...", features = [...] }` in `[workspace.dependencies]`.
2. Depend with `name.workspace = true` in the member.
3. Use the crate from the member that needs it, not from every crate.
4. Run the compile you need, then `git checkout -- Cargo.lock` if the only lock diff is a prune of unrelated packages. If you added a real crate, keep the new `[[package]]` blocks and the root package's `dependencies` update, and restore any deleted packages that were not yours.

`cc` is a build-dependency of `opentide-syntax` only. `wasm-bindgen` and `js-sys` are dependencies of `opentide-wasm` only. `clap` and `anyhow` are dependencies of `opentide-lsp` only.

## serde

- Engine structs that cross the CLI JSON boundary derive `Serialize` / `Deserialize`.
- `#[serde(rename_all = "kebab-case")]` on `LanguageId`, with explicit `rename` / `alias` where the wire string is not the kebab of the variant (`TideYaml` → `opentide-yaml`).
- Optional fields that must disappear from JSON use `#[serde(default, skip_serializing_if = "Option::is_none")]`.
- Catalog TOML uses `#[serde(default)]` on vectors and flags so a missing key is empty, not a parse failure.
- `toml::from_str` on `include_str!` data. Do not `std::fs::read_to_string` a catalog from an engine.
- `serde_json::json!` is the LSP wire format in `opentide-lsp`. See `skills/lsp-host/SKILL.md`.
- `serde_yaml` 0.9 parses Tide documents in `opentide-tide`. Keep it there.

## thiserror 2 and anyhow

`thiserror` 2 uses the same `#[derive(Error)]` / `#[error("...")]` / `#[from]` shape as 1.x. Prefer an enum variant over `Box<dyn Error>` in the engine.

`anyhow::Context` (`context("...")`) is for host I/O: reading a CLI path, binding a socket, parsing a content-length. `bail!` for a CLI usage error (`cannot detect language`).

## clap 4

```rust
#[derive(Parser, Debug)]
#[command(name = "opentide-lsp", version, about = "OpenTide language server")]
struct Cli {
    #[arg(long)]
    stdio: bool,
    #[arg(long)]
    listen: Option<String>,
    #[command(subcommand)]
    command: Option<Command>,
}
```

`main` checks `stdio`, then `listen`, then `command`. Keep that order. `--help` text is the about string; do not build a second argument parser.

## uuid

Feature `v4` is enabled at the workspace. Object ids go through `Uuid::parse_str` and `get_version_num() == 4`. `Uuid::new_v4()` is not used to invent ids inside the language server; documents bring their own ids. Generating an id belongs to content tooling, not this engine.

## regex

The `regex` crate is Unicode-aware by default. Patterns that should be ASCII-only say so (`(?-u:...)` or an explicit ASCII class). Prefer the existing helpers over a new pattern. A pattern that runs on every document is a `OnceLock`.

## similar

`similar` 2 is a workspace dependency and no crate imports it. Do not reach for it to diff two diagnostic lists. Assert the codes.

## insta

`insta` 1.48 is a dev-dependency of `opentide-kql`, `opentide-spl`, `opentide-highlight`, and `opentide-tide`. No test calls `insta::assert_snapshot`. Do not add a `.snap` file to make a review easier. Assert the code, the field path, and the severity. If a snapshot is specifically requested, `insta::assert_snapshot!` needs the `INSTA_UPDATE=1` env var to write, and the `.snap` file is committed.

## Profile

Release profile is already set: `lto = true`, `codegen-units = 1`, `strip = "symbols"`. Do not weaken it to make a local build faster.
