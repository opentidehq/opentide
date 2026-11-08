# AGENTS.md — the Rust workspace and the engine

Instructions for coding agents working on the Cargo workspace of this repository (`opentidehq/opentide`): the engine crates in `crates/`, imported from opentidehq/language-server with their history (`docs/engine/IMPORT.md`), the binding in `analysis/`, the tooling in `xtask/`, and the grammars, highlights, catalogs, editors, npm packages and fuzz targets they build on. The root `AGENTS.md` is the map of the rest. Each crate has its own `AGENTS.md`; read it before changing the crate. Detection-authoring skills live in `opentidehq/skills` and are not an engine.

Before editing, read the one skill that matches the change. Skills follow the [Agent Skills specification](https://agentskills.io/specification).

| Change | Read |
| --- | --- |
| Any `crates/**/*.rs`, `Cargo.toml`, `Cargo.lock` | `.agents/skills/rust-engine/SKILL.md` |
| `grammars/`, `crates/opentide-syntax`, `highlights/queries/` | `.agents/skills/tree-sitter/SKILL.md` |
| `crates/opentide-lsp`, `editors/`, stdio tests | `.agents/skills/lsp-host/SKILL.md` |
| `crates/opentide-wasm`, `packages/`, packaging | `.agents/skills/wasm-hosts/SKILL.md` |
| A `crates/CHANGELOG.md` entry, or an engine release's notes | `.agents/skills/engine-release-notes/SKILL.md` |
| An engine release: `scripts/engine/release.py`, `.github/engine-workflows/release.yml` | `.agents/skills/engine-release/SKILL.md` |
| `data/catalogs/`, `highlights/spec.toml`, `crates/testdata/conformance`, `crates/testdata/oracles`, `scripts/engine/oracles`, schema sync | `.agents/skills/catalogs/SKILL.md` |
| A new query language (S1QL, Sigma, YARA) | `.agents/skills/add-language/SKILL.md` (then the rows above) |

## Product

Native language server for **KQL**, **SPL**, **Tide YAML**, the Elastic Security languages **ES|QL**, **EQL**, **Kibana KQL** (`kuery`, never confused with Microsoft KQL), and **Lucene**, and **Falco** rule conditions (Sysdig Secure, `configurations.sysdig`). SQL is out of scope. Names use `opentide`, never `otide`. The client factory is `createOpentideClient`.

The offline query checks of the CLI (`validate`'s and `lint`'s `queries` checks, `validate query`), `opentide lsp start`, `opentide tui` and MCP `validate_query` run this engine: `analysis/` binds `opentide-analysis` and `opentide-lsp` with PyO3, by path, and `hatch_build.py` compiles it into the opentide package as `opentide._native`. There is no separate engine distribution and no engine pin. `uv sync` builds `_native` (develop profile) with the Rust release `rust-toolchain.toml` pins (rustup installs it); the crates declare `rust-version` 1.85, but no job checks it: the code needs Rust 1.88 or later (let chains) and `Cargo.lock` 1.90 (tree-sitter-language 0.1.8). Release wheels are one `cp310-abi3` wheel per platform, and the sdist carries the workspace.

Engines are I/O-free. Hosts (`opentide-lsp`, the WASM crate, the TypeScript packages) own the filesystem and the editor protocol. The CLI (`analyze`, `highlight`, `generate-highlights`) prints plain JSON. Only `--stdio` and `--listen` speak JSON-RPC.

## Crates and layers

One workspace (root `Cargo.toml`, one `Cargo.lock`; `fuzz/` keeps its own). A crate depends only on crates of a lower layer, or of a lower tier of its own layer; `cargo xtask check-layers` enforces [`xtask/layers.toml`](../xtask/layers.toml), the one copy of the table (plan §4), and a new crate fails it until it is placed there.

| Layer, tier | Crates (each with an `AGENTS.md`) |
| --- | --- |
| foundation 0 | [`opentide-core`](opentide-core/AGENTS.md) |
| foundation 1 | [`opentide-syntax`](opentide-syntax/AGENTS.md), [`opentide-highlight`](opentide-highlight/AGENTS.md), [`opentide-ecs`](opentide-ecs/AGENTS.md) |
| foundation 2 | [`opentide-kql`](opentide-kql/AGENTS.md), [`opentide-spl`](opentide-spl/AGENTS.md), [`opentide-kuery`](opentide-kuery/AGENTS.md), [`opentide-lucene`](opentide-lucene/AGENTS.md), [`opentide-falco`](opentide-falco/AGENTS.md) |
| foundation 3 | [`opentide-esql`](opentide-esql/AGENTS.md), [`opentide-eql`](opentide-eql/AGENTS.md) |
| foundation 4 | [`opentide-schema`](opentide-schema/AGENTS.md) |
| domain 0, 1 | [`opentide-tide`](opentide-tide/AGENTS.md), then [`opentide-analysis`](opentide-analysis/AGENTS.md) |
| application | [`opentide-lsp`](opentide-lsp/AGENTS.md) |
| facade | none yet: the `opentide` crate (UC-5.1, #836) |
| bindings | [`opentide-native`](../analysis/AGENTS.md) (`analysis/`), [`opentide-wasm`](opentide-wasm/AGENTS.md) |
| tooling | [`xtask`](../xtask/AGENTS.md) |

## Hard rules

- No `std::fs` in `crates/opentide-{core,highlight,syntax,kql,spl,esql,eql,kuery,lucene,falco,ecs,tide,analysis,schema}/src`. Tests may read the repo.
- Do not rename a HighlightSpec capture. Adding one is a minor (`highlights/spec.toml` `[meta].version`).
- Do not validate CrowdStrike. `configurations.crowdstrike.*` stays unsupported.
- Control commands (`.show`, `.create`) parse so the engine can emit `kql_control_command_unsupported`. They are not valid detections.
- Highlight tokenizes **authored** SPL. An implicit leading `| search` is not a source rewrite.
- opentide LSP owns Tide diagnostics. Editor samples keep yamlls off `objects/**`.
- There is no `opentide-sql` crate, no `.sql` language id, and no stub SQL highlighter.
- Do not hand-edit `grammars/**/src/parser.c`, `grammar.json`, or `node-types.json`. Regenerate with `tree-sitter-cli` **0.25.10**.
- Do not commit a rewritten `Cargo.lock` with a change that is not about dependencies. The lock is what Cargo resolves and CI builds with `--locked`; restore the committed lock if Cargo rewrites it.
- Configuration TOML (`opentide-config`, #158) is checked by the host, never by Rust. The engine places the host checker's `{code, field_path, severity}` findings and reads the host's schemas for hover and completion. No configuration check logic in Rust, no vendored or hand-written configuration schema, no TOML grammar, no HighlightSpec captures. Without a host checker there are no configuration diagnostics.
- Pydantic in this repository's `opentide` package (`src/opentide`) remains CLI authority for Tide objects. The LSP matches `{code, field_path, severity}` and adds ranges.
- A change opentide users see gets an entry in `CHANGELOG.md`, beside `crates/CHANGELOG.md`. After a change to `analysis/src/lib.rs`, update `src/opentide/_native.pyi`.
- Object models, vocabulary or pins (`src/opentide`) change the bundled Tide catalog: regenerate it in the same change with `uv run python scripts/engine/sync_opentide_schemas.py`.

## Lints

The workspace's lints are in the root `Cargo.toml` (`[workspace.lints]`), each allowed pedantic lint with its reason; `clippy.toml` allows `unwrap`, `expect` and `dbg!` in `#[test]` functions and `#[cfg(test)]` modules; `rustfmt.toml` writes down rustfmt's defaults.

- **One Rust, pinned.** `rust-toolchain.toml` names an exact release; CI installs that file's toolchain, so a new stable's lints cannot turn every PR red. Move to a newer release in a change of its own, as the file says: bump `channel`, then fix or allow (with a reason) what the new lints report.

- **`unsafe_code` is forbidden** except in `opentide-syntax` (tree-sitter FFI) and `opentide-wasm` (wasm32 libc shims). Those two copy the workspace table with `unsafe_code = "deny"`, allow it per item with a reason, and comment every `unsafe` block with `// SAFETY:`. `xtask/tests/lint_policy.rs` fails when a copy drifts or another crate leaves the workspace table.
- **No `unwrap`, `expect`, `dbg!`, `todo!` or `unimplemented!` outside tests.** A panic on user input is a bug: return a diagnostic or an error. Where a value cannot fail (a catalog compiled in with `include_str!`, a regex literal, a structural invariant), the item says why: `#[expect(clippy::expect_used, reason = "...")]`. An integration test file's helpers outside `#[test]` take the same `#![expect]` at the file's top.
- **`missing_docs`** holds for `opentide-syntax`, `opentide-kuery`, `opentide-lsp`, `opentide-wasm`, `opentide-native` and `xtask`, and for every new crate. The eleven other crates, imported undocumented, opt out at their crate root (`#![expect(missing_docs, ...)]`); remove the opt-out once a crate is documented. Inaccurate docs are worse than none.
- Prefer `#[expect(..., reason)]` to `#[allow]`: a stale expectation fails. Use `allow` only where an expectation cannot be fulfilled (clippy's glob-import lints; `dead_code` in a test module only some test binaries use up), and say so beside it.
- **Casts.** `clippy::cast_possible_truncation` is on: a narrowing `as` carries `#[expect(..., reason)]` on its function naming the bound (LSP positions are `u32`; a char is one or two UTF-16 units), or becomes `try_from`, or widens the other side.

## Tests

| Command | Runs |
| --- | --- |
| `cargo nextest run --profile fast` | Unit tests and the fast integration tests of the workspace, about 15 s warm on 4 cores; `-p <crate>` for one crate. It leaves out the stdio server tests, the Pydantic comparison, the deep-nesting test and the public corpora (`.config/nextest.toml`) |
| `cargo nextest run --workspace --profile ci` | Everything, no retries, JUnit at `target/nextest/ci/junit.xml` |
| `cargo test --workspace --doc` | Doctests, which nextest does not run (CI's `cargo test --workspace` does) |
| `cargo test --workspace` | Everything, without nextest |

The tests that compare the engine with the Pydantic models need `uv sync --group dev` first (they run `.venv`'s interpreter; `OPENTIDE_PYTHON` names another).

**Snapshots (insta).** `insta::assert_snapshot!` keeps the expected text in `tests/snapshots/*.snap` next to the test, committed and reviewed like code (`crates/opentide-analysis/tests/snapshots.rs`). After an intended change run the test, then `cargo insta review` (`cargo install cargo-insta --locked`) or `INSTA_UPDATE=always cargo test -p <crate> --test <name>`, and read the diff before committing. CI sets `INSTA_UPDATE=no`: a changed or missing snapshot fails and nothing is written. Never commit a `.snap.new` (gitignored). Snapshot what a contract fixes (a diagnostic's code, range and message, a renderer's output), not whole structs.

**Command-line cases (trycmd).** `tests/cmd/*.trycmd` hold a binary's commands with their output and exit status (`? 2`); `tests/cmd/<case>.in/` is the working directory; `[..]` elides a part that varies (a version). `TRYCMD=overwrite cargo test -p <crate> --test cli` rewrites the expected output after an intended change. Used by `opentide-lsp` and `xtask`.

## Verify

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo xtask check-layers
bash scripts/engine/check-io-free.sh
bash scripts/engine/check-names.sh
bash scripts/engine/validate-skills.sh
cargo test --workspace
cargo run -p opentide-lsp -- generate-highlights --check
```

Grammar, catalog, and corpus edits can flip an oracle verdict. `bash scripts/engine/ci-oracle.sh` runs the Kusto.Language and Splunk oracles and skips a reference you do not have (`scripts/engine/oracles/README.md`). Grammar edits also need `bash scripts/engine/check-grammars.sh` from the repository root (CLI 0.25.10). The engine's CI jobs (`ci.yml`'s `engine` and `engine-wasm`, and `engine-ci.yml`) set `RUSTFLAGS=-Dwarnings`. Code under `cfg(target_arch = "wasm32")` or `cfg(target_os = "wasi")` is linted only for that target: `bash scripts/engine/build-wasm.sh clippy` (CI's `engine-wasm` job) runs clippy for `opentide-wasm` on wasm32-unknown-unknown and `opentide-lsp` on wasm32-wasip1 with the wasm C toolchain the grammars need. Code under `cfg(windows)` is built and tested by `engine-ci.yml`'s Windows job but not linted with clippy (UC-0.3, #801, adds the Windows and macOS Rust jobs).

## Upstream docs, not downloaded skills

The Rust project, tree-sitter, wasm-bindgen, and the LSP spec publish documentation, not Agent Skills. Use those docs when a skill points at them:

- Edition 2024: <https://doc.rust-lang.org/stable/edition-guide/rust-2024/>
- tree-sitter 0.25.10: <https://docs.rs/tree-sitter/0.25.10/tree_sitter/>
- wasm-bindgen targets: <https://wasm-bindgen.github.io/wasm-bindgen/reference/rust-targets.html>
- LSP framing: <https://microsoft.github.io/language-server-protocol/specifications/lsp/3.17/specification/#headerPart>

Do not `npx skills add` a generic Rust, tree-sitter, or WASM skill into this repo. The packs on skills.sh describe async services, snapshot tests, `wasm-pack`, or a multi-hundred-language parser cache. None of them match this engine. Apollo's `rust-best-practices` handbook is the closest maintained Rust skill and still disagrees with this repo on snapshots and async.
