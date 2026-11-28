# AGENTS.md — the Rust workspace and the engine

Instructions for coding agents working on the Cargo workspace of this repository (`opentidehq/opentide`): the engine crates in `crates/`, imported from opentidehq/language-server with their history (`docs/engine/IMPORT.md`), the binding in `bindings/python/`, the tooling in `xtask/`, and the highlights, catalogs, editors, npm packages and fuzz targets they build on. The root `AGENTS.md` is the map of the rest. Each crate has its own `AGENTS.md`; read it before changing the crate. Detection-authoring skills live in `opentidehq/skills` and are not an engine.

Before editing, read the one skill that matches the change. Skills follow the [Agent Skills specification](https://agentskills.io/specification).

| Change | Read |
| --- | --- |
| Any `crates/**/*.rs`, `Cargo.toml`, `Cargo.lock` | `.agents/skills/rust-engine/SKILL.md` |
| A language crate's lexer, parser, `.ungram` or keyword table; `crates/opentide-parse` | `.agents/skills/parser/SKILL.md` |
| `crates/opentide-lsp`, `editors/`, stdio tests | `.agents/skills/lsp-host/SKILL.md` |
| `crates/opentide-wasm`, `packages/`, packaging | `.agents/skills/wasm-hosts/SKILL.md` |
| A `crates/CHANGELOG.md` entry, or an engine release's notes | `.agents/skills/engine-release-notes/SKILL.md` |
| A release: the release train (`.github/workflows/publish.yml`, `vX.Y.Z` tags; `scripts/engine/release.py` for the crates and assets); the engine's own `engine-v*` releases are retired | `release-management`, in the root `AGENTS.md`'s skills table |
| `data/catalogs/`, `highlights/spec.toml`, `crates/testdata/conformance`, `crates/testdata/oracles`, `scripts/engine/oracles`, schema sync | `.agents/skills/catalogs/SKILL.md` |
| A new query language (S1QL, Sigma) | `.agents/skills/add-language/SKILL.md`: its checklist and definition of done, which link every rule the language meets (then the rows above) |

## Product

Native language server for **KQL**, **SPL**, **Tide YAML**, the Elastic Security languages **ES|QL**, **EQL**, **Kibana KQL** (`kuery`, never confused with Microsoft KQL), and **Lucene** (Elastic, plus the Carbon Black Cloud and Graylog dialects: `configurations.carbon_black_cloud`, and `--platform graylog`), **Falco** rule conditions (Sysdig Secure, `configurations.sysdig`), the **CrowdStrike Query Language** (CQL: Falcon LogScale and Next-Gen SIEM, `configurations.crowdstrike`), **YARA** (YARA-X 1.x is the language; the HarfangLab and Bitdefender profiles refuse YARA-X-only syntax: `.yar` and `.yara` files, `docs/engine/YARA.md`), the **Exabeam Query Language** (`exabeam`, never `eql`: Exabeam New-Scale SIEM, `.exabeam` files, `docs/engine/EXABEAM.md`), **YARA-L 2.0** (Google Security Operations: `.yaral` and `.yl2` files, `docs/engine/YARAL.md`), and the **Datadog log search syntax** (`datadog`: Datadog Cloud SIEM, `.datadog` files, `docs/engine/DATADOG.md`; its platform is phase 2 of `docs/internal/rfc-datadog-cloud-siem.md`). SQL is out of scope: there is no generic SQL dialect; Exabeam's SQL-like advanced operators are part of its specified language and live in the `exabeam` grammar only. Names use `opentide`, never `otide`. The client factory is `createOpentideClient`.

The offline query checks of the CLI (`validate`'s and `lint`'s `queries` checks, `validate query`), `opentide lsp start`, `opentide tui` and MCP `validate_query` run this engine: `bindings/python/` binds the facade crate `opentide` (its `analysis` and `cli` features; `opentide-cli` hosts `opentide-lsp`) with PyO3, by path, and maturin (`[tool.maturin]` in `pyproject.toml`) compiles it into the opentide package as `opentide._native`. There is no separate engine distribution and no engine pin. `uv sync` builds `_native` (develop profile) with the Rust release `rust-toolchain.toml` pins (rustup installs it); the crates declare `rust-version` 1.95 (what `yara-x-parser` and `yara-x-fmt` need), but no job checks it. Release wheels are one `cp310-abi3` wheel per platform, and the sdist carries the workspace.

Engines are I/O-free. Hosts (`opentide-lsp`, the WASM crate, the TypeScript packages) own the filesystem and the editor protocol. The CLI (`analyze`, `highlight`, `generate-highlights`) prints plain JSON. Only `--stdio` and `--listen` speak JSON-RPC.

## Crates and layers

One workspace (root `Cargo.toml`, one `Cargo.lock`; `fuzz/` keeps its own). A crate depends only on crates of a lower layer, or of a lower tier of its own layer; `cargo xtask check-layers` enforces [`xtask/layers.toml`](../xtask/layers.toml), the one copy of the table (plan §4), and a new crate fails it until it is placed there.

| Layer, tier | Crates (each with an `AGENTS.md`) |
| --- | --- |
| foundation 0 | [`opentide-core`](opentide-core/AGENTS.md), [`opentide-schema-derive`](opentide-schema-derive/AGENTS.md) (the `#[derive(FromNode)]` proc-macro opentide-schema uses), [`opentide-dataset`](opentide-dataset/AGENTS.md) (the embedded datasets, compressed at build time and decoded on first use, #1743), [`opentide-cassette`](opentide-cassette/AGENTS.md) (the recorded-HTTP harness, UC-4.1, not published) |
| foundation 1 | [`opentide-parse`](opentide-parse/AGENTS.md) (the pure-Rust parsers' toolkit, ADR 0012), [`opentide-highlight`](opentide-highlight/AGENTS.md), [`opentide-ecs`](opentide-ecs/AGENTS.md) |
| foundation 2 | [`opentide-kql`](opentide-kql/AGENTS.md), [`opentide-spl`](opentide-spl/AGENTS.md), [`opentide-kuery`](opentide-kuery/AGENTS.md), [`opentide-falco`](opentide-falco/AGENTS.md), [`opentide-cql`](opentide-cql/AGENTS.md), [`opentide-yara`](opentide-yara/AGENTS.md), [`opentide-yaral`](opentide-yaral/AGENTS.md), [`opentide-exabeam`](opentide-exabeam/AGENTS.md), [`opentide-datadog`](opentide-datadog/AGENTS.md). A new query language goes here, with an `AGENTS.md` |
| foundation 3 | [`opentide-lucene`](opentide-lucene/AGENTS.md) (above kuery: each tells the other's rules by the other's grammar) |
| foundation 4 | [`opentide-esql`](opentide-esql/AGENTS.md), [`opentide-eql`](opentide-eql/AGENTS.md) |
| foundation 5 | [`opentide-schema`](opentide-schema/AGENTS.md) |
| domain 0, 1, 2 | [`opentide-tide`](opentide-tide/AGENTS.md) and [`opentide-workspace`](opentide-workspace/AGENTS.md) (loading and the index, UC-2.1), then [`opentide-analysis`](opentide-analysis/AGENTS.md) and [`opentide-compile`](opentide-compile/AGENTS.md) (deploy compile and plan, UC-3.1), then [`opentide-connectors`](opentide-connectors/AGENTS.md) (tenant HTTP, UC-4.1) |
| application 0, 1 | [`opentide-lsp`](opentide-lsp/AGENTS.md), then [`opentide-cli`](opentide-cli/AGENTS.md) (the command line, UC-3.3, which hosts the language server: `lsp start`) |
| facade | [`opentide`](opentide/AGENTS.md): the Rust SDK, the only crate with a stability promise (UC-5.1, #836) |
| bindings | [`opentide-native`](../bindings/python/AGENTS.md) (`bindings/python/`), [`opentide-wasm`](opentide-wasm/AGENTS.md), [`opentide-node`](../bindings/node/AGENTS.md) (`bindings/node`, the npm package `@opentide/opentide`, UC-5.3) |
| tooling | [`xtask`](../xtask/AGENTS.md) |

## Hard rules

- No `std::fs` in an engine crate's `src/`: `scripts/engine/check-io-free.sh` lists them (`opentide-core`, `-highlight`, `-parse`, `-ecs`, `-tide`, `-analysis`, `-schema` and every language crate), and a new language crate is added there. Tests may read the repo.
- Do not rename a HighlightSpec capture. Adding one is a minor (`highlights/spec.toml` `[meta].version`).
- CrowdStrike is CQL, checked against CrowdStrike's published grammar and function reference (`docs/engine/CQL.md`). Never report an unknown field, saved search, lookup file or repository as a finding: they live in the tenant.
- Control commands (`.show`, `.create`) parse so the engine can emit `kql_control_command_unsupported`. They are not valid detections.
- Highlight tokenizes **authored** SPL. An implicit leading `| search` is not a source rewrite.
- opentide LSP owns Tide diagnostics. Editor samples keep yamlls off `objects/**`.
- There is no `opentide-sql` crate, no `.sql` language id, and no stub SQL highlighter.
- Every query parser is pure Rust on `opentide-parse` (ADR 0012; YARA reads `yara-x-parser`). No C, no tree-sitter, no generated parser: do not add a `cc` build or a `*-sys` crate to the engine (the WASI command line's `ring` is the one C dependency). Do not hand-edit `src/generated/ast.rs`: `cargo xtask codegen` writes it from the `.ungram`.
- Do not commit a rewritten `Cargo.lock` with a change that is not about dependencies. The lock is what Cargo resolves and CI builds with `--locked`; restore the committed lock if Cargo rewrites it.
- Configuration TOML (`opentide-config`, #158): the models, layering and checks are `opentide-schema`'s `configuration` module (UC-1.5, #811), the Python CLI's configuration text checks ported and compared case for case. The language server checks a buffer natively with `buffer_issues` (UC-2.6, #821) and `opentide-analysis` places the `{code, field_path, severity}` findings (`place_configuration_issues`); hover and completion read the host's schemas. No configuration check logic in `opentide-analysis`, no vendored or hand-written configuration schema, no TOML grammar, no HighlightSpec captures.
- YARA's verdict parser is `yara-x-parser`, never the `yara-x` compiler crate (wasmtime, breaks WASI). `yara-x` and `yara-python` are oracles only: not in `Cargo.lock`, never shipped.
- The Tide object checks are `opentide-workspace`'s `validate`: the language server publishes its findings (UC-2.6, #821), and `cargo xtask lsp parity --corpus faults` holds them equal. No object check in `opentide-tide` or `opentide-analysis`.
- A change opentide users see gets an entry in `CHANGELOG.md`, beside `crates/CHANGELOG.md`. After a change to `bindings/python/src/lib.rs`, update `src/opentide/_native/__init__.pyi`; after a change to a model of `opentide-schema`, run `cargo xtask stubs` (the generated `src/opentide/_native/models.pyi`).
- **One value type per job (#1967).** `opentide_core::json::Json` holds every value opentide owns or writes: documents, payloads, envelopes, a configuration as the model sees it, a tenant's `setup`. `serde_json::Value` only reads JSON someone else wrote (a tenant's answer, a cassette, LSP params, a state file), inside the code that parses it, and the facade's `Document`; never a stored model, never output whose key order shows. A request body is a typed `Serialize` struct, or `json!` where the receiver ignores order. `toml::Value` and `toml::Table` appear only where TOML text is read or written, deserialised straight into a typed struct or a `Json`; never an in-memory settings map, since TOML has no null and no integer past `i64`. Conversions between the three live in `opentide-core/src/json.rs`; a crate-local converter is a review finding.
- One tokio runtime per process (#1558): `opentide_connectors::runtime::shared()`, two I/O workers, started by its first user and never dropped. Never build a runtime of your own (tests aside). CPU work runs on rayon, network I/O on tokio. Async code calls blocking work through `tokio::task::spawn_blocking`. Synchronous code reaches the network with `runtime::block_on` (`sync_call` around a command, which hops to its own thread only inside an embedder's runtime). `block_on` may be called from the main thread, a rayon thread or a `spawn_blocking` thread. Never call it inside async work: there it refuses (`INSIDE_THE_RUNTIME`) rather than panic.
- **Embedded datasets are compressed, never `include_str!`d (#1743).** A catalog, vocabulary, pin file or template the binary carries is `opentide_dataset::text!("<path>")` (or a pre-parsed `value!`), written to a blob by the crate's `build.rs`; plain text in a binary is what antivirus heuristics flagged. `scripts/av/markers.py` (pytest, and the release gate) fails when `moneropool`, `sekurlsa`, `Login Data`, `Invoke-Mimikatz` or `jndi:ldap` is in plain text in any artifact. No XOR, no encryption, no packer; code is not compressed. [`opentide-dataset/AGENTS.md`](opentide-dataset/AGENTS.md).
- Object models (`opentide-schema`), vocabulary or pins (`src/opentide/data`) change the bundled Tide catalog: regenerate it in the same change with `cargo xtask codegen` (`--check` in CI).

## Lints

The workspace's lints are in the root `Cargo.toml` (`[workspace.lints]`), each allowed pedantic lint with its reason; `clippy.toml` allows `unwrap`, `expect` and `dbg!` in `#[test]` functions and `#[cfg(test)]` modules; `rustfmt.toml` writes down rustfmt's defaults.

- **One Rust, pinned.** `rust-toolchain.toml` names an exact release; CI installs that file's toolchain, so a new stable's lints cannot turn every PR red. Move to a newer release in a change of its own, as the file says: bump `channel`, then fix or allow (with a reason) what the new lints report.

- **`unsafe_code` is forbidden** in every crate, and none holds any (#1231 removed the last: the tree-sitter FFI and the browser build's libc shims). `opentide-node` (`bindings/node`) copies the table with `deny`, and writes no `unsafe`: napi-derive's registration carries `#[allow(unsafe_code)]`, which `forbid` refuses. A crate that came to need `unsafe` would copy the workspace table with `unsafe_code = "deny"`, allow it per item with a reason, and comment every `unsafe` block with `// SAFETY:` (`clippy::undocumented_unsafe_blocks`), one unsafe operation per block (`clippy::multiple_unsafe_ops_per_block`). `xtask/tests/lint_policy.rs` fails when a copy drifts or another crate leaves the workspace table; [`docs/internal/unsafe.md`](../docs/internal/unsafe.md) lists every site with its justification, and `xtask/tests/unsafe_listing.rs` fails when it misses one.
- **No `unwrap`, `expect`, `dbg!`, `todo!` or `unimplemented!` outside tests.** A panic on user input is a bug: return a diagnostic or an error. Where a value cannot fail (a regex literal, a structural invariant), the item says why: `#[expect(clippy::expect_used, reason = "...")]`. A catalog compiled in with `include_str!` is read through `opentide_core::catalog::compiled_in`, which carries that expectation once (ADR 0013). An integration test file's helpers outside `#[test]` take the same `#![expect]` at the file's top.
- **`missing_docs`** holds for `opentide` (the facade), `opentide-parse`, `opentide-kuery`, `opentide-lsp`, `opentide-wasm`, `opentide-native` and `xtask`, and for every new crate. The fifteen other crates, imported undocumented (`opentide-cql` with language-server 0.12.0), opt out at their crate root (`#![expect(missing_docs, ...)]`); remove the opt-out once a crate is documented. Inaccurate docs are worse than none.
- Prefer `#[expect(..., reason)]` to `#[allow]`: a stale expectation fails. Use `allow` only where an expectation cannot be fulfilled (clippy's glob-import lints; `dead_code` in a test module only some test binaries use up), and say so beside it.
- **Casts.** `clippy::cast_possible_truncation` is on: a narrowing `as` carries `#[expect(..., reason)]` on its function naming the bound (LSP positions are `u32`; a char is one or two UTF-16 units), or becomes `try_from`, or widens the other side.

## Tests

| Command | Runs |
| --- | --- |
| `cargo nextest run --profile fast` | Unit tests and the fast integration tests of the workspace, about 15 s warm on 4 cores; `-p <crate>` for one crate. It leaves out the stdio server tests, the deep-nesting test, the public corpora, the comparisons with outside tools (`external_*`) and the command line's E2E tests on scratch git repositories (`.config/nextest.toml`) |
| `cargo nextest run --workspace --profile ci` | Everything, no retries, JUnit at `target/nextest/ci/junit.xml` |
| `cargo test --workspace --doc` | Doctests, which nextest does not run (CI's `cargo test --workspace` does) |
| `cargo test --workspace` | Everything, without nextest |

`opentide-workspace`'s `external_difflib` compares the dry run's diff with CPython's `difflib`: it needs a Python, `.venv`'s after `uv sync --group dev` (`OPENTIDE_PYTHON` names another).

**Snapshots (insta).** `insta::assert_snapshot!` keeps the expected text in `tests/snapshots/*.snap` next to the test, committed and reviewed like code (`crates/opentide-analysis/tests/snapshots.rs`). After an intended change run the test, then `cargo insta review` (`cargo install cargo-insta --locked`) or `INSTA_UPDATE=always cargo test -p <crate> --test <name>`, and read the diff before committing. CI sets `INSTA_UPDATE=no`: a changed or missing snapshot fails and nothing is written. Never commit a `.snap.new` (gitignored). Snapshot what a contract fixes (a diagnostic's code, range and message, a renderer's output), not whole structs. A behaviour change does not need a snapshot: unit and end-to-end tests hold behaviour, and snapshots hold only what the exact output is the product of (the CLI's `--json` documents, the files it writes, exit codes and a small rendering set: `tests/golden/README.md`).

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

Parser, catalog, and corpus edits can flip an oracle verdict. `bash scripts/engine/ci-oracle.sh` runs the Kusto.Language and Splunk oracles and skips a reference you do not have (`scripts/engine/oracles/README.md`). The engine's CI jobs (`ci.yml`) set `RUSTFLAGS=-Dwarnings`. Code under `cfg(target_arch = "wasm32")` or `cfg(target_os = "wasi")` is linted only for that target: `bash scripts/engine/build-wasm.sh clippy` (CI's `engine-lint` job, when `wasm` runs) runs clippy for `opentide-wasm` on wasm32-unknown-unknown and `opentide-lsp` and the command line on wasm32-wasip1 (wasi-sdk only for the command line's `ring`). Code under `cfg(windows)` is built and tested by `nightly.yml`'s `engine-test-os` on Windows (nextest, as on Linux and macOS; the nightly only, never on a pull request) but not linted with clippy.

## Upstream docs, not downloaded skills

The Rust project, logos, rowan, wasm-bindgen, and the LSP spec publish documentation, not Agent Skills. Use those docs when a skill points at them:

- Edition 2024: <https://doc.rust-lang.org/stable/edition-guide/rust-2024/>
- logos: <https://docs.rs/logos/>; rowan 0.17: <https://docs.rs/rowan/0.17/rowan/>; ungrammar: <https://docs.rs/ungrammar/>
- wasm-bindgen targets: <https://wasm-bindgen.github.io/wasm-bindgen/reference/rust-targets.html>
- LSP framing: <https://microsoft.github.io/language-server-protocol/specifications/lsp/3.17/specification/#headerPart>

Do not `npx skills add` a generic Rust, parser, or WASM skill into this repo. The packs on skills.sh describe async services, snapshot tests, `wasm-pack`, or a multi-hundred-language parser cache. None of them match this engine. Apollo's `rust-best-practices` handbook is the closest maintained Rust skill and still disagrees with this repo on snapshots and async.
