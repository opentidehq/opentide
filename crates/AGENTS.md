# AGENTS.md — OpenTide language server

Instructions for coding agents in **this** repository (`OpenTideHQ/language-server`). Detection-authoring skills live in `OpenTideHQ/skills` and are not an engine.

Before editing, read the one skill that matches the change. Skills follow the [Agent Skills specification](https://agentskills.io/specification).

| Change | Read |
| --- | --- |
| Any `crates/**/*.rs`, `Cargo.toml`, `Cargo.lock` | `skills/rust-engine/SKILL.md` |
| `grammars/`, `crates/opentide-syntax`, `highlights/queries/` | `skills/tree-sitter/SKILL.md` |
| `crates/opentide-lsp`, `editors/`, stdio tests | `skills/lsp-host/SKILL.md` |
| `crates/opentide-wasm`, `packages/`, `pyproject.toml` | `skills/wasm-hosts/SKILL.md` |
| `catalogs/`, `highlights/spec.toml`, `testdata/conformance`, schema sync | `skills/catalogs/SKILL.md` |
| A new query language (S1QL, Lucene, Sigma, YARA) | `skills/add-language/SKILL.md` (then the rows above) |

## Product

Native language server for **KQL**, **SPL**, and **Tide YAML**. SQL is out of scope. Names use `opentide`, never `otide`. The client factory is `createOpentideClient`.

Engines are I/O-free. Hosts (`opentide-lsp`, the WASM crate, the TypeScript packages) own the filesystem and the editor protocol. The CLI (`analyze`, `highlight`, `generate-highlights`) prints plain JSON. Only `--stdio` and `--listen` speak JSON-RPC.

## Hard rules

- No `std::fs` in `crates/opentide-{core,highlight,syntax,kql,spl,tide,analysis}/src`. Tests may read the repo.
- Do not rename a HighlightSpec capture. Adding one is a minor (`highlights/spec.toml` `[meta].version`).
- Do not validate CrowdStrike. `configurations.crowdstrike.*` stays unsupported.
- Control commands (`.show`, `.create`) parse so the engine can emit `kql_control_command_unsupported`. They are not valid detections.
- Highlight tokenizes **authored** SPL. An implicit leading `| search` is not a source rewrite.
- OpenTide LSP owns Tide diagnostics. Editor samples keep yamlls off `objects/**`.
- There is no `opentide-sql` crate, no `.sql` language id, and no stub SQL highlighter.
- Do not hand-edit `grammars/**/src/parser.c`, `grammar.json`, or `node-types.json`. Regenerate with `tree-sitter-cli` **0.25.10**.
- Do not commit a rewritten `Cargo.lock`. Resolution prunes entries the lock keeps on purpose. Restore the committed lock if Cargo rewrites it.
- Configuration TOML (`#64`) is post-v1. No tree-sitter TOML grammar, no HighlightSpec captures, no hand-written JSON Schema. It waits on `opentide#374`.
- Pydantic in the pinned `opentide` package remains CLI authority for Tide objects. The LSP matches `{code, field_path, severity}` and adds ranges.

## Verify

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
bash scripts/check-io-free.sh
bash scripts/check-names.sh
bash scripts/validate-skills.sh
cargo test --workspace
cargo run -p opentide-lsp -- generate-highlights --check
```

Grammar edits also need `bash scripts/check-grammars.sh` from the repository root (CLI 0.25.10). CI sets `RUSTFLAGS=-Dwarnings`.

## Upstream docs, not downloaded skills

The Rust project, tree-sitter, wasm-bindgen, and the LSP spec publish documentation, not Agent Skills. Use those docs when a skill points at them:

- Edition 2024: <https://doc.rust-lang.org/stable/edition-guide/rust-2024/>
- tree-sitter 0.25.10: <https://docs.rs/tree-sitter/0.25.10/tree_sitter/>
- wasm-bindgen targets: <https://wasm-bindgen.github.io/wasm-bindgen/reference/rust-targets.html>
- LSP framing: <https://microsoft.github.io/language-server-protocol/specifications/lsp/3.17/specification/#headerPart>

Do not `npx skills add` a generic Rust, tree-sitter, or WASM skill into this repo. The packs on skills.sh describe async services, snapshot tests, `wasm-pack`, or a multi-hundred-language parser cache. None of them match this engine. Apollo's `rust-best-practices` handbook is the closest maintained Rust skill and still disagrees with this repo on snapshots and async.
