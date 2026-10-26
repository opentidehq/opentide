# opentide language server

Native language server for **KQL**, **SPL**, **ES|QL**, **EQL**, **Kibana KQL** (`kuery`), **Lucene**, and **Tide YAML** objects.

v1 languages: KQL + SPL + Tide YAML. The Elastic languages cover `configurations.elastic` rules. SQL is out of scope. Names use `opentide`, never `otide`.

## Product hierarchy

1. **Query languages** — standalone files and YAML-injected `query: |` / `search` blocks (KQL, SPL, and the Elastic languages selected by `type` and `language`).
2. **Tide objects** — DetectionOps product (schema, vocabs, UUID graph, CLI-equivalent diagnostics).
3. **Hosts** consume the engine plus frozen HighlightSpec artifacts.

## Install

```bash
cargo install opentide-lsp          # from crates.io
opentide-lsp --version
```

Each [GitHub Release](https://github.com/opentidehq/language-server/releases) also carries a prebuilt binary per target (`opentide-lsp-<version>-<target>`), the browser WASM build, and the highlights zip. The `opentide` Python package wraps the server in its own CLI; this repository publishes no Python package.

## Releases

Versions follow [Semantic Versioning](https://semver.org/) and are listed in [CHANGELOG.md](CHANGELOG.md). Every crate shares the workspace version, and the internal crates pin each other to it. To cut a release:

```bash
python3 scripts/release.py bump 0.6.0     # workspace version, internal pins, Cargo.lock
# write the 0.6.0 section of CHANGELOG.md; its first paragraph is the summary
python3 scripts/release.py check v0.6.0
git commit -am "chore: release 0.6.0" && git tag v0.6.0 && git push origin main v0.6.0
```

The tag runs `.github/workflows/release.yml`: it checks the version, builds every target, opens the GitHub Release with the changelog notes, then publishes the crates to crates.io (`CARGO_REGISTRY_TOKEN`). The crates embed catalogs and grammars from the repository root; `scripts/release.py vendor` copies them into each crate first, and CI packages every crate on each pull request so a missing file fails there.

## Quick start

```bash
# Development (never use `npx convex deploy` here — this is not a Convex app)
cargo test --workspace
cargo run -p opentide-lsp -- analyze testdata/workspaces/tide_corpus/objects/rules/rule-0001-sentinel-kql.yaml
cargo run -p opentide-lsp -- highlight testdata/corpus/kql/take_operator__valid.kql --html > /tmp/kql.html
cargo run -p opentide-lsp -- --stdio   # editor protocol
```

The **CLI never speaks JSON-RPC**. `--stdio` / `--listen` is the editor protocol. `analyze` / `highlight` print plain JSON.

## Hard rules

- I/O-free engine crates (`opentide-kql`, `opentide-spl`, `opentide-esql`, `opentide-eql`, `opentide-kuery`, `opentide-lucene`, `opentide-ecs`, `opentide-tide`, `opentide-analysis`). No `std::fs`.
- HighlightSpec capture rename is a **major**.
- Never fake CrowdStrike validation.
- Control commands (`.show` / `.create`) → `kql_control_command_unsupported`.
- Highlight tokenizes **authored** SPL (implicit `| search` is semantic, not a rewrite).
- opentide LSP owns Tide diagnostics — disable yamlls on `objects/**`.
- Client factory is `createOpentideClient`, not `createOtideClient`.

## Crates

| Crate | Role |
| --- | --- |
| `opentide-core` | Shared types, diagnostic codes |
| `opentide-highlight` | Frozen HighlightSpec, semantic tokens, tm/monaco/helix maps |
| `opentide-syntax` | Vendored tree-sitter KQL/SPL/ES\|QL/EQL/kuery/Lucene |
| `opentide-kql` | Catalog, HIR, Sentinel/Defender profiles, `compile_kql_query` |
| `opentide-spl` | searchbnf-informed catalog, `spl_unknown_command` |
| `opentide-esql` | ES\|QL catalog with stack-version lifecycle, `esql_*` diagnostics |
| `opentide-eql` | EQL catalog, sequence/sample/pipe rules, `eql_*` diagnostics |
| `opentide-kuery` | Kibana KQL checks, Lucene-syntax-in-kuery warnings |
| `opentide-lucene` | Lucene `query_string` checks, kuery-syntax-in-Lucene warnings |
| `opentide-ecs` | Elastic Common Schema field catalog (completion, hover; never a closed list) |
| `opentide-tide` | Schemas, vocabs, UUID graph, YAML injection remap |
| `opentide-analysis` | `WorkspaceHost` orchestrator |
| `opentide-lsp` | stdio LSP + CLI |
| `opentide-wasm` | `wasm32-unknown-unknown` `highlight()` (no WASI mix-in) |

## Editors

Samples in `editors/{helix,nvim,zed}`. VS Code lives in a **different repository**.

## Agent skills

Coding agents start at [`AGENTS.md`](AGENTS.md). Procedures for the Rust workspace, tree-sitter 0.25, the stdio host, WASM, and catalogs live in [`skills/`](skills/README.md). Detection-authoring skills stay in `opentidehq/skills`.

## License

[EUPL-1.2](LICENSE)
