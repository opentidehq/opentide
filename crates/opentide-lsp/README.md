# OpenTide language server

Native language server for **KQL**, **SPL**, and **Tide YAML** objects.

v1 languages: KQL + SPL + Tide YAML. SQL is out of scope. Names use `opentide`, never `otide`.

## Product hierarchy

1. **KQL and SPL** — standalone files and YAML-injected `query: |` / `search` blocks.
2. **Tide objects** — DetectionOps product (schema, vocabs, UUID graph, CLI-equivalent diagnostics).
3. **Hosts** consume the engine plus frozen HighlightSpec artifacts.

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

- I/O-free engine crates (`opentide-kql`, `opentide-spl`, `opentide-tide`, `opentide-analysis`). No `std::fs`.
- HighlightSpec capture rename is a **major**.
- Never fake CrowdStrike validation.
- Control commands (`.show` / `.create`) → `kql_control_command_unsupported`.
- Highlight tokenizes **authored** SPL (implicit `| search` is semantic, not a rewrite).
- OpenTide LSP owns Tide diagnostics — disable yamlls on `objects/**`.
- Client factory is `createOpentideClient`, not `createOtideClient`.

## Crates

| Crate | Role |
| --- | --- |
| `opentide-core` | Shared types, diagnostic codes |
| `opentide-highlight` | Frozen HighlightSpec, semantic tokens, tm/monaco/helix maps |
| `opentide-syntax` | Vendored tree-sitter KQL/SPL |
| `opentide-kql` | Catalog, HIR, Sentinel/Defender profiles, `compile_kql_query` |
| `opentide-spl` | searchbnf-informed catalog, `spl_unknown_command` |
| `opentide-tide` | Schemas, vocabs, UUID graph, YAML injection remap |
| `opentide-analysis` | `WorkspaceHost` orchestrator |
| `opentide-lsp` | stdio LSP + CLI |
| `opentide-wasm` | `wasm32-unknown-unknown` `highlight()` (no WASI mix-in) |

## Editors

Samples in `editors/{helix,nvim,zed}`. VS Code lives in a **different repository**.

## License

[EUPL-1.2](LICENSE)
