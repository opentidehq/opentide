# Architecture

OpenTide LSP is an I/O-free Rust engine plus thin hosts.

```
editors / @opentide/lsp-client / WASM worker
                │
         opentide-lsp  (stdio JSON-RPC, CLI analyze/highlight)
                │
         opentide-analysis  (WorkspaceHost)
          /        |         \
    opentide-kql  opentide-spl  opentide-tide
          \        |         /
            opentide-syntax + opentide-highlight
                      |
               opentide-core
```

## Layers

- **Grammars** (`grammars/tree-sitter-opentide-{kql,spl}`) vendored `parser.c`. CI regenerates and fails on drift.
- **Catalogs** (`catalogs/`) compiled into the engine with `include_str!`. Workspace override path: `.opentide/lsp/catalogs/`.
- **HighlightSpec** (`highlights/spec.toml`) is frozen. Capture rename = major. Generated tmLanguage / Monaco / Helix maps are CI-checked.
- **Injection**: block-scalar indent is stripped for analysis; tokens are remapped onto YAML coordinates.

## Injection table

| Field path | Language |
| --- | --- |
| `configurations.sentinel.query` | KQL |
| `configurations.defender_for_endpoint.query` | KQL |
| `configurations.splunk.query` | SPL |
| `configurations.splunk.search` (legacy) | SPL |
| `configurations.crowdstrike.*` | unsupported (`None`) |
| `description` / `procedure.analysis` / `recommendation` / other `markdown = true` fields | Markdown (HighlightSpec `markdown.*`) |

YAML keys are captured from [`catalogs/tide/fields.toml`](../catalogs/tide/fields.toml) (pydantic-aligned). Capture rename in HighlightSpec is a **major**; adding `markdown.*` / `macro` is a minor (`0.2.0`).

## Diagnostics

Pydantic remains CLI authority. The LSP emits the same `{code, field_path, severity}` with real ranges. The engine may add **extra** query diagnostics inside `query: |`.

## Hosts

- Native: `opentide-lsp --stdio` or `--listen 127.0.0.1:2087`
- Web: `wasm32-unknown-unknown` `highlight(language_id, bytes)` — do **not** mix WASI + wasm-bindgen in one artifact
- vscode.dev: `wasm32-wasip1` of the same binary
- TypeScript: `createOpentideClient({ transport: "stdio" | "worker" | "wasi" })`

## Custom RPCs

- `opentide/analyze`
- `opentide/highlight`
- `opentide/compiledKql`
- `opentide/compiledSpl`
- `opentide/fs/read`

## Development

Use `cargo test --workspace`. Release tags are `v0.x.y`, independent of the `opentide` Python package.
