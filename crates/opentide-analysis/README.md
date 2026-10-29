# opentide-analysis

The public entry point of the [opentide language server](https://github.com/opentidehq/language-server) engine: KQL, SPL, ES|QL, EQL, Kibana KQL, Lucene, and Tide YAML objects, analyzed without I/O.

```rust
use opentide_analysis::{analyze, AnalyzeRequest, LanguageId, MemoryWorkspace};

let workspace = MemoryWorkspace { files: vec![] };
let response = analyze(
    &workspace,
    AnalyzeRequest {
        uri: "query.kql".into(),
        language: LanguageId::Kql,
        text: "SecurityEvent | take 10".into(),
    },
);
for diagnostic in response.diagnostics {
    println!("{}: {}", diagnostic.code, diagnostic.message);
}
```

The host supplies files through `WorkspaceHost`; this crate never touches the filesystem. `highlight`, `semantic_tokens`, `hover`, `completions`, and `signature_help` take the same inputs, and every type they use is re-exported here, so this is the only engine crate a host needs. The [`opentide-lsp`](https://crates.io/crates/opentide-lsp) server, the browser build, and the `opentide` Python package build on it.

The other `opentide-*` crates are its components. Every engine crate shares one version; see the [changelog](https://github.com/opentidehq/language-server/blob/main/CHANGELOG.md).
