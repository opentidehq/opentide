# opentide language server

Native language server for **KQL**, **SPL**, **ES|QL**, **EQL**, **Kibana KQL** (`kuery`), **Lucene**, and **Tide YAML** objects.

v1 languages: KQL + SPL + Tide YAML. The Elastic languages cover `configurations.elastic` rules. SQL is out of scope. Names use `opentide`, never `otide`.

## Product hierarchy

1. **Query languages** — standalone files and YAML-injected `query: |` / `search` blocks (KQL, SPL, and the Elastic languages selected by `type` and `language`).
2. **Tide objects** — the opentide catalogue (schema, vocabs, UUID graph, CLI-equivalent diagnostics).
3. **Hosts** consume the engine plus frozen HighlightSpec artifacts.

## Install

```bash
cargo binstall opentide-lsp         # prebuilt binary for your target (cargo-binstall)
cargo install opentide-lsp          # or build it from crates.io
opentide-lsp --version
```

Each [GitHub Release](https://github.com/opentidehq/language-server/releases) also carries a prebuilt binary per target (`opentide-lsp-<version>-<target>`), the browser WASM build, and the highlights zip. The `opentide` Python package wraps the server in its own CLI; this repository publishes no Python package.

## Releases

Versions follow [Semantic Versioning](https://semver.org/) and are listed in [CHANGELOG.md](CHANGELOG.md). Every crate shares the workspace version, and the internal crates pin each other to it. The procedure is [`skills/release/SKILL.md`](skills/release/SKILL.md):

1. In a pull request, run `python3 scripts/release.py bump X.Y.Z` (workspace version, internal pins, `Cargo.lock`) and write the `X.Y.Z` section of CHANGELOG.md; its first paragraph is the summary. `python3 scripts/release.py check vX.Y.Z` confirms they agree.
2. Merge it, then run the **Release** workflow on `main` (Actions → Release → Run workflow). Pushing a `vX.Y.Z` tag does the same.
3. Open a PR in [opentidehq/opentide](https://github.com/opentidehq/opentide) that pins `opentide-analysis` and `opentide-lsp` in `analysis/Cargo.toml` to `"=X.Y.Z"`, and merge it. opentide compiles the engine into its Python package and cannot publish while it builds from a git revision, so a release is not done until that PR is merged.

The workflow checks the version, packages every crate, builds every target, and opens the GitHub Release with the changelog notes, creating the tag. Then it publishes the crates to crates.io in dependency order (a re-run resumes where a failed one stopped).

crates.io publishing uses [trusted publishing](https://crates.io/docs/trusted-publishing): the first release publishes with the `CARGO_REGISTRY_TOKEN` secret (scopes `publish-new`, `publish-update`, `trusted-publishing`) and registers `release.yml` as each crate's trusted publisher; later releases log in with the workflow's OIDC identity. The token is then needed only to publish a crate that does not exist yet.

The crates embed catalogs and grammars from the repository root; `scripts/release.py vendor` copies them into each crate first, and CI packages every crate on each pull request so a missing file fails there.

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

`opentide-analysis` is the engine's public entry point: the server, the browser build, and the `opentide` Python package depend on it alone, and it re-exports the types its API uses. The `opentide` package also links `opentide-lsp` as a library, so `pip install opentide` serves this server as `opentide lsp start` with no second install. The other library crates are its components, published so it can be; their APIs follow the engine, not a promise of their own. Every crate shares the workspace version.

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
| `opentide-ecs` | Elastic Common Schema field catalog (completion, hover) and the ECS checks for queries on ECS indices (`ecs_type_mismatch`, near-miss `ecs_unknown_field`; never a closed list) |
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
