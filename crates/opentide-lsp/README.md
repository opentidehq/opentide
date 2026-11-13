# opentide language server

Internal to opentide, with no stability promise: depend on [`opentide`](https://docs.rs/opentide), the opentide Rust SDK, instead (its `lsp` feature: `opentide::lsp`).

Native language server for **KQL**, **SPL**, **ES|QL**, **EQL**, **Kibana KQL** (`kuery`), **Lucene**, **Falco** rule conditions, the **CrowdStrike Query Language** (CQL), and **Tide YAML** objects.

v1 languages: KQL + SPL + Tide YAML. The Elastic languages cover `configurations.elastic` rules, and Falco covers `configurations.sysdig` (Sysdig Secure and Falco), checked as libsinsp and Falco's rule loader check it ([docs/engine/FALCO.md](../../docs/engine/FALCO.md)). CQL covers `configurations.crowdstrike` (Falcon LogScale and Next-Gen SIEM), checked against CrowdStrike's published grammar and function reference ([docs/engine/CQL.md](../../docs/engine/CQL.md)). SQL is out of scope. Names use `opentide`, never `otide`.

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

Each opentide [GitHub Release](https://github.com/opentidehq/opentide/releases) (tagged `vX.Y.Z` since the release train; the engine's own `engine-vX.Y.Z` releases came before it, and releases up to 0.12.0 are [language-server's](https://github.com/opentidehq/language-server/releases)) also carries a prebuilt binary per target (`opentide-lsp-vX.Y.Z-<target>`, glibc Linux, macOS and Windows; no musl build), the browser WASM build, and the highlights zip. `opentide-installer.sh` and `opentide-installer.ps1` on the same release install it with the `opentide` command line. The `opentide` Python package, built from the same repository, compiles the engine in and serves it as `opentide lsp start`.

## Releases

Versions follow [Semantic Versioning](https://semver.org/). Every crate shares the workspace version, which is opentide's product version: the wheel, the crates, the npm packages and the binaries carry one version, and one tag releases them all. The procedure is [`.agents/skills/release-management/SKILL.md`](../../.agents/skills/release-management/SKILL.md): `python3 scripts/engine/release.py bump X.Y.Z` (workspace version, internal pins, `Cargo.lock`) in the release's pull request, then **Publish** (`.github/workflows/publish.yml`) on `development`. The changes are listed in opentide's [CHANGELOG.md](../../CHANGELOG.md); [crates/CHANGELOG.md](../CHANGELOG.md) holds the engine's releases before the release train.

The workflow checks the version, packages every crate, builds every target, and opens the GitHub Release, creating the tag. Then it publishes the crates to crates.io in dependency order (a resumed run, `checkout_ref=vX.Y.Z`, picks up where it stopped). Assets are never uploaded over: once a GitHub Release has them, a re-run fails, so each asset keeps the digest consumers pinned.

Every asset of a GitHub Release is listed in its `SHA256SUMS` (`scripts/engine/release.py sums`) and carries a [build provenance attestation](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations) signed by the release workflow. To check a download:

```bash
sha256sum --check --ignore-missing SHA256SUMS        # only the assets you downloaded
gh attestation verify highlights-vX.Y.Z.zip --repo opentidehq/opentide \
  --cert-identity-regex '^https://github\.com/opentidehq/opentide/\.github/workflows/publish\.yml@refs/heads/development$'
```

`--repo` alone accepts an attestation that any workflow of the repository signed, from any branch; `--cert-identity-regex` requires the release workflow, run from `development`. The engine's own releases (`engine-vX.Y.Z`) verify with `engine-release\.yml@refs/(heads/development|tags/engine-vX\.Y\.Z)`; language-server's (0.12.0 and earlier) with `--repo opentidehq/language-server` and its `release.yml` on `main` or `vX.Y.Z`.

The workflow runs both on the published assets before it publishes the crates.

crates.io publishing uses [trusted publishing](https://crates.io/docs/trusted-publishing): a crate's first version publishes with the `CARGO_REGISTRY_TOKEN` secret (scopes `publish-new`, `publish-update`, `trusted-publishing`), which also registers `publish.yml` as each crate's trusted publisher; later releases log in with the workflow's OIDC identity.

The crates embed catalogs and grammars from the repository root; `scripts/engine/release.py vendor` copies them into each crate first, and CI packages every crate (nightly, on every push, and on a pull request that changes the Cargo manifests or carries the `full-ci` label) so a missing file fails there.

## Quick start

```bash
# Development (never use `npx convex deploy` here — this is not a Convex app)
cargo test --workspace
cargo run -p opentide-lsp -- analyze crates/testdata/workspaces/tide_corpus/objects/rules/rule-0001-sentinel-kql.yaml
cargo run -p opentide-lsp -- highlight crates/testdata/corpus/kql/take_operator__valid.kql --html > /tmp/kql.html
cargo run -p opentide-lsp -- --stdio   # editor protocol
```

The **CLI never speaks JSON-RPC**. `--stdio` / `--listen` is the editor protocol. `analyze` / `highlight` print plain JSON.

## Command line

| Command | Does |
| --- | --- |
| `opentide-lsp --stdio` | Serve LSP on stdin and stdout. Exits `0` after `shutdown` then `exit`, `1` when the client exits or closes the stream without `shutdown` |
| `opentide-lsp --listen <addr>` | Serve LSP to one TCP client (`127.0.0.1:2087`); says where it listens on stderr. Not in the WASI build |
| `opentide-lsp --version` (`-V`) | Print `opentide-lsp <version>`. With `--json`, print what `initialize` reports in `capabilities.experimental.opentide` ([EDITORS.md](../../docs/engine/EDITORS.md#structure-providers)), without starting a session |
| `opentide-lsp analyze <file> [--language <id>] [--platform <key>]` | Print the file's diagnostics as a JSON array. The language comes from the extension (`.yaml` and `.yml` are Tide YAML) unless `--language` names it. `--platform` is the `configurations` key a query file is for: `carbon_black_cloud` checks Lucene in the Carbon Black dialect, `defender_for_endpoint` KQL against the Defender schema. A Tide file under an `objects/` folder is analysed with its workspace: the other object files, the catalog in `.opentide/lsp/catalogs/generated/` (else the bundled one) and the Elastic tenants' `setup.version`. A query file is analysed on its own |
| `opentide-lsp highlight <file> [--language <id>] [--html]` | Print the file's highlight tokens as JSON, or with `--html` a page that shows them |
| `opentide-lsp generate-highlights [--check]` | Rewrite `highlights/generated/` (the TextMate grammars, the Monaco and Helix maps, `package-contributions.json`) from `highlights/spec.toml`; `--check` fails when they are stale. For this repository's CI |

With none of these, it says so on stderr and exits `2`. `opentide lsp start`, in the `opentide` Python package, runs the same server with the catalog, configuration checks and schemas opentide generates for the workspace ([EDITORS.md](../../docs/engine/EDITORS.md#configuration-toml)).

## Hard rules

- I/O-free engine crates (`opentide-kql`, `opentide-spl`, `opentide-esql`, `opentide-eql`, `opentide-kuery`, `opentide-lucene`, `opentide-ecs`, `opentide-tide`, `opentide-analysis`). No `std::fs`.
- HighlightSpec capture rename is a **major**.
- Never report a CQL field, saved search, lookup file or repository as unknown: they live in the tenant.
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
| `opentide-syntax` | Vendored tree-sitter KQL/SPL/ES\|QL/EQL/kuery/Lucene/Falco/CQL |
| `opentide-kql` | Catalog, HIR, Sentinel/Defender profiles, `compile_kql_query` |
| `opentide-spl` | searchbnf-informed catalog, `spl_unknown_command` |
| `opentide-esql` | ES\|QL catalog with stack-version lifecycle, `esql_*` diagnostics |
| `opentide-eql` | EQL catalog, sequence/sample/pipe rules, `eql_*` diagnostics |
| `opentide-kuery` | Kibana KQL checks, Lucene-syntax-in-kuery warnings |
| `opentide-lucene` | Lucene `query_string` checks, kuery-syntax-in-Lucene warnings |
| `opentide-falco` | Falco rule conditions (Sysdig Secure): a port of libsinsp's filter parser and compiler checks, field and event catalogs, `falco_*` diagnostics |
| `opentide-cql` | CrowdStrike Query Language (Falcon LogScale, Next-Gen SIEM): function, event and field catalogs, Next-Gen SIEM correlation-rule checks, `cql_*` diagnostics |
| `opentide-ecs` | Elastic Common Schema field catalog (completion, hover) and the ECS checks for queries on ECS indices (`ecs_type_mismatch`, near-miss `ecs_unknown_field`; never a closed list) |
| `opentide-tide` | Schemas, vocabs, UUID graph, YAML injection remap |
| `opentide-analysis` | `WorkspaceHost` orchestrator |
| `opentide-lsp` | stdio LSP + CLI |
| `opentide-wasm` | `wasm32-unknown-unknown`: the language server for a browser worker, and `highlight()` (no WASI mix-in) |

## Editors

Samples in `editors/{helix,nvim,zed}`. VS Code lives in a **different repository**.

## Agent skills

Coding agents start at [`AGENTS.md`](../AGENTS.md). Procedures for the Rust workspace, tree-sitter 0.25, the stdio host, WASM, and catalogs live in [`.agents/skills/`](../../.agents/skills/README.md). Detection-authoring skills stay in `opentidehq/skills`.

## License

[EUPL-1.2](../../LICENSE)
