# Changelog

Notable changes to the opentide language server, newest first. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html); before 1.0, a minor version may change diagnostics and settings.

Each version's first paragraph is its summary: the GitHub Release and [opentide.org/releases](https://opentide.org/releases/language-server/) show it above the change lists. Versions before 0.5.0 were tagged after the fact, each on the commit where that stretch of work ended. The crates still said 0.1.0 then, so a binary built from those tags reports 0.1.0, and none of them was published to crates.io.

## [Unreleased]

### Added

- `opentide-analysis` re-exports every type its functions take and return, so a host (the `opentide` Python package, an editor) depends on it alone. Its crates.io page shows a usage example, run as a doctest.
- `cargo binstall opentide-lsp` downloads the release binary for the target instead of compiling the workspace.

### Changed

- The other library crates say on crates.io that they are engine components and point to `opentide-analysis`.

## [0.5.0] - 2026-10-26

The Elastic Security release: ES|QL, EQL, Kibana KQL, and Lucene rules get the same editing support as KQL and SPL, and the server installs from crates.io with `cargo install opentide-lsp`.

### Added

- ES|QL, EQL, Kibana KQL (kuery), and Lucene grammars, with highlighting, diagnostics, hover, completion, signature help, and injection into Tide rule queries ([#88](https://github.com/opentidehq/language-server/pull/88)).
- An Elastic Common Schema field catalog for the Elastic engines.
- Conformance against Elastic's own parsers, a live Elasticsearch reference from 8.19 through 9.5, and a sweep of the public Elastic detection rules in CI.
- Every crate is published to crates.io. Each GitHub Release carries a binary per target, named for it.

### Changed

- The workspace version is the release version; the internal crates are pinned to it.
- This repository no longer builds a Python wheel. The Python bindings, and the `opentide` command that wraps the server, live in [opentidehq/opentide](https://github.com/opentidehq/opentide).

## [0.4.0] - 2026-10-23

Differential oracles: every corpus query is checked against Microsoft's Kusto.Language and Splunk's own parser, and the grammar and catalog gaps they found are closed.

### Added

- Kusto.Language 12.4.1 and Splunk 10.6.1 oracles compared with opentide-lsp on every corpus query, external rule, Tide rule query, and catalog name; `testdata/oracles/exceptions.toml` records each known disagreement ([#87](https://github.com/opentidehq/language-server/pull/87)).
- KQL: named aggregates, multi-value lists, `between`, dynamic literals, member and index access, `mv-expand`, `mv-apply`, `make-series`, `evaluate`, `datatable`, operator options, tabular `let` and functions, `materialize` and `toscalar`. Every Sentinel rule in the corpus parses.
- KQL catalog: 32 functions and 17 plugins from Microsoft Learn; 15 deprecated aliases warn `kql_deprecated_function`.
- SPL: multiple aggregations, `tstats where` in search syntax, leading macros, boolean groups, and field lists; searchbnf aliases and `Risk.All_Risk`.
- A licence scan of every release artifact for oracle references.

### Changed

- Tide catalogs are generated from opentide 0.16.1 ([#75](https://github.com/opentidehq/language-server/pull/75)).
- The project is spelled opentide in lowercase, Opentide in class names ([#74](https://github.com/opentidehq/language-server/pull/74)).

### Fixed

- `evaluate` plugins are checked against the plugin catalog, and `let`-bound names are no longer flagged as unknown.
- `dedup` requires a field.

## [0.3.0] - 2026-09-29

Queries read like their vendor documentation: KQL and SPL signatures follow Microsoft Learn and the Splunk Search Reference, and slow query shapes warn.

### Added

- Warnings, with vendor citations, for slow public KQL and SPL shapes: a late `where`, unscoped `search` or `union`, wildcard tables, `join` or `summarize` before `project`, leading and mid-token wildcards, and truncating subsearches ([#61](https://github.com/opentidehq/language-server/pull/61)).
- SPL completion, hover, and signature help from Search Reference arguments ([#60](https://github.com/opentidehq/language-server/pull/60)).
- Standalone `.kql` and `.spl` files are first-class documents ([#59](https://github.com/opentidehq/language-server/pull/59)).
- Validation of Tide lists and of public KQL and SPL faults ([#53](https://github.com/opentidehq/language-server/pull/53)).
- Agent skills for the Rust, tree-sitter, and host stack ([#71](https://github.com/opentidehq/language-server/pull/71)).

### Changed

- KQL signatures and operator options follow each item's Microsoft Learn syntax, with parameter docs ([#62](https://github.com/opentidehq/language-server/pull/62)).

### Fixed

- Tide YAML keys keep one color at every nesting depth ([#58](https://github.com/opentidehq/language-server/pull/58)).

## [0.2.0] - 2026-09-24

Tide objects from the schemas: hover, completion, and highlighting come from the opentide 0.5.0 schema export, and deprecated fields warn.

### Added

- Tide fields resolved by schema family and YAML path, generated from opentide 0.5.0.
- Warnings on deprecated Tide fields, with a workspace overlay at `.opentide/lsp/catalogs/`.
- KQL Sentinel and Defender columns; SPL macros, CIM data models, and `tstats`; signature help.
- Markdown highlighting inside Tide description, analysis, and recommendation blocks.
- Folding, selection ranges, workspace symbols, code actions, inlay hints, and document highlights.
- Tag builds attach the highlights zip and native binaries to a GitHub Release.

### Fixed

- Incremental edits all apply, and closing a document clears its diagnostics.
- SPL `tstats` `as` and `where` are highlighted.

## [0.1.0] - 2026-09-16

The first working server: KQL, SPL, and Tide YAML over stdio and WASM, with the highlighting spec every editor shares.

### Added

- I/O-free KQL and SPL engines on vendored tree-sitter grammars, with catalogs from Microsoft Learn and the Splunk Search Reference.
- Tide YAML with the UUID graph and KQL and SPL injected into rule queries.
- A frozen HighlightSpec with generated editor maps, and semantic tokens on the standard LSP legend.
- Stdio and WASM hosts, and Zed, Helix, and Neovim samples.

[0.5.0]: https://github.com/opentidehq/language-server/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/opentidehq/language-server/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/opentidehq/language-server/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/opentidehq/language-server/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/opentidehq/language-server/releases/tag/v0.1.0
