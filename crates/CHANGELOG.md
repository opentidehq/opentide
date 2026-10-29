# Changelog

Notable changes to the opentide language server, newest first. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html); before 1.0, a minor version may change diagnostics and settings.

Each version's first paragraph is its summary: the GitHub Release and [opentide.org/releases](https://opentide.org/releases/language-server/) show it above the change lists. Versions before 0.5.0 were tagged after the fact, each on the commit where that stretch of work ended. The crates still said 0.1.0 then, so a binary built from those tags reports 0.1.0, and none of them was published to crates.io.

## [Unreleased]

## [0.6.0] - 2026-10-29

The host release: opentide compiles the engine into its Python package and drives it through a new host API, each Tide object is checked against the schema revision it names with catalogs from opentide 0.18.0's own generator, and `@opentide/lsp-client` works on stdio, a browser worker, and WASI.

### Added

- `opentide_analysis::set_default_catalog` replaces the bundled Tide catalogs for the whole process whenever no workspace catalog is installed, so a host that generates them from its own models (opentide) is never behind the snapshot compiled in, including after `initialize` finds no workspace catalog, and `opentide_lsp::use_host_catalogs()` keeps `initialize` from replacing them with a committed workspace copy ([opentide#677](https://github.com/opentidehq/opentide/issues/677)).
- `opentide_analysis::bundled_catalog()` returns the Tide catalogs compiled into the engine, as their files hold them, so a host can tell whether the engine it bundles matches its own models ([#99](https://github.com/opentidehq/language-server/issues/99)). opentide's CI fails when it does not.
- Each Tide object is checked against the schema revision its `metadata.schema` names ([#98](https://github.com/opentidehq/language-server/issues/98)). The field catalog has rows per revision (`rule::1.0`, `rule::1.1`); required fields come from it rather than three checks hard-coded for `rule::1.0`, so a `rule::1.1` without `description` is reported; and a key the object's revision does not define is a `schema_validation` error where it is (`field 'metadata.reviewed' is not defined in rule::1.0`), except the legacy spellings opentide accepts (a splunk block's `search`). Catalogs keyed by family, from an older `opentide generate schemas`, still load. Every field with an enum in the catalog is checked (`vocab_unknown`), not only a hand-picked few: `response.alert_severity`, `objective.type`, `objective.composition.strategy` and the signals' fields were not.
- `recommended_field_missing` (warning): a field the templates ask for and opentide validate does not require (a rule's `configurations` and `response`) is missing. The catalog's `required` follows what validation requires, and such fields are `recommended`.
- `opentide-analysis` re-exports every type its functions take and return, so a host (the `opentide` Python package, an editor) depends on it alone. Its crates.io page shows a usage example, run as a doctest.
- `cargo binstall opentide-lsp` downloads the release binary for the target instead of compiling the workspace.
- A host API on `opentide-analysis` for the `opentide` Python package ([opentide#332](https://github.com/opentidehq/opentide/issues/332), [#16](https://github.com/opentidehq/language-server/issues/16)): `analyze_queries` reports every query a Tide object carries, with its language, YAML path, place and diagnostics, including queries with no finding; `analyze_query` checks one query with its platform's profile (Defender KQL, Carbon Black Lucene, an ES|QL stack); `install_catalog` replaces the bundled Tide field and deprecation catalogs with a workspace's; `analyze_with_index` reuses one workspace index across files; `VERSION`.
- `opentide_core::codes::ALL` lists every diagnostic code, and `codes::describe` gives each one a sentence, for hosts that explain a code (`opentide explain`).
- `opentide-lsp` is also a library (`opentide_lsp::run_stdio`), so a host can serve the protocol from its own process.
- The server and `opentide-lsp analyze` read the workspace field catalog `.opentide/lsp/catalogs/generated/fields.json`, which `opentide generate schemas` writes, as well as `deprecations.json`. Hover, completion and vocabulary checks then follow the workspace's schemas, custom vocabulary included. A catalog that does not parse is reported on stderr, and the bundled one is used.

### Fixed

- `pydantic_object_issues.py` validates each object with its revision's model, not the family's first one.
- A rule's `severity: High` was reported as `vocab_unknown` when the workspace had no generated catalog: the bundled Tide catalogs came from opentide 0.16.1, which checked a rule's severity against the threat severity scale. They are generated from opentide 0.18.0 now, where it takes `alert_severity` values, and hover shows the field descriptions 0.18.0 added.
- A diagnostic inside a block-scalar query (`query: |`) after a non-ASCII character (`é`, `🔥`, an accented comment) pointed too far right, and could spill onto the next line: the injection map counted characters where it is indexed by bytes. Semantic tokens and hover inside the query moved the same way.
- An injected query's span starts at its text, not at the indentation of its first line.
- The shape check reads YAML as opentide does: a `<<` merge key fills the fields it merges instead of being an unknown key; a key that is not a string (`1: x`) is not a field; a value outside its enum in the second item of a list is reported on that item, and each bad item once; an unknown key that is quoted, non-ASCII or in a flow mapping is placed on its key, or on the nearest key above it, never at the top of the file.
- A quoted query key (`"query": |`, `'sentinel':`) is still a query: it was left unchecked.
- A KQL query may start with `search` or `find` (`search "mimikatz"`, `search in (SecurityEvent) "x"`, `find in (T) where ...`): it was a `kql_parse_error`, and only `T | search ...` parsed.
- A block-scalar query with an indentation indicator (`query: |2`) whose later line is indented less than the first and holds a multi-byte character no longer panics.
- `scripts/sync_opentide_schemas.py --check` reports a reference schema opentide no longer registers, which writing removes.
- `rootUri` and document URIs are percent-decoded, and a Windows drive (`file:///c%3A/...`) becomes `c:/...`, so a workspace whose path has a space or a drive letter finds its objects and catalogs. Locations the server returns are percent-encoded.
- `opentide-lsp analyze` on a `.kql`, `.spl`, `.esql`, `.eql`, `.kuery` or `.lucene` file no longer reads the directories around it. Outside a workspace it walked the file's grandparent directory, so one YAML file there that was not UTF-8 failed the command.
- One unreadable workspace file (not UTF-8, no permission) no longer drops the whole object index. The stdio server reported every reference to another object as `invalid_ref`, and `analyze` on a Tide object failed. Now that file is left out, and the rest of the workspace still resolves.

### Changed

- The other library crates say on crates.io that they are engine components and point to `opentide-analysis`.
- The workspace deprecation overlay is process-wide instead of per thread, so a host that analyzes on several threads sees the one it installed.
- The bundled Tide catalogs are generated by opentide's own generator: `scripts/sync_opentide_schemas.py` runs `opentide.generation.lsp_catalog`, which `opentide generate schemas` also uses, instead of a copy of it ([#100](https://github.com/opentidehq/language-server/issues/100)). `--check` says whether the committed catalogs match, and a daily `opentide canary` job runs it against opentide's `development` branch, then the test suite against the catalogs it generates, without blocking. The router schema points each revision at its own schema (`rule::1.1` named `rule.1.0`).
- `@opentide/lsp-client` works on all three transports ([#14](https://github.com/opentidehq/language-server/issues/14)):
  - `stdio` keeps one `opentide-lsp --stdio` running and calls `opentide/analyze` and `opentide/highlight` over JSON-RPC;
  - `worker` calls the `opentide-wasm` module you load with `@opentide/lsp-worker`;
  - `wasi` runs the `wasm32-wasip1` CLI under `node:wasi`.

  Before, `analyze` always returned no diagnostics, `wasi` did nothing, and `legend()` was a hard-coded list that lacked `markdown.*` and `macro`. A transport that cannot answer now rejects, as does an unknown language id. The `worker` transport takes `module` instead of reading a global, and `wasi` takes the binary as `wasi`.

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

[0.6.0]: https://github.com/opentidehq/language-server/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/opentidehq/language-server/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/opentidehq/language-server/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/opentidehq/language-server/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/opentidehq/language-server/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/opentidehq/language-server/releases/tag/v0.1.0
