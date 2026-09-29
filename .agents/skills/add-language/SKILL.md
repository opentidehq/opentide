---
name: add-language
description: Add a query language to the OpenTide language server (S1QL, Lucene, Sigma, YARA). Follow the harness from LanguageId through a vendored tree-sitter grammar, corpus gate, OnceLock catalogs, HighlightSpec, YAML injection, and external fault twins. CrowdStrike and SQL stay unsupported. Use when creating a new engine crate or grammar.
license: EUPL-1.2
metadata:
  author: OpenTideHQ
---

# Add a language

KQL, SPL, and Tide YAML are the 1.0 engines. A later language follows this list. Authoring guidance for detections lives in `OpenTideHQ/skills` (`kusto-query-language`, `splunk-spl-processing`, and the platform skills). Those skills are not an engine. Implementation skills in this repo are `rust-engine`, `tree-sitter`, `catalogs`, `lsp-host`, and `wasm-hosts`. Read them before the matching step.

CrowdStrike stays unsupported until its language is specified. SQL stays unsupported until a real dialect and grammar are chosen. A stub parser or a fake highlighter is not a language.

## Done when

- `LanguageId` parses the public name and rejects `sql`.
- `scripts/check-names.sh` still passes (`opentide`, never `otide`; no `opentide-sql`).
- The grammar coverage gate names the productions, and `parser.c` matches `tree-sitter-cli` 0.25.10.
- Catalogs load once per process through `OnceLock` and `include_str!`. No `std::fs` in the new engine's `src/`.
- `generate-highlights --check` passes, and capture names are an append-only change to HighlightSpec.
- `testdata/conformance/external/<id>/` contains real public rules and a `.broken.` twin with one injected fault. The full valid file may still parse-error where the grammar does not cover the rule yet. The harness keeps that file, takes the longest prefix that parses, and requires the injected fault on that prefix to diagnose. The broken full file must produce at least one diagnostic. Copy `crates/opentide-analysis/tests/external_corpus.rs`.
- Unsupported platforms still produce no fake validation.
- `cargo clippy --workspace --all-targets -- -D warnings` is clean.

## Steps

1. Add a variant to `LanguageId` in `crates/opentide-core` (`as_str`, `parse`, `Display`, serde rename). Wire name is the public id (`kql`, `spl`, `opentide-yaml`), not a crate path.
2. Add diagnostic codes to `opentide_core::codes`. Unknown constructs get a stable code, not a free-form message.
3. Vendor `grammars/tree-sitter-opentide-<id>/` and compile `parser.c` from `crates/opentide-syntax/build.rs`. Follow `skills/tree-sitter/SKILL.md`. CI fails if `parser.c` drifts.
4. Add the C symbol to the `unsafe extern` block and a `language()` arm. Use `Language::from_raw` on `*const TSLanguage`. Do not `.collect()` a `QueryCursor`.
5. Add corpus files under `testdata/corpus/<id>/` tagged `prod:<rule>`, a row in `docs/LANGUAGE.md`, and the required list in `crates/opentide-syntax/tests/corpus_gate.rs`.
6. Add `catalogs/<id>/` and a `Catalog::cached`-style `OnceLock`. Follow `skills/catalogs/SKILL.md`.
7. Add `highlights/queries/<id>/highlights.scm`. Specific patterns come before `(identifier) @variable`. New captures are appended to `highlights/spec.toml` `legend`. Run `generate-highlights`.
8. Register the engine in `opentide-analysis` on `LanguageId`. Hover, completion, and signature help dispatch here. Do not copy a second implementation into `opentide-tide` except the injection remap.
9. If Tide YAML embeds the language, add a row to the injection table in `docs/ARCHITECTURE.md` and to `language_for_field_path`. Remap tokens onto YAML coordinates after stripping block-scalar indent.
10. Add `testdata/conformance/external/<id>/`: unmodified public rules, plus `<name>.broken.<ext>` with one injected fault. Record the source and license in `SOURCES.md`. Follow `external_corpus.rs`: do not delete a public rule because the full text parse-errors; assert the fault on the longest prefix the grammar accepts, and assert the broken full file emits some diagnostic.
11. Extend `crates/opentide-lsp` only for host behaviour (language id from the URI suffix, e2e frame). The CLI `analyze` / `highlight` path must keep printing plain JSON.
12. WASM: `highlight(language_id, bytes)` already goes through `LanguageId::parse` and `opentide_analysis::highlight`. Do not add a wasm-bindgen export per language, and do not link `opentide-wasm` into a WASI build.

## Dispatch

`Session::language_for` selects the engine from a reported language id, then from the URI suffix. A reported id the parser does not know is ignored and the suffix is used. Raw `.kql` and `.spl` files are first-class documents with an empty Tide workspace. `crates/opentide-analysis/tests/raw_query_composability.rs` is the pattern: the same diagnostic fires for a standalone file and for the same text injected into a Tide query block.

## Out of scope

- Rewriting the server onto `tower-lsp` or `lsp-types`.
- Shipping Kusto.Language or a Splunk SDK in the binary. Oracles stay in CI.
- Validating a platform whose language is unspecified. Return unsupported.
