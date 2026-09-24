# Adding a language

KQL, SPL, and Tide YAML are the 1.0 engines. A later language (S1QL, Lucene, Sigma, YARA) follows this list. CrowdStrike stays unsupported. SQL stays out.

1. Add a variant to `LanguageId` in `crates/opentide-core`.
2. Vendor `grammars/tree-sitter-opentide-<id>/` and compile it from `crates/opentide-syntax`. CI fails if `parser.c` drifts.
3. Add corpus files under `testdata/corpus/<id>/` tagged `prod:<rule>`, and a row in `docs/LANGUAGE.md`. `crates/opentide-syntax/tests/corpus_gate.rs` must require every production.
4. Add catalogs under `catalogs/<id>/` and load them once with `OnceLock`, the way `Catalog::cached` does for KQL and SPL.
5. Add `highlights/queries/<id>/highlights.scm`. `generate-highlights --check` must pass.
6. If Tide YAML embeds the language, add a row to the injection table in `docs/ARCHITECTURE.md` and `language_for_field_path`.
7. Add cases under `testdata/conformance/external/<id>/`: unmodified public rules, and the same rules with one injected fault. The analysis test must see a diagnostic on every broken file and no parse error on the valid files.
8. Do not validate a platform whose language is unspecified. Return unsupported. Never invent a successful diagnostic.

`opentide-analysis` dispatches on `LanguageId`. New engines register there. They do not grow a second copy of hover, completion, and signature matching inside the Tide crate except for injection.
