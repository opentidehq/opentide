---
name: catalogs
description: Load OpenTide catalogs and conformance corpora. Covers include_str, OnceLock, toml 0.8, HighlightSpec capture freezes, Pydantic schema sync for opentide 0.5.0, and external KQL/SPL fault twins. Use when editing catalogs/, highlights/spec.toml, testdata/conformance, or scripts/sync_opentide_schemas.py.
license: EUPL-1.2
metadata:
  author: OpenTideHQ
---

# Catalogs and conformance

Catalogs are data compiled into the binary. The engine does not read them from disk at request time. A workspace override path exists for deprecations (`.opentide/lsp/catalogs/`); the bundled files under `catalogs/` are the default.

Read `references/highlight-spec.md` before touching `highlights/spec.toml` or a capture name.

## How a catalog is loaded

1. TOML (or JSON for generated Tide fields) lives in `catalogs/`.
2. The engine `include_str!`s it with a path relative to the source file (`../../../catalogs/...`).
3. A `serde::Deserialize` struct matches the file. `#[serde(default)]` on optional arrays.
4. `toml::from_str` (toml 0.8) parses it inside `OnceLock` so each profile is parsed once per process. `Catalog::cached` is the pattern in `opentide-kql` and `opentide-spl`.
5. Tests construct the catalog through that cache. They do not open the TOML themselves unless they are checking the sync script.

Adding a key to a row struct without `#[serde(default)]` rejects every existing file that omits the key. Add the field as `Option` or `#[serde(default)]`, then fill the catalogs.

Do not parse catalogs with `serde_yaml`. Do not switch catalog files to JSON unless the file is already generated JSON (`catalogs/tide/generated/fields.json`).

## KQL and SPL catalogs

| Path | Contents |
| --- | --- |
| `catalogs/kql/core/` | operators, scalar operators, functions, types, evaluate plugins, operator options |
| `catalogs/kql/sentinel/` | tables and columns |
| `catalogs/kql/defender/` | tables and columns |
| `catalogs/spl/` | commands, command options, fields, datamodels, macros |

KQL profiles are `Core`, `Sentinel`, and `Defender`. Sentinel analysis is the default for a raw `.kql` file. Defender is selected when the Tide field path contains `defender_for_endpoint`. A function that exists only in one profile must not be marked known in the other.

Signatures and operator options are copied from public docs (Microsoft Learn for KQL, Splunk Search Reference for SPL). `scripts/sync_kql_learn_signatures.py` is the generator. Do not invent a parameter the Learn page does not list. Cite the page in the catalog `citation` field when the row has one.

Unknown operators, functions, tables, and commands are diagnostics (`kql_unknown_operator`, `kql_unknown_function`, `kql_unknown_table`, `spl_unknown_command`), not grammar errors. `render` parses and warns `kql_render_not_valid`. Control commands warn `kql_control_command_unsupported`.

Slow-query warnings (`kql_where_not_first`, `kql_unscoped_search`, `spl_wildcard`, `spl_leading_not`, and the rest of `opentide_core::codes`) come from the `perf` modules. They are warnings about public query shapes, not style nits. Do not add a warning that contradicts `docs/kql/` or `docs/spl/`.

## Tide objects

`scripts/sync_opentide_schemas.py` pins `opentide==0.5.0` (`scripts/requirements-opentide.txt`) and writes `catalogs/tide/generated/`. Pydantic is the CLI authority. The LSP emits the same `{code, field_path, severity}` with ranges. `scripts/pydantic_object_issues.py` is the comparison source. Do not re-encode the object schema as hand-written Rust structs when the generated field catalog already has the answer.

Vocabularies live in `catalogs/tide/vocabs/*.vocab.toml` and load once (`OnceLock` in `vocabs.rs`). An unknown vocab value is `vocab_unknown`. Deprecated fields use the generated deprecation list (`deprecated_field`).

Injection, from `language_for_field_path`:

| Field path | Language |
| --- | --- |
| `configurations.sentinel.query` | KQL |
| `configurations.defender_for_endpoint.query` | KQL |
| `configurations.splunk.query` and legacy `configurations.splunk.search` | SPL |
| `configurations.crowdstrike.*` | unsupported |
| markdown fields | HighlightSpec `markdown.*`, not a query engine |

Block-scalar indent is stripped for analysis. Tokens are remapped onto the original YAML coordinates. Do not highlight the dedented buffer's offsets.

## Conformance

`testdata/conformance/external/<id>/` holds real public rules and a `.broken.` twin (`frobnicate` or `.show` for KQL, `notacommand` for SPL). `crates/opentide-analysis/tests/external_corpus.rs` does not require the full valid file to parse. v1 grammars still miss forms such as `summarize min =`, `between`, leading SPL macros, and `stats ... BY`. The test keeps the full rule, finds the longest prefix that parses (at most 16 lines, and the prefix must contain `|`), injects the fault on that prefix, and requires `kql_unknown_operator` or `spl_unknown_command`. The broken full file must produce at least one diagnostic. A corpus that catches the fault on fewer than 5 KQL prefixes or 2 SPL prefixes fails. Sources and licenses are `testdata/conformance/external/SOURCES.md`. Do not add a rule whose license is unclear, and do not trim a public rule down to the prefix the grammar already accepts.

`testdata/conformance/pydantic/` and `crates/opentide-analysis/tests/tide_corpus.rs` check object issues. `testdata/oracles/exceptions.toml` lists Kusto.Language disagreements. The Kusto.Language oracle is CI-only (`scripts/ci-oracle.sh`, `continue-on-error`). Do not vendor Microsoft Kusto.Language in the binary.

## Configuration TOML is not a catalog yet

Issue `#64` (children `#65`–`#68`) will vendor Pydantic JSON Schema for `.opentide/configurations/**/*.toml` after `opentide#374`. Until that pin exists:

- Do not hand-write a JSON Schema, a tree-sitter TOML grammar, or HighlightSpec captures for TOML.
- Do not validate `sharing.toml` inside `opentide-tide`.
- `Cargo.toml`, `pyproject.toml`, and `catalogs/**/*.toml` are not `opentide-config` documents.

## Checks

```bash
cargo test -p opentide-kql -p opentide-spl -p opentide-tide -p opentide-analysis
cargo run -p opentide-lsp -- generate-highlights --check
```

Schema sync, when the pin is installed: `python scripts/sync_opentide_schemas.py` and a clean `git diff` on `catalogs/tide/generated/`.
