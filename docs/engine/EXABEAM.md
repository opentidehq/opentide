---
title: "Exabeam Query Language"
description: "How the engine checks the Exabeam Query Language (`crates/opentide-exabeam`): the reference-checker port, the Common Information Model catalogue, and the conformance results."
---

# Exabeam Query Language

The Exabeam engine (`crates/opentide-exabeam`) checks the search language of Exabeam's New-Scale Security Operations Platform (the New-Scale SIEM): the sequence queries of an Exabeam correlation rule (`configurations.exabeam.sequences[].query`, platform `exabeam-1.0`), Exabeam threat hunts (`response.procedure.searches[]` with `system: exabeam`), and raw `.exabeam` files. Exabeam's guides call the language "EQL". opentide never does, because `eql` is Elastic's Event Query Language: the language id is `exabeam`.

The contract is opentidehq/specifications [`specs/languages/exabeam-1.0.md`](https://github.com/opentidehq/specifications/blob/main/specs/languages/exabeam-1.0.md) (normative) and the platform spec [`specs/platforms/exabeam-1.0.md`](https://github.com/opentidehq/specifications/blob/main/specs/platforms/exabeam-1.0.md), with the research in RFC 0018. Exabeam publishes no grammar and no parser. The spec ships a reference checker, `scripts/exabeam_language.py`, and the block checker `validate_exabeam_block` in `scripts/engine/object_fixtures.py`; the engine is held to both.

| Layer | Source of truth | Engine |
|-------|-----------------|--------|
| Syntax, profiles, every language code | exabeam-1.0 and its reference checker | `src/check.rs`: a step-for-step port of the reference checker |
| Regular expressions (`RGX`, `RGXi`, `RGX_EXTRACT`) | RE2 | the `regex` crate's syntax parser (RE2 syntax), after RE2's own rules and refusals (below) |
| Fields, subjects, activity types, outcomes | Exabeam's Common Information Model, ExabeamLabs/CIMLibrary@e72bfa2 (Apache-2.0) | `data/catalogs/exabeam/` (`scripts/engine/sync_exabeam_catalog.py`), `src/catalog.rs` |
| Highlighting | the spec's highlight table (existing HighlightSpec captures only) | `grammars/tree-sitter-opentide-exabeam`, `highlights/queries/exabeam/highlights.scm` |
| Block constraints and advisories | exabeam-1.0 platform "Constraints", "Advisories" and `validate_exabeam_block` | `crates/opentide-tide/src/exabeam.rs` |

## The SQL-like layer

The repository's rule that "SQL is out of scope" is about a generic SQL dialect: there is no `opentide-sql` crate, no `.sql` language id and no SQL grammar. Exabeam's advanced operators (`SELECT`, `FROM`, `WHERE`, `AS`, `GROUP-BY`, `ORDER-BY`, `LIMIT`, pipes, `FOREACH`, the aggregations and `RGX_EXTRACT`) are part of a specified vendor language, exabeam-1.0's "Advanced grammar", with its own keywords (`GROUP-BY` is one word), limits and diagnostics. They are implemented as part of the `exabeam` grammar and engine, and nowhere else.

## Profiles

| Profile | Used for | Layers |
|---------|----------|--------|
| `rule` | `configurations.exabeam.sequences[].query`; `analyze_query` with `platform: exabeam` | the filter; the advanced form is `exabeam_advanced_in_rule` |
| `search` | hunts with `system: exabeam`; `.exabeam` files; `analyze_query` without a platform | the filter and the advanced operators |

## Conformance results

| Suite | Queries | Agreement | Harness |
|-------|---------|-----------|---------|
| The spec's fixtures (`crates/testdata/conformance/exabeam/{valid,invalid,highlight}/`) | 9 valid, 32 invalid (one per catalogue-free code), 3 highlight goldens | every valid query clean (the catalogue warnings included), every invalid one exactly its code, every golden token for token (the verdict parser and the tree-sitter highlighting) | `crates/opentide-exabeam/tests/conformance.rs` |
| The reference checker's recorded verdicts (`reference.json`): the fixtures above, `crates/testdata/conformance/external/exabeam/` and 255 probes (`probes.tsv`) | 331 | codes, ranges and highlight tokens identical, but for the narrowed ranges of two codes (below) | `crates/opentide-exabeam/tests/reference.rs` |
| Tree-sitter highlighting against the reference's tokens | every error-free query of `reference.json` | identical | `tests/reference.rs` |
| Queries written for opentide (`crates/testdata/conformance/external/exabeam/`) | 16 (12 rule, 4 search), each with a `.broken.` twin | 16 / 16 clean under their profile; every twin reports the code `FAULTS.toml` names (16 fault kinds) | `crates/opentide-analysis/tests/external_exabeam.rs` |
| The block checker's recorded verdicts: 51 block cases written for opentide and the spec's 8 object fixtures | 59 | every error, code and field path, identical, but for the block without `status` (below) | `crates/opentide-tide/tests/exabeam_spec.rs` |
| Grammar productions | 21 rules, one valid and one invalid fixture each | 21 / 21 | `crates/opentide-syntax/tests/corpus_gate.rs` |
| Exabeam's published correlation rules, ExabeamLabs/new-scale-content-hub (measured, not vendored: its README forbids redistribution) | 2,371 rules, one sequence each | see below | `crates/opentide-exabeam/tests/content_hub.rs` (ignored; reads a local checkout) |

### Exabeam's published rules (measured, not vendored)

`EXABEAM_CONTENT_HUB=<checkout> cargo test -p opentide-exabeam --test content_hub -- --ignored --nocapture` runs the `rule` profile over `Correlation-Rules/**/*.json` (`ruleDefinitions[0].sequencesConfig.sequences[].query`) and writes every finding for a comparison with the reference checker (`python3 scripts/exabeam_language.py --profile rule`, or its `analyze`). Measured on 2026-11-12 against the checkout of that date:

| Rules | Count | Reference checker: with an error | Engine: with an error | Engine and reference disagree |
|-------|-------|-------------------------------|---------------------|-------------------------------|
| Exabeam's own (path without `exabeam_new_scale_correlation_rule_json-2025`) | 77 | 0 | 0 | 0 |
| Sigma conversions (`exabeam_new_scale_correlation_rule_json-2025/`) | 2,294 | 76 | 75 | 3 rules, all `exabeam_regex`, each RE2 against Python's `re` (below) |

| Code | Engine | Reference |
|------|--------|-----------|
| `exabeam_function_arity` (error) | 323 | 323 |
| `exabeam_regex` (error) | 46 | 47 |
| `exabeam_parse_error` (error) | 39 | 39 |
| `exabeam_single_group` (warning) | 20 | 20 |
| `exabeam_legacy_regex` (warning) | 10 | 10 |
| `exabeam_mixed_boolean` (warning) | 4 | 4 |
| `exabeam_unknown_field` (warning) | 7,327 in 1,399 rules | — (no catalogue) |
| `exabeam_string_field_number` (warning) | 287 | — (no catalogue) |

- Every error in the Sigma conversions is a defect of the conversion: broken escaping (`\\"` closing a string early, which leaves the rest of the pattern as bare arguments), Sigma modifiers left unconverted, and Python-only regular expressions.
- The two catalogue warnings fire on Sigma conversions only, never on Exabeam's 77 own rules: the conversions keep Sysmon and Windows field names the CIM does not have (`ScriptBlockText`, `ImageLoaded`, `OriginalFileName` as `process_original_file_name`, `c-useragent`) and compare `event_code` with unquoted numbers (`event_code:7045`).
- Highlight tokens of the verdict parser equal the reference's on all 2,371 queries. The tree-sitter grammar parses all 2,296 error-free queries without an error node and gives the same tokens; on the 75 with errors, the verdict parser still recovers where the grammar has an `ERROR` node (50 of them), so only highlighting degrades there.
- No disagreement with the reference checker: two rules use `$?` (an optional end-of-text assertion), which RE2 accepts, and one escapes U+00A0 (`\ ` with a non-breaking space), which RE2 refuses (it escapes ASCII punctuation only). The reference checker now rewrites and refuses these as RE2 does, and both forms are probes in `reference.json`.

## Regular expressions

`RGX`, `RGXi` and `RGX_EXTRACT` patterns are RE2 (exabeam-1.0). The pattern is the string's value (`\"`, `\'`, `` \` `` and `\\` lose their backslash). The engine refuses, in this order:

1. a back-reference: `\1`–`\9` unless `\1`–`\7` opens an octal escape (`\12`), as in RE2, where `\0` and up to three octal digits are a character;
2. RE2's own rules where the `regex` crate's syntax differs, outside character classes only (`[a?+]` and `[(?=]` are sets of literals): look-around (`(?=`, `(?!`, `(?<=`, `(?<!`), an atomic group (`(?>`) and a possessive quantifier (`*+`, `}+`) are errors; a repetition of a repetition (`.**`, `a{2}{3}`) and a count above 1,000 are errors; `\p{…}` and `\x{…}` keep their braces; `\Q` inside a class, an ASCII class other than RE2's fourteen (`[[:foo:]]`), a capture name other than `[A-Za-z0-9_]+` or a repeated one, and groups nested deeper than 1,000 are errors; a `{` that does not open `{n}`, `{n,}` or `{n,m}`, and `]` or `}` outside a class, are literals; a backslash before any ASCII character other than a letter, digit or `_` escapes it (`\ `), but not before a non-ASCII one; `\Q…\E` quotes; `[` inside a class is a literal (no nested classes or `&&`); flags are `i`, `m`, `s` and `U`;
3. the `regex` crate's syntax parser (`regex-syntax`, already in the lock as `regex`'s parser) on the result.

The reference checker approximates RE2 with Python's `re`, refusing and rewriting the syntax the two read differently (`\Z`, `\pL`, `\z`, `\x{…}`, `\Q…\E`, `(?<n>…)`, the `U` flag, counts above 1,000, `$?`, an escaped non-ASCII character), so the two agree on every probe.

## Fields

The catalogue is Exabeam's CIM: the 1,130 typed fields of `Fields_Descriptions.md`, the platform fields the CIM table omits (`approxLogTime`, `rawLogIds`, `ingest_time`, `raw_log_time`; `time` is in the CIM), 84 subjects, 456 activity types and the outcomes `success` and `fail` (`cim.json`). Names compare without regard to case. A field is known when the catalogue has it, when it starts with `c_` (custom) or `m_` (metadata), when its first part is known (a structured field, `src_ip.country`), or when it is an `AS` name defined earlier in the query. Any other is `exabeam_unknown_field`, a warning with a near-miss suggestion: a tenant's parsers define fields too. An unquoted number on a field the CIM types as `string` is `exabeam_string_field_number` (warning; a comparison is numeric and is not reported). The time fields take a range or `null` only: an exact value, quoted or not, is `exabeam_time_exact`. On them, ten or more digits are epoch milliseconds, and datetime bounds compare as instants (`+05:00` included).

## Highlighting

`highlights/queries/exabeam/highlights.scm` uses the spec's table and only existing HighlightSpec captures. Filter operators are any case; clause keywords are recognised in any case so a mixed-case one still highlights while the engine reports `exabeam_keyword_case`, and clauses parse in any order while the engine reports `exabeam_clause_order`. Function names, values (booleans, `null`, IP addresses, `@field`) and range bounds are told apart with `#match?` predicates. Sequence queries are nested in a list, so the Tide TextMate grammar gives them no embedded region: semantic tokens colour them.

## Block constraints

`crates/opentide-tide/src/exabeam.rs` reports the platform's constraint codes from the raw YAML, so they do not wait for the Tide catalogue: `exabeam_sequences`, `exabeam_correlation`, `exabeam_threshold_function`, `exabeam_threshold_operator`, `exabeam_threshold_value`, `exabeam_group_by`, `exabeam_duration`, `exabeam_severity`, `exabeam_outcome`, `exabeam_email`, `exabeam_schedule`, `exabeam_name_length`, `exabeam_context_table_trigger` and the workspace check `exabeam_name_duplicate` (errors), and the advisories `exabeam_outcome_silent` and `exabeam_correlation_window` (warnings), each on the field path the spec's table names. An unknown key, at the root or inside a sequence, threshold, correlation, suppression, email or recurrence, is never one of these codes: the Tide catalogue reports it (`schema_validation`) at the key. A null is the key left out, at every level. `exabeam_context_table_trigger` reads the lookups from the parsed query, so a quoted ` in '…'` is not one. `exabeam_correlation_window` follows Exabeam's rule for ordered sequences: the window must be more than the sum of the sequence windows (a minute for an any-match sequence) plus a minute between sequences. The language codes of each sequence query are reported on `configurations.exabeam.sequences.<N>.query`, errors and warnings.

## Differences from the reference checkers

| Where | Reference | Engine | Why |
|-------|-----------|--------|-----|
| RE2's program-size limit (`(a{100}){100}`), `[a--b]`, a leading-zero count (`a{01}`) | as Python's `re` reads them | as the `regex` crate reads them | rare; neither is RE2's own parser |
| tree-sitter highlighting (editors only) of a Unicode space other than U+0020, a lone `AS` or `LIMIT`, a `WHERE` inside a filter, an IPv6-looking word that is not an address | — | the grammar's tokens; the verdict parser's semantic tokens are the reference's | highlighting only, never a diagnostic |
| a bad threshold or outcome value in the editor | — | `vocab_unknown` from the Tide catalogue and the `exabeam_*` code, as on Bitdefender blocks | the opentide CLI reports the `exabeam_*` code only |
| `exabeam_group_by_column`, `exabeam_group_by_select_star` ranges | from the start of the query to the end of the statement | the column, or the `*` | a usable range; the codes are the same |
| unknown fields, numbers on string fields | not reported (no catalogue) | the catalogue warnings | exabeam-1.0 "Field catalogue" |
| messages of `exabeam_unknown_function` and `exabeam_not_equal` | a generic hint | the Exabeam form of `contains`, `startswith`, `endswith`, `cidr`, `exists` and `!=` | exabeam-1.0 asks for it |
| nesting deeper than 200 groups or `NOT`s | Python's recursion limit (an exception) | `exabeam_parse_error` | the engine never overflows its stack |
| a block without `status` | the block's codes | none: the missing field is the Tide catalogue's | as on the Sysdig and Bitdefender blocks |
| unknown keys at the root or nested, legacy external ids (`unknown_field`, `external_id_in_rule`) | reported | left to the Tide catalogue | the catalogue owns closed objects |
| a sequence query's language warnings | not reported (errors only) | reported, as warnings | exabeam-1.0: "its warnings are reported" |
| `exabeam_name_duplicate`, the two advisories | not checked | checked | the spec's table; the reference leaves them to opentide |

## No oracle

Exabeam's search language is closed source: there is no parser to port or run in CI, and the only reference is a tenant's Search API (`POST /search/v2/events`, which `opentide validate query --live` calls). The specification's reference checker stands in for one, and its verdicts are recorded (`scripts/engine/sync_exabeam_conformance.py`). See `scripts/engine/oracles/README.md`.

## Open

- Whether RE2 receives a pattern's string value (`\\` is one backslash), as Exabeam's own rules assume and the engine and the spec take, or the string as written, as one example of Exabeam's regex page reads (specifications RFC 0018, unresolved question 6). Patterns written with single backslashes (`\s`, `\.`, `\(`) mean the same either way.
