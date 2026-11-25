---
title: "Adding a language"
description: "Where adding a query language to the engine is written down (the add-language skill), how raw query files and Tide injections share one engine, and why SQL is not a language."
---

# Adding a language

The steps, the rules each step meets and the definition of done are in one place, the
[`add-language`](../../.agents/skills/add-language/SKILL.md) skill: a pure-Rust parser on
`opentide-parse` ([ADR 0012](../internal/adr/0012-pure-rust-parsing.md)), catalogs
([ADR 0013](../internal/adr/0013-language-catalogs.md)), the analysis rules
([ADR 0014](../internal/adr/0014-analysis-performance.md)), and the proofs: the corpus gate, the
public rules, the vendor's parser, work counts, the throughput budgets, fuzzing and the command
line's snapshots. This page explains two contracts the skill relies on.

## Raw query documents

Raw query files (`.kql`, `.spl`, `.esql`, `.eql`, `.kuery`, `.lucene`, `.falco`, `.cql`, `.yar`, `.yara`, `.exabeam`, `.yaral`, `.yl2`) are first-class documents. They are analyzed on their own, with an empty Tide workspace, by the same engines that Tide `query:` and `search:` injections use (`configurations.sentinel.query`, `configurations.microsoft_defender.query`, `configurations.splunk.query`, and legacy `configurations.splunk.search`). Elastic queries come from `configurations.elastic.query` and `configurations.elastic.threat.query`, with the engine chosen by the block's `type` and `language` (see the injection table in `ARCHITECTURE.md`). `Session::language_for` selects the engine from a reported language id, then from the URI suffix through `LanguageId::from_extension` (each suffix above to its engine, otherwise Tide YAML). A reported id the parser does not know is ignored and the suffix is used.

`crates/opentide-analysis/tests/raw_query_composability.rs` checks that `analyze` on a standalone file and the same text inside a Tide query block return the same operator diagnostic (`kql_unknown_operator` for an injected `frobnicate`, `spl_unknown_command` for an injected unknown command). `crates/opentide-analysis/tests/elastic_corpus.rs` does the same for the four Elastic languages over the whole diagnostic set. Slow-query warnings follow the same split: `crates/opentide-analysis/tests/perf_warnings.rs` requires `kql_where_not_first` and `spl_wildcard` on both the raw file and the Tide block, with the Tide diagnostic's `field_path` set to the injected key (`configurations.sentinel.query`, `configurations.splunk.search`). Warning rules: [kql/DESIGN.md](kql/DESIGN.md), [spl/search-syntax.md](spl/search-syntax.md#wildcards), [spl/DESIGN.md](spl/DESIGN.md).

## SQL

SQL stays unsupported until a real dialect and grammar are chosen (for example T-SQL, or the SQL a specific platform documents). There is no SQL `LanguageId`, no `.sql` suffix, and no `opentide-sql` dialect. A `.sql` file is treated as Tide YAML and does not validate SQL. A stub parser or a fake SQL highlighter is not a 1.0 language.

