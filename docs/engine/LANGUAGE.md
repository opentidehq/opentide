# Languages

SQL is out of scope. There is no `opentide-sql`.

## KQL

| id | grammar rule | fixture ids | capture |
| --- | --- | --- | --- |
| kql.let | `let_statement` | `let_statement__valid`, `let_statement__invalid` | `keyword` |
| kql.where | `where_operator` | `where_operator__valid` | `keyword` |
| kql.project | `project_operator` | `project_operator__valid` | `keyword` |
| kql.project-away | `project_away_operator` | `project_away_operator__valid` | `keyword` |
| kql.project-rename | `project_rename_operator` | `project_rename_operator__valid` | `keyword` |
| kql.extend | `extend_operator` | `extend_operator__valid` | `keyword` |
| kql.summarize | `summarize_operator` | `summarize_operator__valid` | `keyword` |
| kql.join | `join_operator` | `join_operator__valid` | `keyword` |
| kql.union | `union_operator` | `union_operator__valid` | `keyword` |
| kql.parse | `parse_operator` | `parse_operator__valid` | `keyword` |
| kql.lookup | `lookup_operator` | `lookup_operator__valid` | `keyword` |
| kql.take | `take_operator` | `take_operator__valid` | `keyword` |
| kql.limit | `limit_operator` | `limit_operator__valid` | `keyword` |
| kql.sort | `sort_operator` | `sort_operator__valid` | `keyword` |
| kql.distinct | `distinct_operator` | `distinct_operator__valid` | `keyword` |
| kql.render | `render_operator` | `render_operator__valid` | `keyword` (warning `kql_render_not_valid`) |
| kql.control | `control_command` | `control_command__valid` | `error` (`kql_control_command_unsupported`) |
| kql.pipe | `"\|"` | `take_operator__valid` | `operator.pipe` |
| kql.function | `function_call` | `function_call__valid` | `function` |
| kql.string | `string` | `string__valid` | `string` |
| kql.number | `number` | `number__valid` | `number` |
| kql.comment | `comment` | `comment__valid` | `comment` |
| kql.function-definition | `function_definition` | `function_definition__valid` | `variable` (parameters), `type` |
| kql.datatable | `datatable_expression` | `datatable_expression__valid` | `keyword` |
| kql.option | `operator_option` | `operator_option__valid` | `keyword` |
| kql.hint | `hint_option` | `hint_option__valid` | `keyword` |
| kql.mv-apply | `mv_apply_operator` | `mv_apply_operator__valid` | `keyword` |
| kql.make-series | `make_series_operator` | `make_series_operator__valid` | `keyword` |
| kql.evaluate | `evaluate_operator` | `evaluate_operator__valid` | `keyword` |
| kql.search source | `search_source` | `search_source__valid` | `keyword` |
| kql.set | `expression_list` | `expression_list__valid` | `punctuation.bracket` |
| kql.between | `range` | `range__valid` | `operator` |
| kql.member | `member_expression` | `member_expression__valid` | `property` |
| kql.index | `index_expression` | `index_expression__valid` | `punctuation.bracket` |
| kql.dynamic | `dynamic_literal` | `dynamic_literal__valid` | `type` |
| kql.materialize | `materialize_expression` | `materialize_expression__valid` | `function.builtin` |
| kql.toscalar | `toscalar_expression` | `toscalar_expression__valid` | `function.builtin` |
| kql.typed-literal | `typed_literal` | `typed_literal__valid`, `typed_literal__invalid` | `constant` |
| kql.externaldata | `externaldata_expression` | `externaldata_expression__valid`, `externaldata_expression__invalid` | `keyword` |
| kql.range | `range_operator` | `range_operator__valid` | `keyword` |
| kql.top-nested | `top_nested_operator`, `top_nested_clause` | `top_nested_operator__valid` | `keyword` |
| kql.sample-distinct | `sample_distinct_operator` | `sample_distinct_operator__valid` | `keyword` |
| kql.fork | `fork_operator`, `fork_branch` | `fork_operator__valid` | `keyword` |
| kql.facet | `facet_operator` | `facet_operator__valid` | `keyword` |
| kql.partition | `partition_operator` | `partition_operator__valid` | `keyword` |
| kql.scan | `scan_operator`, `scan_step` | `scan_operator__valid` | `keyword` |

Control commands are parsed so the engine can reject them. They are not valid detections.

## SPL

| id | grammar rule | fixture ids | capture |
| --- | --- | --- | --- |
| spl.bare | `bare_search` | `bare_search__valid` | `property` |
| spl.search | `search_command` | `search_command__valid` | `keyword` |
| spl.where | `where_command` | `where_command__valid` | `keyword` |
| spl.eval | `eval_command` | `eval_command__valid` | `keyword` |
| spl.stats | `stats_command` | `stats_command__valid` | `keyword` |
| spl.rex | `rex_command` | `rex_command__valid` | `keyword` |
| spl.table | `table_command` | `table_command__valid` | `keyword` |
| spl.rename | `rename_command` | `rename_command__valid` | `keyword` |
| spl.fields | `fields_command` | `fields_command__valid` | `keyword` |
| spl.dedup | `dedup_command` | `dedup_command__valid` | `keyword` |
| spl.sort | `sort_command` | `sort_command__valid` | `keyword` |
| spl.head | `head_command` | `head_command__valid` | `keyword` |
| spl.tail | `tail_command` | `tail_command__valid` | `keyword` |
| spl.join | `join_command` | `join_command__valid` | `keyword` |
| spl.lookup | `lookup_command` | `lookup_command__valid` | `keyword` |
| spl.makemv | `makemv_command` | `makemv_command__valid` | `keyword` |
| spl.mvexpand | `mvexpand_command` | `mvexpand_command__valid` | `keyword` |
| spl.tstats | `tstats_command` | `tstats_command__valid` | `keyword` |
| spl.unknown | `unknown_command` | `unknown_command__valid` | `error` (`spl_unknown_command`) |
| spl.pipe | `"\|"` | `head_command__valid` | `operator.pipe` |
| spl.search-group | `search_group` | `search_group__valid` | `punctuation.bracket` |
| spl.field-name | `field_name` | `field_name__valid` | `variable` |
| spl.dedup-option | `dedup_option` | `dedup_option__valid` | `keyword` |
| spl.search-expression | `search_expression` | `search_expression__valid` | `operator` (`AND`, `OR`, `NOT`) |
| spl.field-value | `field_value` | `field_value__valid` | `property` |
| spl.search-word | `search_word` | `field_value__valid` | `variable` |
| spl.in | `in_clause` | `in_clause__valid` | `operator` |
| spl.term | `term_clause` | `term_clause__valid` | `function.builtin` |
| spl.case | `case_clause` | `case_clause__valid` | `function.builtin` |
| spl.prefix | `prefix_clause` | `prefix_clause__valid` | `function.builtin` |
| spl.comment | `comment` | `comment__valid` | `comment` |

Authored text is tokenized as written. An implicit leading `| search` is a Splunk runtime default, not a rewrite of the source.

## ES|QL

Language id `esql` (`.esql`). Commands and keywords are case-insensitive. The catalog in `catalogs/esql/` records each command's and function's `applies_to` lifecycle from the pinned Elasticsearch docs. `esql_unavailable` is an error for snapshot-only commands and information for anything an 8.19 cluster lacks or that is still in technical preview.

Each catalog row also lists the release lines (8.19, 9.0 … 9.6) whose own grammar and definitions accept it, and the engine keeps the same sets for forms that are not names (`RENAME new = old`, `LIKE (…)`, `::failures`, `??`, the `m` unit, subqueries, `where(` with no space). `opentide_esql::analyze` checks against every supported line: information when an older line lacks a form, a warning when the newest line does too (the 8.19-only `FROM x [METADATA …]` and `COMPLETION … WITH endpoint`, functions removed after a release). `analyze_for(source, Some(target))` checks one declared line (`StackTarget::parse("9.5")`, `"serverless"`) and warns when it lacks a form. `::type` names no release accepts are `esql_unknown_type` errors. Block comments nest as in Elasticsearch (`src/scanner.c`). `opentide_esql::output_columns` returns the query's column names when `KEEP` or `STATS` fixes them, and `None` when they depend on the index.

`esql_pattern` checks `LIKE` and `RLIKE` patterns: `LIKE` escapes only `\*`, `\?`, and `\\`, and an `RLIKE` pattern gets Lucene's `RegExp` checks (`lucene_regexp` below). `esql_expression_depth` is an error past 400 nested expressions, which every release rejects, and a warning from 301. A `::` selector other than `data` or `failures` is an `esql_parse_error`.

| id | grammar rule | fixture ids | capture |
| --- | --- | --- | --- |
| esql.change-point | `change_point_command` | `change_point_command__valid`, `change_point_command__invalid` | `keyword` |
| esql.comment | `comment` | `comment__valid`, `comment__invalid` | `comment` |
| esql.completion | `completion_command` | `completion_command__valid`, `completion_command__invalid` | `keyword` |
| esql.dedup | `dedup_command` | `dedup_command__valid`, `dedup_command__invalid` | `keyword` |
| esql.dense-vector | `dense_vector_command` | `dense_vector_command__valid`, `dense_vector_command__invalid` | `keyword` |
| esql.dissect | `dissect_command` | `dissect_command__valid`, `dissect_command__invalid` | `keyword` |
| esql.drop | `drop_command` | `drop_command__valid`, `drop_command__invalid` | `keyword` |
| esql.enrich | `enrich_command` | `enrich_command__valid`, `enrich_command__invalid` | `keyword` |
| esql.eval | `eval_command` | `eval_command__valid`, `eval_command__invalid` | `keyword` |
| esql.explain | `explain_command` | `explain_command__valid`, `explain_command__invalid` | `keyword` |
| esql.fill-null | `fill_null_command` | `fill_null_command__valid`, `fill_null_command__invalid` | `keyword` |
| esql.fork | `fork_command` | `fork_command__valid`, `fork_command__invalid` | `keyword` |
| esql.from | `from_command` | `from_command__valid`, `from_command__invalid` | `keyword` |
| esql.function-call | `function_call` | `function_call__valid`, `function_call__invalid` | `function` |
| esql.fuse | `fuse_command` | `fuse_command__valid`, `fuse_command__invalid` | `keyword` |
| esql.grok | `grok_command` | `grok_command__valid`, `grok_command__invalid` | `keyword` |
| esql.highlight | `highlight_command` | `highlight_command__valid`, `highlight_command__invalid` | `keyword` |
| esql.in-expression | `in_expression` | `in_expression__valid`, `in_expression__invalid` | `keyword` |
| esql.in-tuple | `in_tuple` | `in_tuple__valid`, `in_tuple__invalid` | `punctuation.bracket` |
| esql.inline-cast | `inline_cast` | `inline_cast__valid`, `inline_cast__invalid` | `operator`, `type` |
| esql.inline-stats | `inline_stats_command` | `inline_stats_command__valid`, `inline_stats_command__invalid` | `keyword` |
| esql.ip-location | `ip_location_command` | `ip_location_command__valid`, `ip_location_command__invalid` | `keyword` |
| esql.is-null-expression | `is_null_expression` | `is_null_expression__valid`, `is_null_expression__invalid` | `keyword`, `constant` |
| esql.join | `join_command` | `join_command__valid`, `join_command__invalid` | `keyword` |
| esql.keep | `keep_command` | `keep_command__valid`, `keep_command__invalid` | `keyword` |
| esql.like-expression | `like_expression` | `like_expression__valid`, `like_expression__invalid` | `keyword` |
| esql.limit | `limit_command` | `limit_command__valid`, `limit_command__invalid` | `keyword` |
| esql.map-expression | `map_expression` | `map_expression__valid`, `map_expression__invalid` | `punctuation.bracket` |
| esql.match-expression | `match_expression` | `match_expression__valid`, `match_expression__invalid` | `operator` |
| esql.metadata | `metadata` | `metadata__valid`, `metadata__invalid` | `keyword`, `constant` |
| esql.metrics-info | `metrics_info_command` | `metrics_info_command__valid`, `metrics_info_command__invalid` | `keyword` |
| esql.mmr | `mmr_command` | `mmr_command__valid`, `mmr_command__invalid` | `keyword` |
| esql.mv-expand | `mv_expand_command` | `mv_expand_command__valid`, `mv_expand_command__invalid` | `keyword` |
| esql.number | `number` | `number__valid`, `number__invalid` | `number` |
| esql.parameter | `parameter` | `parameter__valid`, `parameter__invalid` | `constant` |
| esql.promql | `promql_command` | `promql_command__valid`, `promql_command__invalid` | `keyword`, `string` |
| esql.qualified-interval | `qualified_interval` | `qualified_interval__valid`, `qualified_interval__invalid` | `number`, `constant` |
| esql.registered-domain | `registered_domain_command` | `registered_domain_command__valid`, `registered_domain_command__invalid` | `keyword` |
| esql.rename | `rename_command` | `rename_command__valid`, `rename_command__invalid` | `keyword` |
| esql.rerank | `rerank_command` | `rerank_command__valid`, `rerank_command__invalid` | `keyword` |
| esql.row | `row_command` | `row_command__valid`, `row_command__invalid` | `keyword` |
| esql.sample | `sample_command` | `sample_command__valid`, `sample_command__invalid` | `keyword` |
| esql.set | `set_command` | `set_command__valid`, `set_command__invalid` | `keyword` |
| esql.show | `show_command` | `show_command__valid`, `show_command__invalid` | `keyword` |
| esql.sort | `sort_command` | `sort_command__valid`, `sort_command__invalid` | `keyword` |
| esql.source-subquery | `source_subquery` | `source_subquery__valid`, `source_subquery__invalid` | `punctuation.bracket` |
| esql.stats | `stats_command` | `stats_command__valid`, `stats_command__invalid` | `keyword` |
| esql.string | `string` | `string__valid`, `string__invalid` | `string` |
| esql.ts-collapse | `ts_collapse_command` | `ts_collapse_command__valid`, `ts_collapse_command__invalid` | `keyword` |
| esql.ts | `ts_command` | `ts_command__valid`, `ts_command__invalid` | `keyword` |
| esql.ts-info | `ts_info_command` | `ts_info_command__valid`, `ts_info_command__invalid` | `keyword` |
| esql.unknown | `unknown_command` | `unknown_command__valid`, `unknown_command__invalid` | `error` (`esql_unknown_command`) |
| esql.uri-parts | `uri_parts_command` | `uri_parts_command__valid`, `uri_parts_command__invalid` | `keyword` |
| esql.user-agent | `user_agent_command` | `user_agent_command__valid`, `user_agent_command__invalid` | `keyword` |
| esql.where | `where_command` | `where_command__valid`, `where_command__invalid` | `keyword` |

## EQL

Language id `eql` (`.eql`). Keywords are lowercase and reserved. Elastic Security rejects `join` and relationship (`descendant of`, `child of`, `event of`) queries, so they parse and report `eql_unsupported`.

| id | grammar rule | fixture ids | capture |
| --- | --- | --- | --- |
| eql.any | `any` | `any__valid`, `any__invalid` | `type` |
| eql.comment | `comment` | `comment__valid`, `comment__invalid` | `comment` |
| eql.comparison | `comparison` | `comparison__valid`, `comparison__invalid` | `operator` |
| eql.event-query | `event_query` | `event_query__valid`, `event_query__invalid` | `type`, `keyword` |
| eql.field | `field` | `field__valid`, `field__invalid` | `property` |
| eql.function-call | `function_call` | `function_call__valid`, `function_call__invalid` | `function` |
| eql.join | `join` | `join__valid`, `join__invalid` | `keyword` (error `eql_unsupported`) |
| eql.missing-event-open | `missing_event_open` | `missing_event_open__valid`, `missing_event_open__invalid` | `operator` |
| eql.number | `number` | `number__valid`, `number__invalid` | `number` |
| eql.pipe | `pipe` | `pipe__valid`, `pipe__invalid` | `operator.pipe`, `keyword` |
| eql.predicate-expression | `predicate_expression` | `predicate_expression__valid`, `predicate_expression__invalid` | `operator` |
| eql.relationship | `relationship` | `relationship__valid`, `relationship__invalid` | `error` (`eql_unsupported`) |
| eql.sample | `sample` | `sample__valid`, `sample__invalid` | `keyword` |
| eql.sequence | `sequence` | `sequence__valid`, `sequence__invalid` | `keyword` |
| eql.string | `string` | `string__valid`, `string__invalid` | `string` |
| eql.subquery | `subquery` | `subquery__valid`, `subquery__invalid` | `punctuation.bracket` |
| eql.term-option | `term_option` | `term_option__valid`, `term_option__invalid` | `keyword` |
| eql.time-unit | `time_unit` | `time_unit__valid`, `time_unit__invalid` | `constant` |

Elasticsearch's lexer nests `/* */` comments; the grammar ends a comment at the first `*/`. The engine blanks the inner `/` and `*` of a comment Elasticsearch nests before parsing (byte offsets unchanged), so diagnostics, highlighting, and hover follow Elasticsearch, and it warns `eql_nested_comment`. The vendored grammar used on its own does not nest, so there is no `comment` corpus fixture for nesting.

Checks beyond the grammar: `eql_argument_type` (literal types the Verifier rejects on every release: function arguments, `:`/`in~`/`regex` patterns and arithmetic operands, `cidrMatch` ranges, and an `in` list mixing strings and numbers), `eql_not_boolean` (a string or number literal as a condition), `eql_field_comparison` (both sides of a comparison read fields), `eql_expression_depth` (over 250 levels: rejected by 8.19.17+, 9.3.5+, 9.4.3+, and 9.5, a warning), `eql_runs_ignored` (decimal `runs`), `eql_until_term` (`runs` or `![` on `until`), `eql_regex` (Lucene `RegExp` pitfalls), and the hint `eql_maxspan_missing`. `opentide_eql::sequences` gives each sequence's `maxspan` in milliseconds for rule-level scheduling checks.

## Kibana KQL (kuery)

Language id `kuery` (`.kuery`, alias `kibana-kql`). This is the Kibana Query Language Elastic rules call `language: kuery`, not Microsoft KQL. `or`, `and`, and `not` are case-insensitive keywords; everything else is a literal.

`or`, `and`, and `not` are keywords only with whitespace after them: at the very end of the query or before `)` or `}` they are value text, as in Kibana (`f:a or`, `f:(not)`), while `f:a or ` (trailing space) fails. Engine checks below the grammar:

- `kuery_parse_error` messages name the problem (no implicit `and` in `a:1 b:2`, an unclosed `(` or quote, a missing value or operand). They are not Kibana's PEG messages word for word: tree-sitter recovers at a different point than Kibana's parser.
- `kuery_question_mark` (hint): `?` is a literal in KQL, not a single-character wildcard. URL query strings (`/path?x=1`) are skipped.
- `kuery_free_text` (hint): a value with no field searches every field; after `f:a and b` the hint suggests `f:(a and b)`.
- `kuery_looks_like_lucene` (warning): two different kinds of Lucene syntax (ranges, `_exists_`, prefixes, `&&`, regexps, fuzzy or boost, text only Lucene parses) suggest `language: lucene`.

| id | grammar rule | fixture ids | capture |
| --- | --- | --- | --- |
| kuery.and-list | `and_list` | `and_list__valid`, `and_list__invalid` | `keyword` |
| kuery.and-query | `and_query` | `and_query__valid`, `and_query__invalid` | `keyword` |
| kuery.field | `field` | `field__valid`, `field__invalid` | `property` |
| kuery.field-value-expression | `field_value_expression` | `field_value_expression__valid`, `field_value_expression__invalid` | `property`, `operator` |
| kuery.group | `group` | `group__valid`, `group__invalid` | `punctuation.bracket` |
| kuery.nested-query | `nested_query` | `nested_query__valid`, `nested_query__invalid` | `punctuation.bracket` |
| kuery.not-list | `not_list` | `not_list__valid`, `not_list__invalid` | `keyword` |
| kuery.not-query | `not_query` | `not_query__valid`, `not_query__invalid` | `keyword` |
| kuery.or-list | `or_list` | `or_list__valid`, `or_list__invalid` | `keyword` |
| kuery.or-query | `or_query` | `or_query__valid`, `or_query__invalid` | `keyword` |
| kuery.quoted-string | `quoted_string` | `quoted_string__valid`, `quoted_string__invalid` | `string` |
| kuery.range-expression | `range_expression` | `range_expression__valid`, `range_expression__invalid` | `operator` |
| kuery.unquoted-literal | `unquoted_literal` | `unquoted_literal__valid`, `unquoted_literal__invalid` | `string` |
| kuery.value-expression | `value_expression` | `value_expression__valid`, `value_expression__invalid` | `string` |
| kuery.value-list | `value_list` | `value_list__valid`, `value_list__invalid` | `punctuation.bracket` |

## Lucene

Language id `lucene` (`.lucene`). Elastic's `query_string` syntax: `AND`, `OR`, and `NOT` are operators only in upper case, so lowercase `and`/`or` are terms (`lucene_lowercase_operator`).

Engine checks below the grammar (Elastic dialect unless noted):

- `lucene_regexp`: the body of `/regexp/` is Lucene's own regular-expression grammar. A body Lucene's `RegExp` rejects (`\b`, `\n`, an unclosed `"` or `<`, `(a|)`) is an error; so is one whose determinization exceeds `max_determinized_states` (10000) on both Elasticsearch 8.19 (Lucene 9) and 9.x (Lucene 10). When only one stack rejects it, it is a warning naming that stack. `(?:`, `(?i)`, `^`, and `$` are literal text in Lucene (warning), and a body over the default `index.max_regex_length` (1000) is a warning. On an index whose `query_string` is lenient (the default when `index.query.default_field` is `*`), Elasticsearch turns a rejected regexp into a clause that matches nothing instead of failing the search; either way the clause never matches.
- `lucene_fuzzy`: Elasticsearch reads `term~N` as a fuzziness and accepts only `0`, `1`, `2`, `AUTO`, or a bare `~` (error otherwise, including `~3` and `~0.5`, which Lucene alone would clamp or read as a similarity). Phrase slop (`"a b"~5`) is not checked.
- `lucene_range_operator` (warning): `f:> 10` searches `f` for `>`; the value must follow the operator (`f:>10`).
- `lucene_unescaped_slash` (warning): `a/b/c` or `path:/var/log` reads `/b/` or `/var/` as a regexp. An unclosed `/` is a `lucene_parse_error` that says so.
- `lucene_bare_term` (hint; warning for Carbon Black): `f:v w` searches `w` in every field.
- `lucene_looks_like_kuery` (warning): two different kinds of KQL syntax (lower-case operators, `f >= 10`, a leading `not`, text only KQL parses) suggest `language: kuery`.
- Carbon Black Cloud (`configurations.carbon_black_cloud.query`): newlines count as spaces (deploy joins lines), `_exists_`, `f:>v`, and `f\*:` are `lucene_elasticsearch_only` warnings, regexp and fuzzy problems are warnings (the Solr version is not known), and upper-case letters in a regexp get a hint because Carbon Black matches lower-cased tokens. There is no Carbon Black field catalogue yet.

| id | grammar rule | fixture ids | capture |
| --- | --- | --- | --- |
| lucene.boolean-query | `boolean_query` | `boolean_query__valid`, `boolean_query__invalid` | `keyword` |
| lucene.boost | `boost` | `boost__valid`, `boost__invalid` | `number` |
| lucene.field-query | `field_query` | `field_query__valid`, `field_query__invalid` | `property` |
| lucene.fuzzy | `fuzzy` | `fuzzy__valid`, `fuzzy__invalid` | `number` |
| lucene.group | `group` | `group__valid`, `group__invalid` | `punctuation.bracket` |
| lucene.modified-clause | `modified_clause` | `modified_clause__valid`, `modified_clause__invalid` | `operator` |
| lucene.phrase-query | `phrase_query` | `phrase_query__valid`, `phrase_query__invalid` | `string` |
| lucene.range-query | `range_query` | `range_query__valid`, `range_query__invalid` | `keyword`, `number` |
| lucene.regexp-query | `regexp_query` | `regexp_query__valid`, `regexp_query__invalid` | `string` |
| lucene.star | `star` | `star__valid`, `star__invalid` | `operator` |
| lucene.term-query | `term_query` | `term_query__valid`, `term_query__invalid` | `string` |
| lucene.wildcard-term | `wildcard_term` | `wildcard_term__valid`, `wildcard_term__invalid` | `string` |

Corpus lives in `testdata/corpus/{kql,spl,esql,eql,kuery,lucene}/` tagged `prod:<rule>`.
