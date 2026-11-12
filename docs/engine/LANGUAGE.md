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
| kql.parse-where | `parse_where_operator` | `parse_where_operator__valid`, `parse_where_operator__invalid` | `keyword` |
| kql.lookup | `lookup_operator` | `lookup_operator__valid` | `keyword` |
| kql.take | `take_operator` | `take_operator__valid` | `keyword` |
| kql.limit | `limit_operator` | `limit_operator__valid` | `keyword` |
| kql.sort | `sort_operator` | `sort_operator__valid` | `keyword` |
| kql.distinct | `distinct_operator` | `distinct_operator__valid` | `keyword` |
| kql.render | `render_operator` | `render_operator__valid` | `keyword` (warning `kql_render_not_valid`) |
| kql.control | `control_command` | `control_command__valid` | `error` (`kql_control_command_unsupported`) |
| kql.pipe | `"\|"` | `take_operator__valid` | `operator.pipe` |
| kql.function | `function_call` | `function_call__valid` | `function` |
| kql.named-argument | `named_argument` | `named_argument__valid` | `variable` |
| kql.quoted-identifier | `quoted_identifier` | `quoted_identifier__valid`, `quoted_identifier__invalid` | `variable` |
| kql.column-pattern | `column_pattern` | `column_pattern__valid` | `variable` |
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
| spl.stats | `stats_command` (`stats`, `eventstats`, `streamstats`, `sistats`, `chart`, `timechart`, `sichart`, `sitimechart`, `geostats`) | `stats_command__valid` | `keyword` |
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
| spl.fillnull | `fillnull_command` | `fillnull_command__valid` | `keyword` |
| spl.foreach | `foreach_command` | `foreach_command__valid` | `keyword` |
| spl.spath | `spath_command` | `spath_command__valid` | `keyword` |
| spl.tojson | `tojson_command` | `tojson_command__valid` | `keyword` |
| spl.inputlookup | `inputlookup_command` | `inputlookup_command__valid` | `keyword` |
| spl.outputlookup | `outputlookup_command` | `outputlookup_command__valid` | `keyword` |
| spl.chart-where | `chart_where` | `chart_where__valid` | `keyword` |
| spl.by | `by_clause` | `stats_command__valid.eventstats` | `keyword` |
| spl.aggregate | `aggregate_item` | `stats_command__valid.eventstats` | `function` |
| spl.rename-item | `rename_item` | `rename_item__valid` | `keyword` (`as`) |
| spl.lookup-field | `lookup_field` | `lookup_field__valid` | `keyword` (`as`, `output`, `outputnew`) |
| spl.option | `command_option` | `command_option__valid` | `property` |
| spl.comparison | `comparison` | `command_option__valid` | `property` |
| spl.arguments | `argument_list` | `command_option__valid` | `variable` |

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
- Carbon Black Cloud (`configurations.carbon_black_cloud.query`): newlines count as spaces (deploy joins lines), `_exists_`, `f:>v`, and `f\*:` are `lucene_elasticsearch_only` warnings, regexp and fuzzy problems are warnings (the Solr version is not known), and upper-case letters in a regexp get a hint because Carbon Black matches lower-cased tokens.
- Carbon Black fields come from `catalogs/carbon_black/fields.toml`: 76 process search fields with their type, whether a process can hold several values, and the values a few take (`device_os`, `process_integrity_level`). The file says where each field is attested (Carbon Black's Python SDK and pySigma's Carbon Black pipeline). In a Carbon Black query:
  - `cbc_unknown_field` (warning) names a field within two edits of a catalog field and suggests it (`process_nmae` → `process_name`). A field far from every catalog field is left alone: the catalog may lack it.
  - Hover shows a field's type and description, and completion offers the catalog's fields, or a field's values after `field:`. ECS fields are never offered: they are Elastic's. A raw `.lucene` file keeps the Elastic behaviour; `opentide-lsp analyze --platform carbon_black_cloud` checks one in the Carbon Black dialect.
  - Which fields Carbon Black tokenizes is not in the catalog (Carbon Black documents it only on developer.carbonblack.com), so the upper-case regexp hint still fires on every field.

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

## Falco

Language id `falco` (`.falco`). Falco rule conditions, which Sysdig Secure runs: `configurations.sysdig.condition`, `macros[].condition`, and `output` in Tide (sysdig-1.0). Verdicts follow the sources Falco runs, not documentation; `docs/FALCO.md` is the conformance matrix.

- **Syntax** is a port of libsinsp's filter parser (`crates/opentide-falco/src/parser.rs`, falcosecurity/libs `filter/parser.cpp`): keywords matched as prefixes, word operators (`contains`, `startswith`, ...) that need a blank after them, `not(`, operator modifiers (`= anyof (a, b)`, `startswith oneof (...)`), multi-argument transformers (`join`, `concat`, `getopt`) with transformer lists and a trailing argument (`getopt(proc.args, "nt:")[t]`), hex and exponent numbers, both quote styles with libsinsp's escapes, and its recursion limit. All 571 expressions of libs' parser tests agree, messages included (`testdata/conformance/libsinsp/parser.json`).
- **Compile checks** follow libsinsp's filter compiler (`compile.rs`): field resolution class by class with each field's argument rules, operator and type (`flt_is_comparable`), values parsed as the field's type, transformer types and arity, right-hand side fields, and libsinsp's compile warnings. All 326 filters of libs' compiler tests agree (`compiler.json`).
- **Falco's rule loader** (`lib.rs`, `exceptions.rs`): lists expand as text before the parse, macros resolve by name, a tuning is appended to the tuned rule's condition, exceptions are validated and compiled as Falco writes them, output templates format as libsinsp's formatter reads them, deprecated fields and `<NA>` checks warn, and a syscall rule that cannot be narrowed to a few event types warns.

The field catalogue is generated from libsinsp's own field tables (types and flags) and the plugin READMEs, and the event and syscall names from the driver tables (`scripts/sync_falco_catalog.py`). The block's `source` picks the fields (`syscall` default; `k8s_audit`, `aws_cloudtrail`, `okta`, `github`, `gcp_auditlog`); its `macros` and `lists` are in scope, as deploy expands them.

Errors are what Falco refuses to load: `falco_parse_error`, `falco_unknown_field`, `falco_field_argument`, `falco_operator_type`, `falco_value_type`, `falco_transformer`, `falco_rhs_field`, `falco_invalid_regex`, `falco_unknown_event`, `falco_misplaced_list`, `falco_append_condition`, `falco_output_syntax`, `falco_exception`. Warnings are what depends on the agent or is advice: `falco_unknown_macro`, `falco_unknown_list`, `falco_unknown_rule`, `falco_unknown_source`, `falco_regex_simple`, `falco_field_as_value`, `falco_transformer_as_value`, `falco_deprecated_field`, `falco_unsafe_na_check`, `falco_no_evttype`, `falco_newer_syntax`.

Every condition of the Falco default rules (`testdata/conformance/external/falco/`, 241 rules across the six sources) comes out with no finding. Hover explains fields (type, sources, description), macros and lists (the block's, or the default rules' with the defining file), operators, modifiers, transformers, and event types; completion offers the source's fields, macros and transformers in condition position, operators after a field, and lists (and event types after `evt.type`) inside a value list.

The tree-sitter grammar drives highlighting and editor structure; it accepts libsinsp's syntax, but its verdict is not the engine's.

| id | grammar rule | fixture ids | capture |
| --- | --- | --- | --- |
| falco.and-expression | `and_expression` | `and_expression__valid`, `and_expression__invalid` | `keyword` |
| falco.or-expression | `or_expression` | `or_expression__valid`, `or_expression__invalid` | `keyword` |
| falco.not-expression | `not_expression` | `not_expression__valid`, `not_expression__invalid` | `keyword` |
| falco.append-fragment | `append_fragment` | `append_fragment__valid`, `append_fragment__invalid` | `keyword` |
| falco.parenthesized | `parenthesized_expression` | `parenthesized_expression__valid`, `parenthesized_expression__invalid` | `punctuation.bracket` |
| falco.macro | `macro_reference` | `macro_reference__valid`, `macro_reference__invalid` | `macro` |
| falco.comparison | `comparison` | `comparison__valid`, `comparison__invalid` | `operator`, `keyword` |
| falco.field | `field` | `field__valid`, `field__invalid` | `property` |
| falco.field-argument | `field_argument` | `field_argument__valid`, `field_argument__invalid` | `string` |
| falco.field-transformer | `field_transformer` | `field_transformer__valid`, `field_transformer__invalid` | `function.builtin` |
| falco.value-transformer | `value_transformer` | `value_transformer__valid`, `value_transformer__invalid` | `function.builtin` |
| falco.value-list | `value_list` | `value_list__valid`, `value_list__invalid` | `string`, `variable` (a list) |
| falco.list-reference | `list_reference` | `list_reference__valid`, `list_reference__invalid` | `variable` |
| falco.quoted-string | `quoted_string` | `quoted_string__valid`, `quoted_string__invalid` | `string` |
| falco.operator-modifier | `operator_modifier` | `operator_modifier__valid`, `operator_modifier__invalid` | `keyword` |
| falco.transformer-list | `transformer_list` | `transformer_list__valid`, `transformer_list__invalid` | `function.builtin` (inner transformers) |

## Elastic indices and ECS

ES|QL, EQL, kuery, and Lucene know which indices a query reads where it is written down: ES|QL from its `FROM` (or `TS`) command, the others from the Tide rule's elastic block, `index` for `query` and `threat.index` for `threat.query`. A `data_view_id`, an omitted `index` (the tenant's `setup.index`), a hunt, or a raw `.kuery`, `.lucene`, or `.eql` file leaves them unknown.

Where the workspace has `system = "elastic"` log sources in `visibility.toml`, whose `name` is an index pattern or data stream, an index pattern a rule or `FROM` reads that no declared pattern covers or reaches is `elastic_dataset_not_declared` (warning). `logs-*` declared covers `logs-azure.signinlogs-*`; a used `win*` reaches a declared `winlogbeat-x`. Opt-in: a workspace with no elastic log source gets no warning. Data views are not declarable, so a `data_view_id` is not checked. The `columns` a log source lists (Elasticsearch field types) are fields its index pattern maps: on ECS indices (`logs-*`), a declared field is never `ecs_unknown_field`, and its declared type decides `ecs_type_mismatch`.

Where every index is ECS, an integration data stream (`logs-*`), fields are checked against `catalogs/ecs/fields.json`:

- `ecs_type_mismatch` (error), only what Elasticsearch rejects on an ECS mapping (`testdata/oracles/elasticsearch`): in kuery and Lucene, a wildcard, regexp, or fuzzy term on a number, date, ip, or boolean field (`source.ip:10.*`) and a value the type cannot parse (`source.port:http`, `process.pid:[a TO b]`); in EQL, `:`, `like`, or `regex` on a field that is not a string, an `in` list of numbers on a string field, a function argument or arithmetic operand of the wrong type, and an object (`host`) used as a value; in ES|QL, `LIKE` or `RLIKE` on a column that is not a string (`FROM logs-* | WHERE source.ip LIKE "10.*"`) and a column passed to a function parameter that takes no type of its kind. A range on an ip field, `==` on a `text` field, and a string compared with an ip or a number with `==` are valid and never reported. ES|QL checks only columns the query reads from the indices: a name `EVAL`, `RENAME`, `DISSECT`, `GROK`, `ENRICH … WITH`, or `INLINE STATS` defines is the query's own, and nothing is checked after `STATS` or a command whose columns the text does not show.
- `ecs_unknown_field` (warning), only a near miss of an ECS field under an ECS field set, with the field as the suggestion (`process.nmae` → `process.name`). ECS allows custom fields, so `labels.*`, children of object, flattened, and nested fields, Elastic Defend's `*.Ext.*`, integration namespaces (`azure.*`, `okta.*`, `winlog.*`), wildcards, and optional EQL fields (`?x`) are never reported. `.text`, `.keyword`, and `.caseless` multi-fields resolve to their parent.

Corpus lives in `testdata/corpus/{kql,spl,esql,eql,kuery,lucene}/` tagged `prod:<rule>`.

## CQL

Language id `cql` (`.cql`). The CrowdStrike Query Language of Falcon LogScale and Falcon Next-Gen SIEM: `configurations.crowdstrike.query` (platform::crowdstrike::1.0, a correlation rule) and hunts with `system: crowdstrike` in Tide. CQL is closed source, so the grammar follows CrowdStrike's published "CQL Grammar Subset" and reference pages; `docs/CQL.md` has the language, the diagnostics and the conformance results.

- **Syntax** is the tree-sitter grammar, with an external scanner for what CQL lexes by position: a word is a function name only when `(` follows at once, a field name before a filter operator and a pattern elsewhere; `/` is a comment, a regex, a pattern character or division. `or` binds tighter than `and`, juxtaposition is `and`, `|` is loosest. Filter and expression constructs are separate nodes. 2,786 of the 2,812 blocks labelled CQL in CrowdStrike's public content parse, and 475 of the 490 queries on CrowdStrike's function pages are clean; the rest are not valid CQL (non-breaking spaces pasted from the web, prose, SPL, templates, author errors). Steps may follow each other without a pipe, as CrowdStrike's examples write them (`docs/CQL.md`).
- **Checks** run on the tree against `catalogs/cql/` (`scripts/sync_cql_catalog.py`): functions (matched without regard to case), parameters, the one omittable argument, enumerated values and bounds, regex flags, string escapes, where free text and `<=>` may appear, and Falcon event names. A correlation rule also refuses `correlate()` with another aggregate.

Errors are what LogScale refuses to compile: `cql_parse_error`, `cql_unknown_function`, `cql_removed_function`, `cql_unknown_parameter`, `cql_duplicate_parameter`, `cql_unnamed_argument`, `cql_missing_parameter`, `cql_parameter_value`, `cql_regex_flag`, `cql_free_text_after_aggregate`, `cql_assignment_as`, `cql_link_outside_correlate`, `cql_event_function_after_aggregate`, `cql_correlate_placement`, `cql_match_guard`, and in a correlation rule `cql_correlate_aggregate`. Warnings: `cql_deprecated_function`, `cql_string_escape`, `cql_unknown_event`, `cql_regex_group_under_or`. No field, saved search, lookup file or repository is ever reported unknown: they live in the tenant.

Hover explains functions (signature, summary, aggregate, lifecycle, CrowdStrike's page), parameters (type, default, allowed values, bounds), tags and fields (LogScale, Falcon or CPS) and Falcon events; completion offers functions and fields in a step, the parameters a call has not been given, allowed values after `name=`, and Falcon events after `#event_simpleName=`; signature help follows the parameter by name, or the omittable one.

| id | grammar rule | fixture ids | capture |
| --- | --- | --- | --- |
| cql.pipeline | `pipeline` | `pipeline__valid`, `pipeline__invalid` | `operator.pipe` |
| cql.and-filter | `and_filter` | `and_filter__valid`, `and_filter__invalid` | `keyword` |
| cql.or-filter | `or_filter` | `or_filter__valid`, `or_filter__invalid` | `keyword` |
| cql.not-filter | `not_filter` | `not_filter__valid`, `not_filter__invalid` | `keyword`, `operator` |
| cql.parenthesized-filter | `parenthesized_filter` | `parenthesized_filter__valid`, `parenthesized_filter__invalid` | `punctuation.bracket` |
| cql.field-filter | `field_filter` | `field_filter__valid`, `field_filter__invalid` | `property`, `operator` |
| cql.free-text | `free_text` | `free_text__valid`, `free_text__invalid` | `string` |
| cql.regex | `regex` | `regex__valid`, `regex__invalid` | `string`, `constant` (flags) |
| cql.string | `string` | `string__valid`, `string__invalid` | `string` |
| cql.field-name | `field_name` | `field_name__valid`, `field_name__invalid` | `property`, `type` (a `#tag`) |
| cql.function-call | `function_call` | `function_call__valid`, `function_call__invalid` | `function.builtin` (catalogued), `function` |
| cql.negated-function-call | `negated_function_call` | `negated_function_call__valid`, `negated_function_call__invalid` | `operator`, `function.builtin` |
| cql.argument | `argument` | `argument__valid`, `argument__invalid` | by value |
| cql.named-argument | `named_argument` | `named_argument__valid`, `named_argument__invalid` | `variable` (the name) |
| cql.array | `array` | `array__valid`, `array__invalid` | `punctuation.bracket` |
| cql.assignment | `assignment` | `assignment__valid`, `assignment__invalid` | `property`, `operator` |
| cql.field-shorthand | `field_shorthand` | `field_shorthand__valid`, `field_shorthand__invalid` | `property`, `operator` |
| cql.stats-shorthand | `stats_shorthand` | `stats_shorthand__valid`, `stats_shorthand__invalid` | `punctuation.bracket` |
| cql.case-statement | `case_statement` | `case_statement__valid`, `case_statement__invalid` | `keyword` |
| cql.case-branch | `case_branch` | `case_branch__valid`, `case_branch__invalid` | `punctuation.delimiter` |
| cql.match-statement | `match_statement` | `match_statement__valid`, `match_statement__invalid` | `property`, `keyword` |
| cql.match-branch | `match_branch` | `match_branch__valid`, `match_branch__invalid` | `operator` |
| cql.saved-query | `saved_query` | `saved_query__valid`, `saved_query__invalid` | `macro` |
| cql.saved-query-argument | `saved_query_argument` | `saved_query_argument__valid`, `saved_query_argument__invalid` | `variable` |
| cql.query-parameter | `query_parameter` | `query_parameter__valid`, `query_parameter__invalid` | `macro` |
| cql.subquery | `subquery` | `subquery__valid`, `subquery__invalid` | `punctuation.bracket` |
| cql.named-subquery | `named_subquery` | `named_subquery__valid`, `named_subquery__invalid` | `variable` |
| cql.attributed-expression | `attributed_expression` | `attributed_expression__valid`, `attributed_expression__invalid` | by expression |
| cql.expression-attribute | `expression_attribute` | `expression_attribute__valid`, `expression_attribute__invalid` | `variable` |
| cql.binary-expression | `binary_expression` | `binary_expression__valid`, `binary_expression__invalid` | `operator` |
| cql.unary-expression | `unary_expression` | `unary_expression__valid`, `unary_expression__invalid` | `operator` |
| cql.parenthesized-expression | `parenthesized_expression` | `parenthesized_expression__valid`, `parenthesized_expression__invalid` | `punctuation.bracket` |
| cql.link-constraint | `link_constraint` | `link_constraint__valid`, `link_constraint__invalid` | `property`, `operator` |
| cql.line-comment | `line_comment` | `line_comment__valid`, `line_comment__invalid` | `comment` |
| cql.block-comment | `block_comment` | `block_comment__valid`, `block_comment__invalid` | `comment` |

## YARA

Language id `yara` (`.yar`, `.yara`). YARA signatures as libyara 4.5 compiles them ([yara-1.0](https://github.com/opentidehq/specifications/blob/main/specs/languages/yara-1.0.md)): HarfangLab and Bitdefender `yara` blocks. `docs/YARA.md` has the codes.

- **Verdicts** come from VirusTotal's `yara-x-parser` (`crates/opentide-yara`), not from this grammar.
- **The tree-sitter grammar** (`grammars/tree-sitter-opentide-yara`) colours and structures the text. It is written from libyara's `grammar.y`, `lexer.l` and `hex_grammar.y`, with their precedence: `expression` (booleans, comparisons, `of`, `for`) over `primary_expression` (arithmetic, string counts and offsets, module references). `\` is division, so `/` always opens a regexp.
- **Agreement**: `crates/opentide-yara/tests/tree_sitter_agreement.rs` runs both parsers over yara-x-parser's own 71 inputs and this corpus. They agree on every input but eight, each listed with its reason. Five are YARA-X-only syntax (`with`, digit separators, float meta and `"""` strings, booleans in `of` tuples), which the grammar refuses as libyara does. Three are libyara syntax that YARA-X refuses (an escape in a `base64` alphabet, rule wildcards in `of`).

| id | grammar rule | fixture ids | capture |
| --- | --- | --- | --- |
| yara.comment | `comment` | `comment__valid`, `comment__invalid` | `comment` |
| yara.import | `import` | `import__valid`, `import__invalid` | `keyword`, `string` |
| yara.include | `include` | `include__valid`, `include__invalid` | `keyword`, `string` |
| yara.rule | `rule` | `rule__valid`, `rule__invalid` | `keyword`, `type` |
| yara.rule-modifier | `rule_modifier` | `rule_modifier__valid`, `rule_modifier__invalid` | `keyword` |
| yara.tags | `tags` | `tags__valid`, `tags__invalid` | `punctuation.delimiter`, `constant` |
| yara.meta-section | `meta_section` | `meta_section__valid`, `meta_section__invalid` | `keyword` |
| yara.meta-definition | `meta_definition` | `meta_definition__valid`, `meta_definition__invalid` | `property`, `operator` |
| yara.negative-integer | `negative_integer` | `negative_integer__valid`, `negative_integer__invalid` | `operator`, `number` |
| yara.strings-section | `strings_section` | `strings_section__valid`, `strings_section__invalid` | `keyword` |
| yara.string-definition | `string_definition` | `string_definition__valid`, `string_definition__invalid` | `variable`, `operator` |
| yara.string-modifier | `string_modifier` | `string_modifier__valid`, `string_modifier__invalid` | `keyword` |
| yara.xor-modifier | `xor_modifier` | `xor_modifier__valid`, `xor_modifier__invalid` | `keyword`, `number` |
| yara.base64-modifier | `base64_modifier` | `base64_modifier__valid`, `base64_modifier__invalid` | `keyword`, `string` |
| yara.hex-string | `hex_string` | `hex_string__valid`, `hex_string__invalid` | `punctuation.bracket`, `number` |
| yara.hex-not | `hex_not` | `hex_not__valid`, `hex_not__invalid` | `operator`, `number` |
| yara.hex-jump | `hex_jump` | `hex_jump__valid`, `hex_jump__invalid` | `punctuation.bracket`, `number` |
| yara.hex-alternative | `hex_alternative` | `hex_alternative__valid`, `hex_alternative__invalid` | `punctuation.bracket`, `operator` |
| yara.condition-section | `condition_section` | `condition_section__valid`, `condition_section__invalid` | `keyword` |
| yara.filesize | `filesize` | `filesize__valid`, `filesize__invalid` | `constant` |
| yara.entrypoint | `entrypoint` | `entrypoint__valid`, `entrypoint__invalid` | `constant` |
| yara.parenthesized-expression | `parenthesized_expression` | `parenthesized_expression__valid`, `parenthesized_expression__invalid` | `punctuation.bracket` |
| yara.parenthesized-primary | `parenthesized_primary` | `parenthesized_primary__valid`, `parenthesized_primary__invalid` | `punctuation.bracket` |
| yara.not-expression | `not_expression` | `not_expression__valid`, `not_expression__invalid` | `keyword` |
| yara.and-expression | `and_expression` | `and_expression__valid`, `and_expression__invalid` | `keyword` |
| yara.or-expression | `or_expression` | `or_expression__valid`, `or_expression__invalid` | `keyword` |
| yara.comparison | `comparison` | `comparison__valid`, `comparison__invalid` | `operator`, `keyword` |
| yara.unary-expression | `unary_expression` | `unary_expression__valid`, `unary_expression__invalid` | `operator` |
| yara.arithmetic-expression | `arithmetic_expression` | `arithmetic_expression__valid`, `arithmetic_expression__invalid` | `operator` |
| yara.string-count-in-range | `string_count_in_range` | `string_count_in_range__valid`, `string_count_in_range__invalid` | `variable`, `keyword` |
| yara.indexed-string | `indexed_string` | `indexed_string__valid`, `indexed_string__invalid` | `variable`, `punctuation.bracket` |
| yara.member-expression | `member_expression` | `member_expression__valid`, `member_expression__invalid` | `type` (module), `property` |
| yara.index-expression | `index_expression` | `index_expression__valid`, `index_expression__invalid` | `punctuation.bracket` |
| yara.call-expression | `call_expression` | `call_expression__valid`, `call_expression__invalid` | `function.builtin` (`uint16`…), `function` |
| yara.string-match | `string_match` | `string_match__valid`, `string_match__invalid` | `variable`, `keyword` |
| yara.range | `range` | `range__valid`, `range__invalid` | `punctuation.bracket`, `operator` |
| yara.of-expression | `of_expression` | `of_expression__valid`, `of_expression__invalid` | `keyword` |
| yara.percent-quantifier | `percent_quantifier` | `percent_quantifier__valid`, `percent_quantifier__invalid` | `number`, `operator` |
| yara.string-set | `string_set` | `string_set__valid`, `string_set__invalid` | `variable` |
| yara.rule-set | `rule_set` | `rule_set__valid`, `rule_set__invalid` | `type` |
| yara.for-expression | `for_expression` | `for_expression__valid`, `for_expression__invalid` | `keyword`, `variable` |
| yara.integer-enumeration | `integer_enumeration` | `integer_enumeration__valid`, `integer_enumeration__invalid` | `number` |
| yara.rule-wildcard | `rule_wildcard` | `rule_wildcard__valid`, `rule_wildcard__invalid` | `type` |
| yara.string-wildcard | `string_wildcard` | `string_wildcard__valid`, `string_wildcard__invalid` | `variable` |
| yara.string-count | `string_count` | `string_count__valid`, `string_count__invalid` | `variable` |
| yara.string-offset | `string_offset` | `string_offset__valid`, `string_offset__invalid` | `variable` |
| yara.string-length | `string_length` | `string_length__valid`, `string_length__invalid` | `variable` |
| yara.float | `float` | `float__valid`, `float__invalid` | `number` |
| yara.regexp | `regexp` | `regexp__valid`, `regexp__invalid` | `string` |

## YARA-L

Language id `yaral` (`.yaral`, `.yl2`). YARA-L 2.0, Google Security Operations ([yara-l-1.0](https://github.com/opentidehq/specifications/blob/main/specs/languages/yara-l-1.0.md)): `configurations.google_secops` sections, Google SecOps hunts, and rule files. `docs/YARAL.md` has the codes.

- **The grammar is the verdict parser** (`grammars/tree-sitter-opentide-yaral`, written for the spec: Google publishes none). It parses a rule or a search: sections in any order (the engine reports order and profile), newline-separated predicates as juxtaposed statements, field paths whose `.segment` and `[index]` accessors follow without blanks, so a UDM segment named like a keyword (`network.dhcp.options`) stays a name.
- **Keywords** are case-insensitive in Google's compiler; the grammar spells each one lower, upper and title case (`and`, `AND`, `And`), so `word` extraction keeps `metadata` an identifier. Mixed case such as `aNd` is a parse error.
- **Coverage**: every rule of chronicle/detection-rules' `rules/community` (410) parses; `testdata/conformance/external/yaral/` holds 79 of them with fault twins.

| id | grammar rule | fixture ids | capture |
| --- | --- | --- | --- |
| yaral.rule | `rule_declaration` | `rule_declaration__valid`, `rule_declaration__invalid` | `keyword`, `type` |
| yaral.meta | `meta_section` | `meta_section__valid`, `meta_section__invalid` | `keyword`, `property` |
| yaral.setup | `setup_section` | `setup_section__valid`, `setup_section__invalid` | `keyword` |
| yaral.graph-operation | `graph_operation` | `graph_operation__valid`, `graph_operation__invalid` | `keyword` |
| yaral.events | `events_section` | `events_section__valid`, `events_section__invalid` | `keyword` |
| yaral.search-events | `search_events` | `search_events__valid`, `search_events__invalid` | `property`, `string` |
| yaral.search | `search_query` | `search_query__valid`, `search_query__invalid` | `keyword` |
| yaral.stage | `stage` | `stage__valid`, `stage__invalid` | `keyword`, `type` |
| yaral.match | `match_section` | `match_section__valid`, `match_section__invalid` | `keyword`, `variable` |
| yaral.match-window | `match_window` | `match_window__valid`, `match_window__invalid` | `keyword`, `number` |
| yaral.duration | `duration` | `duration__valid`, `duration__invalid` | `number` |
| yaral.outcome | `outcome_section` | `outcome_section__valid`, `outcome_section__invalid` | `keyword`, `constant` |
| yaral.condition | `condition_section` | `condition_section__valid`, `condition_section__invalid` | `keyword`, `variable` |
| yaral.options | `options_section` | `options_section__valid`, `options_section__invalid` | `keyword`, `property` |
| yaral.export | `export_section` | `export_section__valid`, `export_section__invalid` | `keyword` |
| yaral.table-call | `table_call` | `table_call__valid`, `table_call__invalid` | `constant`, `function.builtin` |
| yaral.named-argument | `named_argument` | `named_argument__valid`, `named_argument__invalid` | `property` |
| yaral.dedup | `dedup_section` | `dedup_section__valid`, `dedup_section__invalid` | `keyword` |
| yaral.order | `order_section` | `order_section__valid`, `order_section__invalid` | `keyword` |
| yaral.limit | `limit_section` | `limit_section__valid`, `limit_section__invalid` | `keyword`, `number` |
| yaral.select | `select_section` | `select_section__valid`, `select_section__invalid` | `keyword` |
| yaral.unselect | `unselect_section` | `unselect_section__valid`, `unselect_section__invalid` | `keyword` |
| yaral.or | `or_expression` | `or_expression__valid`, `or_expression__invalid` | `keyword` |
| yaral.and | `and_expression` | `and_expression__valid`, `and_expression__invalid` | `keyword` |
| yaral.not | `not_expression` | `not_expression__valid`, `not_expression__invalid` | `keyword` |
| yaral.comparison | `comparison` | `comparison__valid`, `comparison__invalid` | `operator`, `keyword` (`nocase`) |
| yaral.in | `in_expression` | `in_expression__valid`, `in_expression__invalid` | `keyword`, `constant` |
| yaral.binary | `binary_expression` | `binary_expression__valid`, `binary_expression__invalid` | `operator` |
| yaral.unary | `unary_expression` | `unary_expression__valid`, `unary_expression__invalid` | `operator` |
| yaral.of | `of_expression` | `of_expression__valid`, `of_expression__invalid` | `keyword` |
| yaral.parenthesized | `parenthesized_expression` | `parenthesized_expression__valid`, `parenthesized_expression__invalid` | `punctuation.bracket` |
| yaral.quantified-field | `quantified_field` | `quantified_field__valid`, `quantified_field__invalid` | `keyword` |
| yaral.udm-field | `udm_field` | `udm_field__valid`, `udm_field__invalid` | `variable`, `property` |
| yaral.bare-field | `bare_field` | `bare_field__valid`, `bare_field__invalid` | `property` |
| yaral.index | `index` | `index__valid`, `index__invalid` | `punctuation.bracket`, `string` |
| yaral.function-call | `function_call` | `function_call__valid`, `function_call__invalid` | `type`, `function.builtin` |
| yaral.if | `if_expression` | `if_expression__valid`, `if_expression__invalid` | `keyword` |
| yaral.array | `array` | `array__valid`, `array__invalid` | `punctuation.bracket` |
| yaral.reference-list | `reference_list` | `reference_list__valid`, `reference_list__invalid` | `constant` |
| yaral.data-table-column | `data_table_column` | `data_table_column__valid`, `data_table_column__invalid` | `constant`, `property` |
| yaral.raw-string | `raw_string` | `raw_string__valid`, `raw_string__invalid` | `string` |
| yaral.regex | `regex` | `regex__valid`, `regex__invalid` | `string` |
| yaral.comment | `comment` | `comment__valid`, `comment__invalid` | `comment` |
