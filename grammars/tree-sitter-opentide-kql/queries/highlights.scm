; KQL highlights. Capture names must be subset of highlights/spec.toml.
; Specific captures are listed before (identifier) @variable (first-wins).

(let_statement "let" @keyword)
(where_operator "where" @keyword)
(filter_operator "filter" @keyword)
(project_operator "project" @keyword)
(project_away_operator "project-away" @keyword)
(project_rename_operator "project-rename" @keyword)
(project_keep_operator "project-keep" @keyword)
(project_reorder_operator "project-reorder" @keyword)
(extend_operator "extend" @keyword)
(summarize_operator "summarize" @keyword)
(join_operator "join" @keyword)
(union_operator "union" @keyword)
(parse_operator "parse" @keyword)
(parse_where_operator "parse-where" @keyword)
(parse_kv_operator "parse-kv" @keyword)
(lookup_operator "lookup" @keyword)
(take_operator "take" @keyword)
(limit_operator "limit" @keyword)
(sort_operator "sort" @keyword)
(sort_operator "order" @keyword)
(distinct_operator "distinct" @keyword)
(render_operator "render" @keyword)
(print_operator "print" @keyword)
(top_operator "top" @keyword)
(count_operator) @keyword
(mv_expand_operator "mv-expand" @keyword)
(mv_expand_operator "mvexpand" @keyword)
(keyword_operator "search" @keyword)
(keyword_operator "find" @keyword)
(keyword_operator "invoke" @keyword)
(evaluate_operator "evaluate" @keyword)
(keyword_operator "serialize" @keyword)
(scan_operator "scan" @keyword)
(keyword_operator "as" @keyword)
(keyword_operator "getschema" @keyword)
(make_series_operator "make-series" @keyword)
(keyword_operator "sample" @keyword)
(sample_distinct_operator "sample-distinct" @keyword)
(mv_apply_operator "mv-apply" @keyword)
(datatable_expression "datatable" @keyword)
(externaldata_expression "externaldata" @keyword)
(externaldata_expression "external_data" @keyword)
(externaldata_expression "with" @keyword)
(range_operator "from" @keyword)
(range_operator "to" @keyword)
(range_operator "step" @keyword)
(project_reorder_operator "asc" @keyword)
(project_reorder_operator "desc" @keyword)
(project_reorder_operator "granny-asc" @keyword)
(project_reorder_operator "granny-desc" @keyword)
(top_nested_clause "of" @keyword)
(top_nested_clause "with" @keyword)
(top_nested_clause "others" @keyword)
(top_nested_clause "by" @keyword)
(sample_distinct_operator "of" @keyword)
(facet_operator "by" @keyword)
(facet_operator "with" @keyword)
(partition_operator "by" @keyword)
(scan_operator "order" @keyword)
(scan_operator "partition" @keyword)
(scan_operator "by" @keyword)
(scan_operator "declare" @keyword)
(scan_operator "with" @keyword)
(scan_step "step" @keyword)
(scan_step "optional" @keyword)
(scan_step "output" @keyword)
(scan_step "last" @keyword)
(range_operator "range" @keyword)
(keyword_operator "externaldata" @keyword)
(partition_operator "partition" @keyword)
(fork_operator "fork" @keyword)
(facet_operator "facet" @keyword)
(keyword_operator "consume" @keyword)
(keyword_operator "reduce" @keyword)
(keyword_operator "make-graph" @keyword)
(keyword_operator "graph-match" @keyword)
(keyword_operator "graph-shortest-paths" @keyword)
(keyword_operator "graph-to-table" @keyword)
(keyword_operator "graph-mark-components" @keyword)
(keyword_operator "top-hitters" @keyword)
(top_nested_clause "top-nested" @keyword)

(mv_expand_operator "limit" @keyword)
(mv_expand_item "to" @keyword)
(mv_expand_item "typeof" @keyword)
(mv_apply_operator "on" @keyword)
(make_series_operator "on" @keyword)
(make_series_operator "from" @keyword)
(make_series_operator "to" @keyword)
(make_series_operator "step" @keyword)
(make_series_operator "by" @keyword)
(sort_item "nulls" @keyword)
(sort_item "first" @keyword)
(sort_item "last" @keyword)
(operator_option name: _ @keyword)
(mv_option name: _ @keyword)
(series_aggregate "default" @keyword)
(hint_option name: (hint_name) @keyword)
(materialize_expression "materialize" @function.builtin)
(toscalar_expression "toscalar" @function.builtin)
(dynamic_literal "dynamic" @type)
(type "dynamic" @type)
(type (identifier) @type)
(parameter name: (identifier) @variable)
(member_expression member: (identifier) @property)
(star) @operator

(control_command "." @error)
(control_command (identifier) @error)

"|" @operator.pipe

(function_call name: (identifier) @function)
(tabular_primary (identifier) @type)
(identifier) @variable
(quoted_identifier) @variable
(string) @string
(number) @number
(boolean) @boolean
(null) @constant
(typed_literal) @constant
(timespan) @number
(comment) @comment

"and" @keyword
"or" @operator
"not" @operator
"==" @operator
"!=" @operator
"=~" @operator
"!~" @operator
"<>" @operator
"<" @operator
">" @operator
"<=" @operator
">=" @operator
"+" @operator
"-" @operator
"*" @operator
"/" @operator
"%" @operator
"has" @operator
"!has" @operator
"has_cs" @operator
"!has_cs" @operator
"has_any" @operator
"has_all" @operator
"contains" @operator
"!contains" @operator
"contains_cs" @operator
"!contains_cs" @operator
"containscs" @operator
"notcontains" @operator
"notcontainscs" @operator
"=>" @operator
"startswith" @operator
"!startswith" @operator
"startswith_cs" @operator
"!startswith_cs" @operator
"endswith" @operator
"!endswith" @operator
"endswith_cs" @operator
"!endswith_cs" @operator
"hasprefix" @operator
"!hasprefix" @operator
"hasprefix_cs" @operator
"!hasprefix_cs" @operator
"hassuffix" @operator
"!hassuffix" @operator
"hassuffix_cs" @operator
"!hassuffix_cs" @operator
"has_ipv4" @operator
"has_ipv4_prefix" @operator
"has_any_ipv4" @operator
"has_any_ipv4_prefix" @operator
"in" @operator
"!in" @operator
"in~" @operator
"!in~" @operator
"between" @operator
"!between" @operator
".." @operator
"matches" @operator
"regex" @operator
"(" @punctuation.bracket
")" @punctuation.bracket
"[" @punctuation.bracket
"]" @punctuation.bracket
"{" @punctuation.bracket
"}" @punctuation.bracket
"," @punctuation.delimiter
"=" @operator
";" @punctuation.delimiter
"by" @keyword
"on" @keyword
"with" @keyword
"kind" @keyword
"asc" @keyword
"desc" @keyword
