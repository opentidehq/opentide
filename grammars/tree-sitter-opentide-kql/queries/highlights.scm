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
(keyword_operator "evaluate" @keyword)
(keyword_operator "serialize" @keyword)
(keyword_operator "scan" @keyword)
(keyword_operator "as" @keyword)
(keyword_operator "getschema" @keyword)
(keyword_operator "make-series" @keyword)
(keyword_operator "sample" @keyword)
(keyword_operator "sample-distinct" @keyword)
(keyword_operator "mv-apply" @keyword)
(keyword_operator "datatable" @keyword)
(keyword_operator "range" @keyword)
(keyword_operator "externaldata" @keyword)
(keyword_operator "partition" @keyword)
(keyword_operator "fork" @keyword)
(keyword_operator "facet" @keyword)
(keyword_operator "consume" @keyword)
(keyword_operator "reduce" @keyword)
(keyword_operator "make-graph" @keyword)
(keyword_operator "graph-match" @keyword)
(keyword_operator "graph-shortest-paths" @keyword)
(keyword_operator "graph-to-table" @keyword)
(keyword_operator "graph-mark-components" @keyword)
(keyword_operator "top-hitters" @keyword)
(keyword_operator "top-nested" @keyword)

(control_command "." @error)
(control_command (identifier) @error)

"|" @operator.pipe

(function_call name: (identifier) @function)
(tabular_primary (identifier) @type)
(identifier) @variable
(string) @string
(number) @number
(boolean) @boolean
(null) @constant
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
"matches" @operator
"regex" @operator
"(" @punctuation.bracket
")" @punctuation.bracket
"," @punctuation.delimiter
"=" @operator
";" @punctuation.delimiter
"by" @keyword
"on" @keyword
"with" @keyword
"kind" @keyword
"asc" @keyword
"desc" @keyword
