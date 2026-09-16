; SPL highlights. Capture names must be subset of highlights/spec.toml.
; Specific captures are listed before (identifier) @variable (first-wins).

(search_command "search" @keyword)
(where_command "where" @keyword)
(eval_command "eval" @keyword)
(stats_command "stats" @keyword)
(rex_command "rex" @keyword)
(table_command "table" @keyword)
(rename_command "rename" @keyword)
(fields_command "fields" @keyword)
(dedup_command "dedup" @keyword)
(sort_command "sort" @keyword)
(head_command "head" @keyword)
(tail_command "tail" @keyword)
(join_command "join" @keyword)
(lookup_command "lookup" @keyword)
(makemv_command "makemv" @keyword)
(mvexpand_command "mvexpand" @keyword)
(tstats_command "tstats" @keyword)
(catalog_command (catalog_command_name) @keyword)
(unknown_command name: (identifier) @error)

"|" @operator.pipe

(function_call name: (identifier) @function)
(field_value field: (identifier) @property)
(assignment name: (identifier) @variable)
(identifier) @variable
(string) @string
(number) @number
(boolean) @boolean
(comment) @comment

"AND" @operator
"OR" @operator
"NOT" @operator
"and" @operator
"or" @operator
"not" @operator
"AS" @keyword
"by" @keyword
"from" @keyword
"(" @punctuation.bracket
")" @punctuation.bracket
"[" @punctuation.bracket
"]" @punctuation.bracket
"," @punctuation.delimiter
"=" @operator
"==" @operator
"!=" @operator
"LIKE" @operator
"IN" @operator

"timechart" @keyword
"chart" @keyword
"eventstats" @keyword
"streamstats" @keyword
"transaction" @keyword
"spath" @keyword
"regex" @keyword
"fillnull" @keyword
"bin" @keyword
"append" @keyword
"inputlookup" @keyword
"makeresults" @keyword
"outputlookup" @keyword
"foreach" @keyword
"top" @keyword
"rare" @keyword
"extract" @keyword
"convert" @keyword
"strcat" @keyword
"metadata" @keyword
"rest" @keyword
"from" @keyword
"union" @keyword
"map" @keyword
"reverse" @keyword
"table" @keyword
