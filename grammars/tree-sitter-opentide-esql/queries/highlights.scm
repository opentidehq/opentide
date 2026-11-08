; ES|QL highlights. Capture names must be subset of highlights/spec.toml.
; Specific captures are listed before the broad identifier patterns (first-wins).

(unknown_command name: (command_name) @error)

(function_call name: (identifier) @function)
(function_call name: (parameter) @function)
(type_name (identifier) @type)
(qualified_interval unit: (time_unit) @constant)
(index_name) @type
(cluster) @type
(selector) @constant
(metadata_field) @constant
(enrich_policy name: (policy_name) @type)
(enrich_policy mode: (enrich_mode) @constant)
(command_option name: (identifier) @keyword)
(fuse_command method: (identifier) @constant)
(star) @operator
(promql_text) @string
(unknown_text) @string

(qualified_name (identifier) @property)
(qualified_name (quoted_identifier) @property)
(name_pattern (id_pattern) @property)
(name_pattern (quoted_identifier) @property)
(identifier) @variable
(quoted_identifier) @variable

(string) @string
(number) @number
(boolean) @boolean
(null) @constant
(parameter) @constant
(comment) @comment

"|" @operator.pipe

"from" @keyword
"ts" @keyword
"row" @keyword
"show" @keyword
"info" @keyword
"explain" @keyword
"promql" @keyword
"set" @keyword
"metadata" @keyword
"where" @keyword
"eval" @keyword
"keep" @keyword
"drop" @keyword
"rename" @keyword
"as" @keyword
"sort" @keyword
"asc" @keyword
"desc" @keyword
"nulls" @keyword
"first" @keyword
"last" @keyword
"limit" @keyword
"stats" @keyword
"inline" @keyword
"inlinestats" @keyword
"by" @keyword
"dissect" @keyword
"grok" @keyword
"enrich" @keyword
"on" @keyword
"with" @keyword
"mv_expand" @keyword
"lookup" @keyword
"left" @keyword
"right" @keyword
"full" @keyword
"join" @keyword
"change_point" @keyword
"completion" @keyword
"rerank" @keyword
"sample" @keyword
"fork" @keyword
"fuse" @keyword
"score" @keyword
"key" @keyword
"group" @keyword
"uri_parts" @keyword
"registered_domain" @keyword
"user_agent" @keyword
"ip_location" @keyword
"metrics_info" @keyword
"ts_info" @keyword
"ts_collapse" @keyword
"dedup" @keyword
"mmr" @keyword
"highlight" @keyword
"dense_vector" @keyword
"fillnull" @keyword

"and" @keyword
"or" @keyword
"not" @keyword
"in" @keyword
"is" @keyword
"like" @keyword
"rlike" @keyword

"==" @operator
"!=" @operator
"<" @operator
"<=" @operator
">" @operator
">=" @operator
"+" @operator
"-" @operator
"*" @operator
"/" @operator
"%" @operator
"=" @operator
"::" @operator
":" @operator
"(" @punctuation.bracket
")" @punctuation.bracket
"[" @punctuation.bracket
"]" @punctuation.bracket
"{" @punctuation.bracket
"}" @punctuation.bracket
"," @punctuation.delimiter
"." @punctuation.delimiter
";" @punctuation.delimiter
