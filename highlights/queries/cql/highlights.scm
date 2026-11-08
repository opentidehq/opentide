; CrowdStrike Query Language (CQL) highlights. Capture names must be a subset
; of highlights/spec.toml. Specific captures are listed before the broad
; literal patterns (first-wins), and a construct's parts are captured rather
; than the whole construct, because the shorter span at the same start wins.

(line_comment) @comment
(block_comment) @comment

; Saved queries `$name(...)` and query parameters `?name`, `?{name=default}`.
(saved_query "$" @macro)
(saved_query name: (_) @macro)
(query_parameter "?" @macro)
(query_parameter "?{" @macro)
(query_parameter name: (_) @macro)

(function_call name: (function_name) @function)

; Field names: `#tags`, then names on the left of an operator, then field
; references in expressions.
(tag) @type
(field_filter field: (field_name) @property)
(field_filter field: (string) @property)
(assignment field: (field_name) @property)
(assignment field: (string) @property)
(field_shorthand field: (field_name) @property)
(field_shorthand field: (string) @property)
(match_statement field: (field_name) @property)
(match_statement field: (string) @property)
(link_constraint left: (field_name) @property)
(link_constraint right: (field_name) @property)

(named_argument name: (argument_name) @variable)
(named_argument name: (string) @variable)
(saved_query_argument name: (argument_name) @variable)
(saved_query_argument name: (string) @variable)
(named_subquery name: (identifier) @variable)
(expression_attribute name: (identifier) @variable)

; A bareword argument such as `span=5min` is a duration.
((field_name) @number
  (#match? @number "^[0-9]+(ms|millis|milliseconds?|s|secs?|seconds?|m|mins?|minutes?|h|hrs?|hours?|d|days?|w|weeks?|mon|months?|q|qtrs?|quarters?|y|yrs?|years?)$"))
(field_name) @property

(regex "/" @string)
(regex_pattern) @string
(regex_flags) @constant

((unquoted_pattern) @number
  (#match? @number "^-?[0-9]+([.][0-9]+)?([eE][+-]?[0-9]+)?$"))
(unquoted_pattern) @string
(string) @string
(number) @number
(boolean) @boolean

(and) @keyword
(or) @keyword
(not) @keyword
"case" @keyword
"match" @keyword
"like" @keyword

"|" @operator.pipe

"=" @operator
"!=" @operator
"<" @operator
"<=" @operator
">" @operator
">=" @operator
"==" @operator
"<=>" @operator
":=" @operator
"=~" @operator
"=>" @operator
"!" @operator
"+" @operator
"-" @operator
"*" @operator
"/" @operator
"%" @operator

"(" @punctuation.bracket
")" @punctuation.bracket
"[" @punctuation.bracket
"]" @punctuation.bracket
"{" @punctuation.bracket
"}" @punctuation.bracket
"," @punctuation.delimiter
";" @punctuation.delimiter
":" @punctuation.delimiter
