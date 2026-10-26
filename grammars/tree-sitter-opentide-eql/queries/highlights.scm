; EQL highlights. Capture names must be subset of highlights/spec.toml.
; Specific captures are listed before the broad identifier patterns (first-wins).

(relationship relation: (identifier) @error)
(pipe name: (identifier) @keyword)
(term_option key: (identifier) @keyword)
(time_unit unit: (identifier) @constant)
(event_category (identifier) @type)
(event_category (string) @type)
(any) @type
(function_call name: (identifier) @function)
(function_call name: (case_insensitive_name) @function)
(field (identifier) @property)
(field (quoted_identifier) @property)
(index) @number
(optional_marker) @operator
(missing_event_open) @operator
(identifier) @variable
(quoted_identifier) @variable

(string) @string
(number) @number
(boolean) @boolean
(null) @constant
(comment) @comment

"|" @operator.pipe

"sequence" @keyword
"sample" @keyword
"join" @keyword
"by" @keyword
"with" @keyword
"maxspan" @keyword
"until" @keyword
"where" @keyword
"of" @keyword

"and" @keyword
"or" @keyword
"not" @keyword
"in" @operator
"in~" @operator
"like" @operator
"like~" @operator
"regex" @operator
"regex~" @operator
":" @operator
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
"(" @punctuation.bracket
")" @punctuation.bracket
"[" @punctuation.bracket
"]" @punctuation.bracket
"," @punctuation.delimiter
"." @punctuation.delimiter
