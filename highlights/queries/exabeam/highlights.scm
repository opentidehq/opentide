; Exabeam Query Language highlights (exabeam-1.0, "Highlighting"). Capture
; names are a subset of highlights/spec.toml; the language adds none.
; Specific patterns come before the broad ones (first-wins).

; Functions: the four filter functions and the aggregations are built in;
; any other name is an error, as is a filter-function argument that is not a
; string.
((call name: (identifier) @function.builtin)
  (#match? @function.builtin "^([rR][gG][xX]|[wW][lL][dD])[iI]?$"))
(call name: (identifier) @error)
(call argument: (string) @string)
(call argument: (_) @error)
((aggregate name: (identifier) @function.builtin)
  (#match? @function.builtin "^([cC][oO][uU][nN][tT]|[mM][iI][nN]|[mM][aA][xX]|[sS][uU][mM]|[aA][vV][gG]|[rR][gG][xX]_[eE][xX][tT][rR][aA][cC][tT])$"))
(aggregate name: (identifier) @error)
(aggregate (field_name) @property)

; Fields, context tables, names.
(field_term field: (field_name) @property)
(context_term field: (field_name) @property)
(context_table) @type
(column field: (field_name) @property)
(column alias: (alias) @variable)
(group_by_clause (field_name) @property)
(order_by_clause (field_name) @property)
(foreach_statement field: (field_name) @property)
(table_name) @type

; Values.
((field_term value: (identifier) @boolean)
  (#match? @boolean "^([tT][rR][uU][eE]|[fF][aA][lL][sS][eE])$"))
((field_term value: (identifier) @constant)
  (#match? @constant "^[nN][uU][lL][lL]$"))
((field_term value: (bare_word) @variable)
  (#match? @variable "^@"))
((field_term value: (bare_word) @constant)
  (#match? @constant "^([0-9]{1,3}(\\.[0-9]{1,3}){3}|[0-9A-Fa-f]*:[0-9A-Fa-f:.]*(%[^%]+)?)$"))
(field_term value: (number) @number)
(field_term value: (identifier) @string)
(field_term value: (bare_word) @string)
((list (identifier) @boolean)
  (#match? @boolean "^([tT][rR][uU][eE]|[fF][aA][lL][sS][eE])$"))
((list (identifier) @constant)
  (#match? @constant "^[nN][uU][lL][lL]$"))
((list (bare_word) @variable)
  (#match? @variable "^@"))
((list (bare_word) @constant)
  (#match? @constant "^([0-9]{1,3}(\\.[0-9]{1,3}){3}|[0-9A-Fa-f]*:[0-9A-Fa-f:.]*(%[^%]+)?)$"))
(list (number) @number)
(list (identifier) @string)
(list (bare_word) @string)
((range (bound) @number)
  (#match? @number "^[+-]?[0-9]+(\\.[0-9]+)?$"))
(range (bound) @constant)
((free_text (text_word) @error)
  (#eq? @error "*"))
(free_text) @string
(limit_clause (number) @number)
(string) @string
(number) @number

(not_equal) @error
(star) @operator

"AND" @keyword
"OR" @keyword
"NOT" @keyword
"TO" @keyword
"IN" @keyword
"SELECT" @keyword
"DISTINCT" @keyword
"FROM" @keyword
"WHERE" @keyword
"AS" @keyword
"GROUP-BY" @keyword
"ORDER-BY" @keyword
"ASC" @keyword
"DESC" @keyword
"LIMIT" @keyword
"FOREACH" @keyword

":" @operator
"=" @operator
"==" @operator
"<" @operator
">" @operator
"<=" @operator
">=" @operator
"|" @operator.pipe

"(" @punctuation.bracket
")" @punctuation.bracket
"[" @punctuation.bracket
"]" @punctuation.bracket
"{" @punctuation.bracket
"}" @punctuation.bracket
"," @punctuation.delimiter
"." @punctuation.delimiter
