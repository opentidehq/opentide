; YARA-L 2.0 highlights (yara-l-1.0 "Highlighting"). Capture names must be a
; subset of highlights/spec.toml; YARA-L adds none. Specific captures come
; before the broad ones (first-wins).

(comment) @comment

; The rule name, meta and option keys.
(rule_declaration name: (rule_name) @type)
(stage name: (stage_name) @type)
(meta_key) @property
(option_key) @property

; Outcome names with platform meaning, before every other variable.
((variable) @constant
  (#match? @constant "^\\$(risk_score|risk_entity_to_score(_[A-Za-z0-9_]+)?|suppression_key)$"))
(variable) @variable
(count) @variable

; UDM path segments, data table columns, named arguments.
(field_name) @property
(data_table_column column: (column) @property)
(argument_name) @property

; Reference lists and data tables, window bounds.
(reference_list) @constant
(window_bound) @constant

; Functions: the namespace is a type, the function a builtin.
(function_name namespace: (namespace) @type)
(function_name name: (name) @function.builtin)
(table_call function: (name) @function.builtin)

; Literals.
(string) @string
(raw_string) @string
(regex) @string
(integer) @number
(float) @number
(duration) @number
(boolean) @boolean
(time_unit) @keyword

"rule" @keyword
"meta" @keyword
"setup" @keyword
"events" @keyword
"match" @keyword
"outcome" @keyword
"condition" @keyword
"options" @keyword
"export" @keyword
"dedup" @keyword
"order" @keyword
"limit" @keyword
"select" @keyword
"unselect" @keyword
"stage" @keyword
"and" @keyword
"or" @keyword
"not" @keyword
"nocase" @keyword
"in" @keyword
"regex" @keyword
"cidr" @keyword
"any" @keyword
"all" @keyword
"of" @keyword
"over" @keyword
"by" @keyword
"before" @keyword
"after" @keyword
"every" @keyword
"first" @keyword
"if" @keyword
"asc" @keyword
"desc" @keyword
"cross" @keyword
"join" @keyword
"graph_override" @keyword
"graph_append" @keyword
"graph_exclude" @keyword

"=" @operator
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
"!" @operator
(wildcard) @operator

"(" @punctuation.bracket
")" @punctuation.bracket
"[" @punctuation.bracket
"]" @punctuation.bracket
"{" @punctuation.bracket
"}" @punctuation.bracket
"," @punctuation.delimiter
":" @punctuation.delimiter
"." @punctuation.delimiter

; A bare name: a search's grouped field (`ip`), `raw`, a metric field.
(identifier) @property
