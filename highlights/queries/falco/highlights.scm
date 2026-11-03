; Falco condition highlights. Capture names must be a subset of highlights/spec.toml.
; Specific captures are listed before the broad literal patterns (first-wins).

(field name: (field_name) @property)
(field_argument (argument_value) @string)
(field_argument (quoted_string) @string)
(transformer_name) @function.builtin
(macro_reference (identifier) @macro)
(list_reference (identifier) @variable)

(comparison_operator) @operator
(list_operator) @keyword
(unary_operator) @keyword
(operator_modifier) @keyword

((bare_string) @boolean
  (#match? @boolean "^(true|false)$"))
((bare_string) @number
  (#match? @number "^([+-]?[0-9]+([.][0-9]*)?([eE][+-][0-9]+)?|0[xX][0-9a-fA-F]+)$"))
(number) @number
(quoted_string) @string
(bare_string) @string

"and" @keyword
"or" @keyword
"not" @keyword

"(" @punctuation.bracket
")" @punctuation.bracket
"[" @punctuation.bracket
"]" @punctuation.bracket
"," @punctuation.delimiter
