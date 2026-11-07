; Kibana KQL (kuery) highlights. Capture names must be subset of highlights/spec.toml.
; Specific captures are listed before the broad literal patterns (first-wins).

(field (unquoted_literal (word) @property))
(field (quoted_string) @property)

((word) @boolean
  (#match? @boolean "^([tT][rR][uU][eE]|[fF][aA][lL][sS][eE])$"))
((word) @constant
  (#match? @constant "^[nN][uU][lL][lL]$"))
((word) @number
  (#match? @number "^-?[0-9]+(\\.[0-9]+)?$"))
(word) @string
(quoted_string) @string

(or) @keyword
(and) @keyword
(not) @keyword

":" @operator
"<" @operator
"<=" @operator
">" @operator
">=" @operator
"(" @punctuation.bracket
")" @punctuation.bracket
"{" @punctuation.bracket
"}" @punctuation.bracket
