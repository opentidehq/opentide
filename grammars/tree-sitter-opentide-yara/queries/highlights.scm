; YARA highlights. Capture names must be a subset of highlights/spec.toml.
; Specific captures are listed before the broad patterns (first-wins).

(comment) @comment

; Rules, tags, meta keys.
(rule name: (identifier) @type)
(tag (identifier) @constant)
(rule_set (identifier) @type)
(rule_wildcard) @type
(meta_definition key: (identifier) @property)

; Strings and their uses: identifiers, wildcards, counts, offsets, lengths.
(string_identifier) @variable
(string_wildcard) @variable
(string_count) @variable
(string_offset) @variable
(string_length) @variable
(loop_variables (identifier) @variable)

; uint16(0), int32be(0): libyara's integer readers.
((call_expression
  function: (identifier) @function.builtin)
  (#match? @function.builtin "^u?int(8|16|32)(be)?$"))
; pe.exports("x"), math.entropy(0, filesize).
(call_expression
  function: (member_expression member: (identifier) @function))
(call_expression function: (identifier) @function)
; The module: pe in pe.number_of_sections.
(member_expression object: (identifier) @type)
(member_expression member: (identifier) @property)

; Modifiers.
(rule_modifier) @keyword
(string_modifier) @keyword
"xor" @keyword
"base64" @keyword
"base64wide" @keyword

; Hex strings.
(hex_byte) @number
(hex_jump_bound) @number
(hex_not "~" @operator)

; Literals.
(text_string) @string
(regexp) @string
(integer) @number
(float) @number
(boolean) @boolean
(filesize) @constant
(entrypoint) @constant
(them) @keyword
(quantifier_keyword) @keyword

"rule" @keyword
"meta" @keyword
"strings" @keyword
"condition" @keyword
"import" @keyword
"include" @keyword
"and" @keyword
"or" @keyword
"not" @keyword
"defined" @keyword
"at" @keyword
"in" @keyword
"of" @keyword
"for" @keyword
"matches" @keyword
"contains" @keyword
"icontains" @keyword
"startswith" @keyword
"istartswith" @keyword
"endswith" @keyword
"iendswith" @keyword
"iequals" @keyword

"==" @operator
"!=" @operator
"<" @operator
"<=" @operator
">" @operator
">=" @operator
"+" @operator
"-" @operator
"*" @operator
"\\" @operator
"%" @operator
"&" @operator
"|" @operator
"^" @operator
"~" @operator
"<<" @operator
">>" @operator
"=" @operator
".." @operator

"(" @punctuation.bracket
")" @punctuation.bracket
"[" @punctuation.bracket
"]" @punctuation.bracket
"{" @punctuation.bracket
"}" @punctuation.bracket
"," @punctuation.delimiter
":" @punctuation.delimiter
"." @punctuation.delimiter

(identifier) @variable
