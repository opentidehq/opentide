; Lucene query syntax highlights. Capture names must be subset of highlights/spec.toml.
; Specific captures are listed before the broad term patterns (first-wins).

(field_name) @property
(star) @operator
(range_query lower: (range_term) @number)
(range_query upper: (range_term) @number)
(regexp) @string
(phrase) @string
(wildcard_term) @string
(bare_operator) @string
(term) @string
(boost) @number
(fuzzy) @number

(and) @keyword
(or) @keyword
(not) @keyword
(required) @operator
(prohibited) @operator
"TO" @keyword

":" @operator
"(" @punctuation.bracket
")" @punctuation.bracket
"[" @punctuation.bracket
"]" @punctuation.bracket
"{" @punctuation.bracket
"}" @punctuation.bracket
