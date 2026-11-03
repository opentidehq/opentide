/// <reference types="tree-sitter-cli/dsl" />
// @ts-check

/**
 * Tree-sitter grammar for Falco rule conditions (Falco, Sysdig Secure).
 *
 * Follows the condition grammar of libsinsp's filter parser
 * (falcosecurity/libs, userspace/libsinsp/filter/parser.h): `or` < `and` <
 * `not` (also `not(`), all lower case; a check is a field comparison, a
 * field transformer comparison, a macro name, or a parenthesised expression.
 * A field or macro name starts with a letter; a field name has at least one
 * dot (`proc.name`) and may take an argument (`proc.aname[2]`, `evt.arg.flags`).
 * A string operator may take a modifier (`= anyof (a, b)`). Transformers take
 * fields, transformers, quoted strings, numbers, and transformer lists
 * (`join(",", (proc.name, proc.pname))`), and may take an argument
 * (`getopt(proc.args, "nt:")[t]`). A tuning's condition is a fragment that
 * starts with `and` or `or` (`append_fragment`).
 *
 * This grammar drives highlighting and editor structure. Diagnostics come
 * from the engine's port of libsinsp's parser (crates/opentide-falco/src/parser.rs),
 * which follows libsinsp's lexing exactly.
 */
module.exports = grammar({
  name: "opentide_falco",

  extras: (_) => [/[ \t\r\n\f\x08]/],

  word: ($) => $.identifier,

  rules: {
    source_file: ($) => optional(choice($._expression, $.append_fragment)),

    append_fragment: ($) =>
      seq(field("operator", choice("and", "or")), field("right", $._expression)),

    _expression: ($) =>
      choice($.or_expression, $.and_expression, $.not_expression, $._check),

    or_expression: ($) =>
      prec.left(1, seq(field("left", $._expression), "or", field("right", $._expression))),

    and_expression: ($) =>
      prec.left(2, seq(field("left", $._expression), "and", field("right", $._expression))),

    not_expression: ($) =>
      prec(3, seq("not", field("operand", choice($.not_expression, $._check)))),

    _check: ($) =>
      choice($.parenthesized_expression, $.comparison, $.macro_reference),

    parenthesized_expression: ($) => seq("(", $._expression, ")"),

    macro_reference: ($) => $.identifier,

    comparison: ($) =>
      choice(
        seq(field("left", $._operand), field("operator", $.unary_operator)),
        seq(
          field("left", $._operand),
          field("operator", $.comparison_operator),
          field("right", choice($._value, $.value_transformer, $.field_transformer)),
        ),
        // libsinsp reads a modifier only when a list or a list name follows,
        // so `= anyof` alone compares with the string "anyof".
        seq(
          field("left", $._operand),
          field("operator", $.comparison_operator),
          field("modifier", alias($.bare_string, $.operator_modifier)),
          field("right", choice($.value_list, $.list_reference)),
        ),
        seq(
          field("left", $._operand),
          field("operator", $.list_operator),
          field(
            "right",
            choice($.value_list, $.list_reference, $.value_transformer, $.field_transformer),
          ),
        ),
      ),

    _operand: ($) => choice($.field, $.field_transformer),

    field: ($) =>
      seq(field("name", $.field_name), optional(field("argument", $.field_argument))),

    field_name: (_) => token(/[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+/),

    field_argument: ($) =>
      seq(token.immediate("["), choice($.quoted_string, $.argument_value), "]"),

    argument_value: (_) => token(/[^\s\[\]"']+/),

    // libsinsp lexes `tolower(` as one token: `tolower` alone is a value.
    field_transformer: ($) =>
      seq(
        field("name", $.transformer_name),
        field("argument", $._transformer_arg),
        repeat(seq(",", field("argument", $._transformer_arg))),
        ")",
        optional(field("field_argument", $.field_argument)),
      ),

    _transformer_arg: ($) =>
      choice($.field_transformer, $.field, $.quoted_string, $.number, $.transformer_list),

    transformer_list: ($) =>
      seq(
        "(",
        optional(
          seq(
            $._transformer_list_arg,
            repeat(seq(",", $._transformer_list_arg)),
          ),
        ),
        ")",
      ),

    _transformer_list_arg: ($) =>
      choice($.field, $.field_transformer, $.quoted_string, $.number),

    transformer_name: (_) =>
      token(
        choice(
          "tolower(",
          "toupper(",
          "b64(",
          "basename(",
          "len(",
          "join(",
          "concat(",
          "getopt(",
        ),
      ),

    value_transformer: ($) =>
      seq(
        field("name", alias("val(", $.transformer_name)),
        field("argument", $.field),
        ")",
        optional(field("field_argument", $.field_argument)),
      ),

    // A regex, not a keyword: libsinsp matches `exists` as a prefix
    // (`proc.name existsand macro` is `exists` then `and`).
    unary_operator: (_) => token(/exists/),

    comparison_operator: (_) =>
      choice(
        "=",
        "==",
        "!=",
        "<",
        "<=",
        ">",
        ">=",
        "contains",
        "icontains",
        "bcontains",
        "startswith",
        "bstartswith",
        "endswith",
        "glob",
        "iglob",
        "regex",
      ),

    list_operator: (_) => choice("in", "intersects", "pmatch"),

    value_list: ($) =>
      seq("(", optional(seq($._value, repeat(seq(",", $._value)))), ")"),

    list_reference: ($) => $.identifier,

    // A number in a value position is a bare string to libsinsp's lexer
    // (`0a!@#` is one value); `number` is for transformer arguments.
    _value: ($) => choice($.quoted_string, $.bare_string),

    number: (_) =>
      token(choice(/0[xX][0-9a-fA-F]+/, /[+-]?[0-9]+(\.[0-9]*)?([eE][+-][0-9]+)?/)),

    bare_string: (_) => token(/[^\s(),="']+/),

    // libsinsp: a quote preceded by a backslash never closes the string.
    quoted_string: (_) =>
      token(
        choice(
          seq('"', repeat(choice(/[^"\\]/, /\\+[^"\\]/, /\\+"/)), '"'),
          seq("'", repeat(choice(/[^'\\]/, /\\+[^'\\]/, /\\+'/)), "'"),
        ),
      ),

    identifier: (_) => /[A-Za-z][A-Za-z0-9_]*/,
  },
});
