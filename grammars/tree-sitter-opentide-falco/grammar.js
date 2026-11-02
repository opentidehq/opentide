/// <reference types="tree-sitter-cli/dsl" />
// @ts-check

/**
 * Tree-sitter grammar for Falco rule conditions (Falco, Sysdig Secure).
 *
 * Follows the condition grammar of libsinsp's filter parser
 * (falcosecurity/libs, userspace/libsinsp/filter/parser.h):
 * `or` < `and` < `not`, all lower case; a check is a field comparison, a
 * field transformer comparison, a macro name, or a parenthesised expression.
 * A field name has at least one dot (`proc.name`) and may take an argument
 * (`proc.aname[2]`, `evt.arg.flags`); a bare name is a macro, or a list
 * inside a value list. A tuning's condition is a fragment that starts with
 * `and` or `or` (`append_fragment`), appended to the tuned rule's condition.
 */
module.exports = grammar({
  name: "opentide_falco",

  extras: (_) => [/[ \t\r\n\f]/],

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
          field("right", choice($._value, $.value_transformer)),
        ),
        seq(
          field("left", $._operand),
          field("operator", $.list_operator),
          field("right", choice($.value_list, $.list_reference, $.value_transformer)),
        ),
      ),

    _operand: ($) => choice($.field, $.field_transformer),

    field: ($) =>
      seq(field("name", $.field_name), optional(field("argument", $.field_argument))),

    field_name: (_) =>
      token(/[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)+/),

    field_argument: ($) =>
      seq(
        token.immediate("["),
        optional(choice($.quoted_string, $.argument_value)),
        "]",
      ),

    argument_value: (_) => token(/[^\s\[\]"']+/),

    field_transformer: ($) =>
      seq(
        field("name", $.transformer_name),
        token.immediate("("),
        field("argument", choice($.field_transformer, $.field)),
        ")",
      ),

    transformer_name: (_) => choice("tolower", "toupper", "b64", "basename", "len"),

    value_transformer: ($) =>
      seq(field("name", alias("val", $.transformer_name)), token.immediate("("), field("argument", $.field), ")"),

    unary_operator: (_) => "exists",

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

    _value: ($) => choice($.quoted_string, $.number, $.bare_string),

    number: (_) =>
      token(
        prec(1, choice(/0[xX][0-9a-fA-F]+/, /[+-]?[0-9]+(\.[0-9]*)?([eE][+-][0-9]+)?/)),
      ),

    bare_string: (_) => token(/[^\s(),="']+/),

    quoted_string: (_) =>
      token(
        choice(
          seq('"', repeat(choice(/[^"\\]/, /\\./)), '"'),
          seq("'", repeat(choice(/[^'\\]/, /\\./)), "'"),
        ),
      ),

    identifier: (_) => /[A-Za-z_][A-Za-z0-9_]*/,
  },
});
