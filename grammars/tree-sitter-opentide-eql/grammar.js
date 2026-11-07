/// <reference types="tree-sitter-cli/dsl" />
// @ts-check

/**
 * Tree-sitter grammar for Elasticsearch Event Query Language (EQL), as used
 * by Elastic Security `eql` detection rules.
 *
 * Covers the EQL Elasticsearch accepts from 8.19 through 9.x (the language
 * has not changed in that range). Keywords are lower case and reserved.
 * `join`, lineage (`descendant of [...]`), array indexes, and unknown pipes
 * parse so the engine can name them; Elasticsearch rejects them.
 */
const PREC = {
  or: 1,
  and: 2,
  not: 3,
  comparison: 4,
  additive: 5,
  multiplicative: 6,
  unary: 7,
  predicate: 8,
};

module.exports = grammar({
  name: "opentide_eql",

  extras: ($) => [/\s/, $.comment],

  word: ($) => $.identifier,

  // Elasticsearch reserves every keyword, in lower case only: `process where
  // like == 1` is a syntax error, and `AND` is an identifier.
  reserved: {
    global: (_) => [
      "and", "any", "by", "false", "in", "join", "like", "maxspan", "not",
      "null", "of", "or", "regex", "sample", "sequence", "true", "until",
      "where", "with",
    ],
  },

  rules: {
    source_file: ($) =>
      optional(seq(field("query", $._query), repeat(field("pipe", $.pipe)))),

    _query: ($) =>
      choice($.sequence, $.sample, $.join, $.event_query),

    event_query: ($) => $._event_filter,

    _event_filter: ($) =>
      seq(
        field("category", choice($.any, $.event_category)),
        "where",
        field("condition", $._expression),
      ),

    any: (_) => "any",

    event_category: ($) => choice($.identifier, $.string),

    sequence: ($) =>
      seq(
        "sequence",
        optional(
          choice(
            seq(field("by", $.join_keys), optional($.sequence_params)),
            seq($.sequence_params, optional(field("by", $.join_keys))),
          ),
        ),
        repeat1(field("term", $.sequence_term)),
        optional(seq("until", field("until", $.sequence_term))),
      ),

    sequence_params: ($) =>
      seq("with", "maxspan", "=", field("maxspan", $.time_unit)),

    time_unit: ($) =>
      seq(field("value", $.number), optional(field("unit", $.identifier))),

    sample: ($) =>
      seq(
        "sample",
        optional(field("by", $.join_keys)),
        repeat1(field("term", $.join_term)),
      ),

    join: ($) =>
      seq(
        "join",
        optional(field("by", $.join_keys)),
        field("term", $.join_term),
        repeat1(field("term", $.join_term)),
        optional(seq("until", field("until", $.join_term))),
      ),

    join_keys: ($) => seq("by", commaSep1($._expression)),

    join_term: ($) => seq($.subquery, optional(field("by", $.join_keys))),

    sequence_term: ($) =>
      seq(
        $.subquery,
        optional(field("by", $.join_keys)),
        optional($.term_option),
      ),

    term_option: ($) =>
      seq("with", field("key", $.identifier), "=", field("value", $.number)),

    subquery: ($) =>
      seq(
        field("open", choice("[", $.missing_event_open)),
        $._event_filter,
        "]",
      ),

    missing_event_open: (_) => "![",

    pipe: ($) =>
      seq(
        "|",
        field("name", $.identifier),
        optional(field("arguments", commaSep1($._expression))),
      ),

    _expression: ($) =>
      choice(
        $.or_expression,
        $.and_expression,
        $.not_expression,
        $.relationship,
        $._value_expression,
      ),

    or_expression: ($) =>
      prec.left(PREC.or, seq(field("left", $._expression), "or", field("right", $._expression))),

    and_expression: ($) =>
      prec.left(PREC.and, seq(field("left", $._expression), "and", field("right", $._expression))),

    not_expression: ($) => prec(PREC.not, seq("not", field("operand", $._expression))),

    relationship: ($) =>
      seq(field("relation", $.identifier), "of", field("subquery", $.subquery)),

    _value_expression: ($) => choice($.comparison, $._operator_expression),

    comparison: ($) =>
      prec.left(
        PREC.comparison,
        seq(
          field("left", $._operator_expression),
          field("operator", choice("==", "!=", "<", "<=", ">", ">=")),
          field("right", $._operator_expression),
        ),
      ),

    _operator_expression: ($) =>
      choice($.predicate_expression, $.unary_expression, $.binary_expression, $._primary_expression),

    unary_expression: ($) =>
      prec(PREC.unary, seq(field("operator", choice("-", "+")), field("operand", $._operator_expression))),

    binary_expression: ($) =>
      choice(
        prec.left(
          PREC.multiplicative,
          seq(field("left", $._operator_expression), field("operator", choice("*", "/", "%")), field("right", $._operator_expression)),
        ),
        prec.left(
          PREC.additive,
          seq(field("left", $._operator_expression), field("operator", choice("+", "-")), field("right", $._operator_expression)),
        ),
      ),

    predicate_expression: ($) =>
      prec(
        PREC.predicate,
        seq(
          field("subject", $._primary_expression),
          choice(
            seq(
              optional(field("negated", "not")),
              field("operator", choice("in", "in~")),
              "(",
              field("values", commaSep1($._expression)),
              ")",
            ),
            seq(
              field("operator", choice(":", "like", "like~", "regex", "regex~")),
              choice(
                field("values", $._constant),
                seq("(", field("values", commaSep1($._constant)), ")"),
              ),
            ),
          ),
        ),
      ),

    _primary_expression: ($) =>
      choice(
        $._constant,
        $.function_call,
        $.field,
        $.parenthesized_expression,
      ),

    parenthesized_expression: ($) => seq("(", $._expression, ")"),

    function_call: ($) =>
      seq(
        field("name", choice($.identifier, $.case_insensitive_name)),
        "(",
        optional(field("arguments", commaSep1($._expression))),
        ")",
      ),

    case_insensitive_name: (_) => /[A-Za-z][A-Za-z0-9_]*~/,

    field: ($) =>
      prec.right(
        seq(
          optional(field("optional", $.optional_marker)),
          $._name_part,
          repeat(choice(seq(".", $._name_part), $.index)),
        ),
      ),

    optional_marker: (_) => "?",

    _name_part: ($) => choice($.identifier, $.quoted_identifier),

    index: (_) => token(seq("[", repeat1(seq(/\s*/, /[0-9]+/)), /\s*/, "]")),

    _constant: ($) => choice($.null, $.number, $.boolean, $.string),

    null: (_) => "null",

    boolean: (_) => choice("true", "false"),

    number: (_) =>
      token(
        choice(
          /[0-9]+/,
          /[0-9]+\.[0-9]*([eE][+-]?[0-9]+)?/,
          /\.[0-9]+([eE][+-]?[0-9]+)?/,
          /[0-9]+[eE][+-]?[0-9]+/,
        ),
      ),

    string: (_) =>
      token(
        choice(
          seq('"""', /([^\r\n"]|"[^\r\n"]|""[^\r\n"])*/, '"""', optional('"'), optional('"')),
          seq('"', repeat(choice(/[^"\\\r\n]/, /\\u\{[0-9A-Fa-f]+\}/, /\\[btnfr"'\\]/, /\\./)), '"'),
          seq("'", repeat(choice(/[^'\\\r\n]/, /\\./)), "'"),
          seq('?"', repeat(choice(/[^"\\\r\n]/, '\\"', /\\/)), '"'),
          seq("?'", repeat(choice(/[^'\\\r\n]/, "\\'", /\\/)), "'"),
        ),
      ),

    identifier: (_) => /[A-Za-z_@][A-Za-z0-9_]*/,

    quoted_identifier: (_) => token(seq("`", repeat(choice(/[^`]/, "``")), "`")),

    comment: (_) =>
      token(choice(seq("//", /[^\r\n]*/), seq("/*", /[^*]*\*+([^/*][^*]*\*+)*/, "/"))),
  },
});

function commaSep1(rule) {
  return seq(rule, repeat(seq(",", rule)));
}
