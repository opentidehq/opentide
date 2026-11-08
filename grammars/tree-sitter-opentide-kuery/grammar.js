/// <reference types="tree-sitter-cli/dsl" />
// @ts-check

/**
 * Tree-sitter grammar for the Kibana Query Language (KQL), which Kibana's
 * detection engine API calls `kuery`. It is not Kusto KQL (`kql`).
 *
 * Follows Kibana's `kbn-es-query/src/kuery/grammar/grammar.peggy`:
 * `or` < `and` < `not`, all case-insensitive; `field:value`,
 * `field:(a or b)`, `field < v`, nested `field:{ query }`, quoted and
 * unquoted literals. An unquoted literal may contain spaces, so it is a run of
 * words. Kibana ends a literal at an unescaped `not ` inside it; the engine
 * diagnoses that, because the grammar cannot see inside a word.
 */
const caseVariants = (word) =>
  word
    .split("")
    .reduce(
      (acc, c) => acc.flatMap((p) => [p + c.toLowerCase(), p + c.toUpperCase()]),
      [""],
    );
const keyword = (word) => choice(...caseVariants(word));

module.exports = grammar({
  name: "opentide_kuery",

  extras: (_) => [/[ \t\r\n\u00A0]/],

  word: ($) => $.word,

  rules: {
    source_file: ($) => optional($._query),

    _query: ($) => choice($.or_query, $.and_query, $.not_query, $._sub_query),

    or_query: ($) =>
      prec.left(1, seq(field("left", $._query), $.or, field("right", $._query))),

    and_query: ($) =>
      prec.left(2, seq(field("left", $._query), $.and, field("right", $._query))),

    not_query: ($) => prec(3, seq($.not, field("operand", $._sub_query))),

    _sub_query: ($) =>
      choice(
        $.group,
        $.nested_query,
        $.range_expression,
        $.field_value_expression,
        $.value_expression,
      ),

    group: ($) => seq("(", $._query, ")"),

    nested_query: ($) =>
      seq(field("field", $.field), ":", "{", field("query", $._query), "}"),

    range_expression: ($) =>
      seq(
        field("field", $.field),
        field("operator", choice("<", "<=", ">", ">=")),
        field("value", $._literal),
      ),

    field_value_expression: ($) =>
      seq(
        field("field", $.field),
        ":",
        field("value", choice($.value_list, $._literal)),
      ),

    value_expression: ($) => field("value", $._literal),

    value_list: ($) => seq("(", $._list, ")"),

    _list: ($) =>
      choice($.or_list, $.and_list, $.not_list, $.value_list, $._literal),

    or_list: ($) =>
      prec.left(1, seq(field("left", $._list), $.or, field("right", $._list))),

    and_list: ($) =>
      prec.left(2, seq(field("left", $._list), $.and, field("right", $._list))),

    not_list: ($) =>
      prec(3, seq($.not, field("operand", choice($.value_list, $._literal)))),

    field: ($) => $._literal,

    _literal: ($) => choice($.quoted_string, $.unquoted_literal),

    unquoted_literal: ($) => prec.right(repeat1($.word)),

    word: (_) =>
      token(
        repeat1(
          choice(
            /[^ \t\r\n\u00A0\\():<>"*{}]/,
            /\\[\\():<>"*{}]/,
            /\\[trn]/,
            /\\u[0-9a-fA-F]{4}/,
            /\\[aA][nN][dD]/,
            /\\[oO][rR]/,
            /\\[nN][oO][tT]/,
            "*",
          ),
        ),
      ),

    quoted_string: (_) =>
      token(seq('"', repeat(choice(/[^"\\]/, /\\./)), '"')),

    or: (_) => keyword("or"),

    and: (_) => keyword("and"),

    not: (_) => keyword("not"),
  },
});
