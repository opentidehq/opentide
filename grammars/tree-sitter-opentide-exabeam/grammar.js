/// <reference types="tree-sitter-cli/dsl" />
// @ts-check

/**
 * Tree-sitter grammar for the Exabeam Query Language (Exabeam New-Scale SIEM;
 * opentide language id `exabeam`, specifications exabeam-1.0). Exabeam's
 * guides call it "EQL"; opentide never does, because `eql` is Elastic's.
 *
 * Two layers, as the spec defines them:
 *
 * - the filter, "a limited subset of Lucene": `field:"value"` terms, `AND`,
 *   `OR`, `NOT` (`NOT` binds tightest, then `AND`, then `OR`), two terms side
 *   by side read as `AND`, lists, ranges, CIDR blocks, context-table lookups
 *   (`user IN "Table"."Column"`), the four filter functions and free text;
 * - the advanced operators of Search: `SELECT`, `FROM`, `WHERE`, `AS`,
 *   `GROUP-BY`, `ORDER-BY`, `LIMIT`, pipes, `FOREACH`, the aggregations and
 *   `RGX_EXTRACT`. This SQL-like layer is part of the specified vendor
 *   language, not a SQL dialect (`docs/EXABEAM.md`).
 *
 * Filter operators are any case; clause keywords are recognised in any case
 * too, so a mixed-case one still highlights while the engine reports
 * `exabeam_keyword_case`. Clauses parse in any order: the engine reports
 * `exabeam_clause_order`.
 *
 * This grammar drives highlighting and editor structure. Diagnostics come
 * from the engine's verdict parser (crates/opentide-exabeam/src/check.rs),
 * which follows the specification's reference checker step for step.
 */

/** A keyword in any case, aliased to its upper-case spelling. */
function kw(word) {
  const pattern = word
    .split("")
    .map((c) => (/[a-z]/i.test(c) ? `[${c.toLowerCase()}${c.toUpperCase()}]` : c.replace(/-/g, "\\-")))
    .join("");
  return alias(token(new RegExp(pattern)), word);
}

function commaSep1(rule) {
  return seq(rule, repeat(seq(",", rule)));
}

module.exports = grammar({
  name: "opentide_exabeam",

  extras: (_) => [/\s/],


  rules: {
    source_file: ($) =>
      optional(seq($._statement, repeat(seq("|", $._statement)))),

    _statement: ($) => choice($.foreach_statement, $.statement),

    // A bare filter is an implicit WHERE. Clauses parse in any order.
    statement: ($) =>
      prec.right(
        choice(
          seq($.filter, repeat($._clause)),
          repeat1($._clause),
        ),
      ),

    _clause: ($) =>
      choice(
        $.select_clause,
        $.from_clause,
        $.where_clause,
        $.as_clause,
        $.group_by_clause,
        $.order_by_clause,
        $.limit_clause,
      ),

    foreach_statement: ($) =>
      seq(
        kw("FOREACH"),
        field("field", $.field_name),
        "[",
        optional($.statement),
        "]",
        optional($.limit_clause),
      ),

    select_clause: ($) =>
      prec.right(seq(kw("SELECT"), optional(kw("DISTINCT")), commaSep1($.column))),

    // `AS` after a column names the column, not the statement.
    column: ($) =>
      prec.right(
        seq(
          choice(alias("*", $.star), field("field", $.field_name), $.aggregate),
          optional(seq(kw("AS"), field("alias", $.alias))),
        ),
      ),

    aggregate: ($) =>
      seq(
        field("name", $.identifier),
        "(",
        optional(commaSep1(choice(alias("*", $.star), $.field_name, $.string, $.bare_word))),
        ")",
      ),

    from_clause: ($) => prec.right(seq(kw("FROM"), field("name", $.table_name), optional($.filter))),

    where_clause: ($) => prec.right(seq(kw("WHERE"), $.filter)),

    as_clause: ($) => seq(kw("AS"), field("name", $.table_name)),

    group_by_clause: ($) => prec.right(seq(kw("GROUP-BY"), commaSep1($.field_name))),

    order_by_clause: ($) =>
      prec.right(
        seq(kw("ORDER-BY"), commaSep1(seq($.field_name, optional(choice(kw("ASC"), kw("DESC")))))),
      ),

    limit_clause: ($) => seq(kw("LIMIT"), $.number),

    alias: ($) => $.identifier,

    table_name: ($) => $.identifier,

    // -- filter -------------------------------------------------------------

    filter: ($) => $._expression,

    // Flat, not left-recursive: a long run of terms is one node with many
    // children, so highlighting stays linear (`a AND b AND c …`).
    _expression: ($) => choice($.or_expression, $._and_operand),

    or_expression: ($) => seq($._and_operand, repeat1(seq(kw("OR"), $._and_operand))),

    _and_operand: ($) => choice($.and_expression, $._unary),

    // `AND`, or two terms side by side.
    and_expression: ($) => prec.left(seq($._unary, repeat1(seq(optional(kw("AND")), $._unary)))),

    _unary: ($) => choice($.not_expression, $._primary),

    not_expression: ($) => seq(kw("NOT"), field("operand", $._unary)),

    _primary: ($) =>
      choice(
        $.group,
        $.field_term,
        $.context_term,
        $.call,
        $.free_text,
      ),

    group: ($) => seq("(", $._expression, ")"),

    field_term: ($) =>
      seq(
        field("field", $.field_name),
        choice(
          seq(field("operator", choice(":", "=", "==")), field("value", $._value)),
          seq(
            optional(field("operator", choice(":", "="))),
            field("operator", choice("<", ">", "<=", ">=")),
            field("value", choice($.number, $.string, $.bare_word, $.identifier)),
          ),
          seq(field("operator", alias("!=", $.not_equal)), field("value", $._value)),
        ),
      ),

    context_term: ($) =>
      seq(
        field("field", $.field_name),
        kw("IN"),
        field("table", alias($.string, $.context_table)),
        optional(seq(".", field("column", alias($.string, $.context_table)))),
      ),

    call: ($) =>
      prec(
        1,
        seq(
          field("name", $.identifier),
          "(",
          optional(commaSep1(field("argument", choice($.string, $.number, $.identifier, $.bare_word)))),
          ")",
        ),
      ),

    free_text: ($) => choice($.string, $.identifier, $.text_word),

    _value: ($) => choice($.string, $._scalar, $.list, $.range, $.call),

    _scalar: ($) => choice($.number, $.identifier, $.bare_word),

    list: ($) => seq("(", commaSep1(choice($.string, $._scalar)), ")"),

    range: ($) =>
      choice(
        seq(
          field("open", choice("[", "{")),
          field("low", $._bound),
          kw("TO"),
          field("high", $._bound),
          field("close", choice("]", "}")),
        ),
        // A CIDR block: `[10.0.0.0/8]`.
        seq("[", field("network", $.bound), "]"),
      ),

    _bound: ($) => choice($.string, $.bound),

    field_name: ($) => $.identifier,

    // -- tokens ---------------------------------------------------------------

    string: (_) =>
      token(choice(/"([^"\\]|\\(.|\r?\n))*"/, /'([^'\\]|\\(.|\r?\n))*'/)),

    number: (_) => /[+-]?[0-9]+(\.[0-9]+)?/,

    // A field name or a word: `.` between parts, `-` inside one (`c-uri`).
    identifier: (_) => /[A-Za-z_][A-Za-z0-9_-]*(\.[A-Za-z_][A-Za-z0-9_-]*)*/,

    // An unquoted value that is neither a number nor a word: an IP address,
    // a CIDR block, `@field`, a datetime.
    bare_word: (_) => /[^\s()\[\]{},"'|=<>!]+/,

    // Free text that is not a word (`web*`, `10.228.200.3`). It stops at `:`
    // so `field:value` stays a field term.
    text_word: (_) => /[^\s()\[\]{},"'|=<>!:]+/,

    // A range bound or a CIDR block: anything up to blank, `]` or `}`.
    bound: (_) => /[^\s\]}"']+/,
  },
});
