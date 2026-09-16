/// <reference types="tree-sitter-cli/dsl" />
// @ts-check

/**
 * Tree-sitter grammar for Kusto Query Language (KQL) as used in Microsoft
 * Sentinel and Defender for Endpoint hunting queries.
 *
 * Control commands (`.show`, `.create`, …) are parsed so the engine can emit
 * `kql_control_command_unsupported`. They are not valid detection queries.
 * SQL is out of scope.
 */
module.exports = grammar({
  name: "opentide_kql",

  extras: ($) => [/\s/, $.comment],

  word: ($) => $.identifier,

  rules: {
    source_file: ($) =>
      seq(repeat($.let_statement), optional(choice($.query, $.control_command))),

    comment: (_) =>
      token(
        choice(seq("//", /.*/), seq("/*", /[^*]*\*+([^/*][^*]*\*+)*/, "/")),
      ),

    let_statement: ($) =>
      seq(
        "let",
        field("name", $.identifier),
        "=",
        field("value", $.expression),
        ";",
      ),

    query: ($) => field("body", $.tabular_expression),

    control_command: ($) =>
      seq(".", field("name", $.identifier), optional(repeat1($.identifier))),

    tabular_expression: ($) =>
      prec.left(
        seq(
          field("source", $.tabular_primary),
          repeat(seq("|", field("operator", $.tabular_operator))),
        ),
      ),

    tabular_primary: ($) =>
      choice(
        field("table", $.identifier),
        seq("(", $.tabular_expression, ")"),
        $.print_operator,
      ),

    tabular_operator: ($) =>
      choice(
        $.where_operator,
        $.filter_operator,
        $.project_operator,
        $.project_away_operator,
        $.project_rename_operator,
        $.project_keep_operator,
        $.project_reorder_operator,
        $.extend_operator,
        $.summarize_operator,
        $.join_operator,
        $.union_operator,
        $.parse_operator,
        $.parse_where_operator,
        $.parse_kv_operator,
        $.lookup_operator,
        $.take_operator,
        $.limit_operator,
        $.top_operator,
        $.count_operator,
        $.mv_expand_operator,
        $.sort_operator,
        $.distinct_operator,
        $.render_operator,
        $.keyword_operator,
        $.unknown_operator,
      ),

    where_operator: ($) => seq("where", field("predicate", $.expression)),

    filter_operator: ($) => seq("filter", field("predicate", $.expression)),

    project_operator: ($) =>
      seq("project", field("columns", commaSep1($.project_item))),

    project_away_operator: ($) =>
      seq("project-away", field("columns", commaSep1($.identifier))),

    project_rename_operator: ($) =>
      seq("project-rename", field("renames", commaSep1($.rename_item))),

    extend_operator: ($) =>
      seq("extend", field("assignments", commaSep1($.assignment))),

    summarize_operator: ($) =>
      seq(
        "summarize",
        field("aggregates", commaSep1($.expression)),
        optional(seq("by", field("by", commaSep1($.expression)))),
      ),

    join_operator: ($) =>
      seq(
        "join",
        optional(seq("kind", "=", field("kind", $.identifier))),
        field("right", $.tabular_primary),
        "on",
        field("condition", $.expression),
      ),

    union_operator: ($) =>
      seq("union", field("tables", commaSep1($.identifier))),

    parse_operator: ($) =>
      seq("parse", field("column", $.identifier), "with", field("pattern", $.string)),

    parse_where_operator: ($) =>
      seq("parse-where", optional(field("args", $.expression))),

    parse_kv_operator: ($) =>
      seq("parse-kv", optional(field("args", $.expression))),

    project_keep_operator: ($) =>
      seq("project-keep", field("columns", commaSep1($.identifier))),

    project_reorder_operator: ($) =>
      seq("project-reorder", field("columns", commaSep1($.identifier))),

    top_operator: ($) =>
      seq(
        "top",
        field("count", $.number),
        optional(seq("by", field("keys", commaSep1($.sort_item)))),
      ),

    count_operator: ($) => "count",

    mv_expand_operator: ($) =>
      seq(choice("mv-expand", "mvexpand"), optional(field("args", $.expression))),

    keyword_operator: ($) =>
      seq(
        field(
          "name",
          choice(
            "search",
            "find",
            "invoke",
            "evaluate",
            "serialize",
            "scan",
            "as",
            "getschema",
            "make-series",
            "sample",
            "sample-distinct",
            "mv-apply",
            "datatable",
            "range",
            "externaldata",
            "partition",
            "fork",
            "facet",
            "consume",
            "reduce",
            "make-graph",
            "graph-match",
            "graph-shortest-paths",
            "graph-to-table",
            "graph-mark-components",
            "top-hitters",
            "top-nested",
          ),
        ),
        optional(field("args", $.expression)),
      ),

    lookup_operator: ($) =>
      seq(
        "lookup",
        field("table", $.identifier),
        "on",
        field("condition", $.expression),
      ),

    take_operator: ($) => seq("take", field("count", $.number)),

    limit_operator: ($) => seq("limit", field("count", $.number)),

    sort_operator: ($) =>
      seq(
        choice("sort", "order"),
        optional("by"),
        field("keys", commaSep1($.sort_item)),
      ),

    sort_item: ($) => seq($.expression, optional(choice("asc", "desc"))),

    distinct_operator: ($) =>
      seq("distinct", optional(field("columns", commaSep1($.identifier)))),

    render_operator: ($) => seq("render", field("kind", $.identifier)),

    print_operator: ($) => seq("print", commaSep1($.expression)),

    unknown_operator: ($) =>
      seq(field("name", $.identifier), optional(field("args", $.expression))),

    project_item: ($) => choice($.assignment, $.identifier),

    rename_item: ($) =>
      seq(field("new", $.identifier), "=", field("old", $.identifier)),

    assignment: ($) =>
      seq(field("name", $.identifier), "=", field("value", $.expression)),

    expression: ($) => $.or_expression,

    or_expression: ($) =>
      prec.left(1, seq($.and_expression, repeat(seq("or", $.and_expression)))),

    and_expression: ($) =>
      prec.left(2, seq($.not_expression, repeat(seq("and", $.not_expression)))),

    not_expression: ($) =>
      choice(seq("not", $.comparison_expression), $.comparison_expression),

    comparison_expression: ($) =>
      prec.left(
        3,
        seq(
          $.additive_expression,
          optional(
            seq(
              choice(
                "==",
                "!=",
                "<>",
                "<",
                ">",
                "<=",
                ">=",
                "=~",
                "!~",
                "has",
                "!has",
                "has_cs",
                "!has_cs",
                "has_any",
                "has_all",
                "contains",
                "!contains",
                "contains_cs",
                "!contains_cs",
                "startswith",
                "!startswith",
                "startswith_cs",
                "!startswith_cs",
                "endswith",
                "!endswith",
                "endswith_cs",
                "!endswith_cs",
                "in",
                "!in",
                "in~",
                "!in~",
                "between",
                "!between",
                "hasprefix",
                "!hasprefix",
                "hasprefix_cs",
                "!hasprefix_cs",
                "hassuffix",
                "!hassuffix",
                "hassuffix_cs",
                "!hassuffix_cs",
                "has_ipv4",
                "has_ipv4_prefix",
                "has_any_ipv4",
                "has_any_ipv4_prefix",
                seq("matches", "regex"),
              ),
              $.additive_expression,
            ),
          ),
        ),
      ),

    additive_expression: ($) =>
      prec.left(
        4,
        seq(
          $.multiplicative_expression,
          repeat(seq(choice("+", "-"), $.multiplicative_expression)),
        ),
      ),

    multiplicative_expression: ($) =>
      prec.left(
        5,
        seq($.unary_expression, repeat(seq(choice("*", "/", "%"), $.unary_expression))),
      ),

    unary_expression: ($) =>
      choice(seq(choice("-", "+"), $.primary_expression), $.primary_expression),

    primary_expression: ($) =>
      choice(
        $.function_call,
        $.identifier,
        $.string,
        $.number,
        $.boolean,
        $.null,
        $.timespan,
        seq("(", $.expression, ")"),
      ),

    function_call: ($) =>
      prec(
        10,
        seq(
          field("name", $.identifier),
          "(",
          field("arguments", optional(commaSep1($.expression))),
          ")",
        ),
      ),

    identifier: (_) => /[A-Za-z_][A-Za-z0-9_]*/,

    string: (_) =>
      token(
        choice(
          seq('"', repeat(choice(/[^"\\]/, /\\./)), '"'),
          seq("'", repeat(choice(/[^'\\]/, /\\./)), "'"),
          seq("@\"", repeat(/[^"]/), '"'),
          seq("@'", repeat(/[^']/), "'"),
        ),
      ),

    number: (_) => token(/[0-9]+(\.[0-9]+)?([eE][+-]?[0-9]+)?/),

    boolean: (_) => choice("true", "false"),

    null: (_) => "null",

    timespan: (_) => token(/[0-9]+(d|h|m|s|ms)/),
  },
});

function commaSep1(rule) {
  return seq(rule, repeat(seq(",", rule)));
}
