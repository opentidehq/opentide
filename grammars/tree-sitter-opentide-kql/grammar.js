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

  // A bare name after `let x =` is a scalar or a table, and `(a)` after
  // `extend` is an expression or a one-name tuple until `=` follows.
  conflicts: ($) => [
    [$.primary_expression, $.tabular_primary],
    [$.primary_expression, $.assignment],
  ],

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
        field(
          "value",
          choice($.expression, $.tabular_expression, $.function_definition),
        ),
        ";",
      ),

    // `let f = (t: string, n: int = 1) { ... };`
    function_definition: ($) =>
      seq(
        "(",
        optional(commaSep1($.parameter)),
        ")",
        "{",
        repeat($.let_statement),
        field("body", choice($.tabular_expression, $.expression)),
        optional(";"),
        "}",
      ),

    parameter: ($) =>
      seq(
        field("name", $.identifier),
        ":",
        field("type", $.type),
        optional(seq("=", field("default", $.expression))),
      ),

    // A scalar type name, or `(*)` / `(col: type, ...)` for a tabular parameter.
    type: ($) =>
      choice(
        $.identifier,
        "dynamic",
        seq("(", choice("*", commaSep1(seq($.identifier, ":", $.type))), ")"),
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
        $.union_operator,
        $.datatable_expression,
        // `table("SigninLogs")`, a tabular function declared with `let`
        $.function_call,
        $.materialize_expression,
      ),

    // `materialize(T | ...)` and `toscalar(T | ...)` take a tabular argument.
    materialize_expression: ($) =>
      seq("materialize", "(", field("body", $.tabular_expression), ")"),

    toscalar_expression: ($) =>
      seq("toscalar", "(", field("body", $.tabular_expression), ")"),

    datatable_expression: ($) =>
      seq(
        "datatable",
        "(",
        commaSep1(seq($.identifier, ":", $.type)),
        ")",
        "[",
        optional(seq(commaSep1($.expression), optional(","))),
        "]",
      ),

    // `kind=inner`, `isfuzzy=true`, `hint.strategy=shuffle`. Where options
    // precede a table or column (join, union, lookup, parse), `name =` can only
    // be an option, so any name is accepted and columns keep names like `flags`.
    operator_option: ($) =>
      seq(
        field("name", choice($.identifier, $.hint_name)),
        "=",
        field("value", choice($.identifier, $.boolean, $.number, $.string)),
      ),

    // mv-expand, mv-apply and make-series items can be `Name = ...`, so their options are
    // a fixed set of names.
    mv_option: ($) =>
      seq(
        field("name", choice("kind", "bagexpansion", "with_itemindex", $.hint_name)),
        "=",
        field("value", choice($.identifier, $.boolean, $.number, $.string)),
      ),

    // summarize, make-series and evaluate only take `hint.*` options; a bare
    // `name = value` there is a named column.
    hint_option: ($) =>
      seq(
        field("name", $.hint_name),
        "=",
        field("value", choice($.identifier, $.boolean, $.number, $.string)),
      ),

    hint_name: (_) => token(seq("hint.", /[A-Za-z_][A-Za-z0-9_]*/)),

    // The operators after `mv-apply ... on (` have no source table.
    subquery: ($) =>
      prec.left(
        seq(
          field("operator", $.tabular_operator),
          repeat(seq("|", field("operator", $.tabular_operator))),
        ),
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
        $.mv_apply_operator,
        $.make_series_operator,
        $.evaluate_operator,
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
      seq("extend", field("assignments", commaSep1($.column_item))),

    summarize_operator: ($) =>
      seq(
        "summarize",
        repeat($.hint_option),
        optional(field("aggregates", commaSep1($.column_item))),
        optional(seq("by", field("by", commaSep1($.column_item)))),
      ),

    // `Name = expr` or an unnamed `expr`, as extend, summarize and print take them.
    column_item: ($) => choice($.assignment, $.expression),

    join_operator: ($) =>
      seq(
        "join",
        repeat(
          $.operator_option,
        ),
        field("right", $.tabular_primary),
        "on",
        field("condition", commaSep1($.expression)),
      ),

    union_operator: ($) =>
      prec.right(
        seq(
          "union",
          repeat($.operator_option),
          field("tables", commaSep1(choice($.identifier, seq("(", $.tabular_expression, ")")))),
        ),
      ),

    parse_operator: ($) =>
      seq(
        "parse",
        repeat($.operator_option),
        field("column", $.expression),
        "with",
        field("pattern", repeat1(choice($.string, "*", $.parse_column))),
      ),

    parse_column: ($) =>
      prec.right(seq($.identifier, optional(seq(":", $.type)))),

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
      seq(
        choice("mv-expand", "mvexpand"),
        repeat($.mv_option),
        field("columns", commaSep1($.mv_expand_item)),
        optional(seq("limit", field("limit", $.expression))),
      ),

    mv_expand_item: ($) =>
      seq(
        choice($.assignment, $.expression),
        optional(seq("to", "typeof", "(", $.type, ")")),
      ),

    mv_apply_operator: ($) =>
      seq(
        "mv-apply",
        repeat($.mv_option),
        field("columns", commaSep1($.mv_expand_item)),
        optional(seq("limit", field("limit", $.expression))),
        "on",
        "(",
        field("subquery", $.subquery),
        ")",
      ),

    make_series_operator: ($) =>
      seq(
        "make-series",
        repeat($.mv_option),
        field("aggregates", commaSep1($.series_aggregate)),
        "on",
        field("axis", $.expression),
        choice(
          seq(
            optional(seq("from", field("from", $.expression))),
            optional(seq("to", field("to", $.expression))),
            "step",
            field("step", $.expression),
          ),
          // `on T in range(start, stop, step)`
          seq("in", field("range", $.function_call)),
        ),
        optional(seq("by", field("by", commaSep1($.column_item)))),
      ),

    // `Name = agg(...) default = 0`
    series_aggregate: ($) =>
      seq($.column_item, optional(seq("default", "=", field("default", $.expression)))),

    evaluate_operator: ($) =>
      seq("evaluate", repeat($.hint_option), field("plugin", $.function_call)),

    keyword_operator: ($) =>
      seq(
        field(
          "name",
          choice(
            "search",
            "find",
            "invoke",
            "serialize",
            "scan",
            "as",
            "getschema",
            "sample",
            "sample-distinct",
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
        repeat($.operator_option),
        field("table", $.tabular_primary),
        "on",
        field("condition", commaSep1($.expression)),
      ),

    take_operator: ($) => seq("take", field("count", $.number)),

    limit_operator: ($) => seq("limit", field("count", $.number)),

    sort_operator: ($) =>
      seq(
        choice("sort", "order"),
        optional("by"),
        field("keys", commaSep1($.sort_item)),
      ),

    sort_item: ($) =>
      seq(
        $.expression,
        optional(choice("asc", "desc")),
        optional(seq("nulls", choice("first", "last"))),
      ),

    distinct_operator: ($) =>
      seq("distinct", optional(field("columns", commaSep1($.identifier)))),

    render_operator: ($) => seq("render", field("kind", $.identifier)),

    print_operator: ($) => seq("print", commaSep1($.column_item)),

    unknown_operator: ($) =>
      seq(field("name", $.identifier), optional(field("args", $.expression))),

    project_item: ($) => choice($.assignment, $.expression),

    rename_item: ($) =>
      seq(field("new", $.identifier), "=", field("old", $.identifier)),

    // `(Anomalies, Score, Baseline) = series_decompose_anomalies(...)` names
    // every column a multi-value function returns.
    assignment: ($) =>
      seq(
        field("name", choice($.identifier, seq("(", commaSep1($.identifier), ")"))),
        "=",
        field("value", $.expression),
      ),

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
            choice(
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
                seq("matches", "regex"),
              ),
              $.additive_expression,
            ),
            seq(
              choice(
                "in",
                "!in",
                "in~",
                "!in~",
                "has_any",
                "has_all",
                "has_any_ipv4",
                "has_any_ipv4_prefix",
              ),
              field("set", $.expression_list),
            ),
            seq(choice("between", "!between"), field("range", $.range)),
            ),
          ),
        ),
      ),

    // `(a, b, ...)`, or `(T | project x)` for a tabular subquery
    expression_list: ($) =>
      seq("(", optional(choice(commaSep1($.expression), $.tabular_expression)), ")"),

    range: ($) => seq("(", $.expression, "..", $.expression, ")"),

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
        $.dynamic_literal,
        $.toscalar_expression,
        $.member_expression,
        $.index_expression,
        seq("(", $.expression, ")"),
      ),

    member_expression: ($) =>
      prec(11, seq(field("object", $.primary_expression), ".", field("member", $.identifier))),

    index_expression: ($) =>
      prec(
        11,
        seq(field("object", $.primary_expression), "[", field("index", $.expression), "]"),
      ),

    function_call: ($) =>
      prec(
        10,
        seq(
          field("name", $.identifier),
          "(",
          field("arguments", optional(commaSep1(choice($.expression, $.star)))),
          ")",
        ),
      ),

    // `arg_max(TimeGenerated, *)`
    star: (_) => "*",

    // `dynamic([...])`, `dynamic({...})`, `dynamic(null)`
    dynamic_literal: ($) => seq("dynamic", "(", optional($.json_value), ")"),

    json_value: ($) =>
      choice(
        seq("[", optional(seq(commaSep1($.json_value), optional(","))), "]"),
        seq(
          "{",
          optional(seq(commaSep1(seq($.string, ":", $.json_value)), optional(","))),
          "}",
        ),
        $.string,
        seq(optional("-"), $.number),
        $.boolean,
        $.null,
      ),

    // `$left` / `$right` in join conditions
    identifier: (_) => /\$?[A-Za-z_][A-Za-z0-9_]*/,

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

    // Kusto booleans are case-insensitive (`isfuzzy=True`).
    boolean: (_) => choice("true", "false", "True", "False", "TRUE", "FALSE"),

    null: (_) => "null",

    timespan: (_) =>
      token(
        /[0-9]+(\.[0-9]+)?(days?|d|hours?|hrs?|h|minutes?|min|m|seconds?|sec|s|milliseconds?|ms|microseconds?|tick|ticks)/,
      ),
  },
});

function commaSep1(rule) {
  return seq(rule, repeat(seq(",", rule)));
}
