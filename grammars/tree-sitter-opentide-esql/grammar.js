/// <reference types="tree-sitter-cli/dsl" />
// @ts-check

/**
 * Tree-sitter grammar for Elasticsearch ES|QL, as used by Elastic Security
 * `esql` detection rules.
 *
 * Covers the ES|QL Elasticsearch accepts from 8.19 through 9.x. Keywords are
 * case-insensitive and contextual: command names are keywords at command
 * position, and tree-sitter's context-aware lexing gives index patterns after
 * FROM, name patterns after KEEP, and expression tokens after WHERE.
 *
 * Every command the grammar names parses, including snapshot-only ones; the
 * catalog decides availability. A command name the grammar does not know is
 * an `unknown_command`, so the engine can diagnose it: ES|QL on Kibana 9.5
 * otherwise drops the command at runtime.
 */

const PREC = {
  or: 1,
  and: 2,
  not: 3,
  predicate: 4,
  comparison: 5,
  additive: 6,
  multiplicative: 7,
  unary: 8,
  cast: 9,
};

/** Case-insensitive keyword token, exposed as the lower-case anonymous node. */
function kw(word) {
  const pattern = word
    .split("")
    .map((c) => (/[a-z]/i.test(c) ? `[${c.toLowerCase()}${c.toUpperCase()}]` : c.replace(/[_]/g, "_")))
    .join("");
  return alias(token(new RegExp(pattern)), word);
}

function commaSep1(rule) {
  return seq(rule, repeat(seq(",", rule)));
}

module.exports = grammar({
  name: "opentide_esql",

  extras: ($) => [/\s/, $.comment],

  // Comments come from src/scanner.c: Elasticsearch nests `/* */`, which a
  // regular expression cannot express.
  externals: ($) => [$.comment],

  conflicts: ($) => [[$.enrich_policy, $._index_name]],

  rules: {
    source_file: ($) =>
      seq(repeat($.set_command), optional($.query)),

    set_command: ($) =>
      seq(
        kw("set"),
        field("name", $.identifier),
        "=",
        field("value", choice($._constant, $.map_expression)),
        ";",
      ),

    query: ($) =>
      seq(
        field("source", $._source_command),
        repeat(seq("|", field("command", $._processing_command))),
      ),

    // ---- Source commands --------------------------------------------------

    _source_command: ($) =>
      choice(
        $.from_command,
        $.ts_command,
        $.row_command,
        $.show_command,
        $.promql_command,
        $.explain_command,
        $.unknown_command,
      ),

    from_command: ($) => seq(kw("from"), $._sources),

    ts_command: ($) => seq(kw("ts"), $._sources),

    _sources: ($) =>
      seq(
        commaSep1(field("index", choice($.index_pattern, $.source_subquery))),
        optional(field("metadata", $.metadata)),
      ),

    index_pattern: ($) =>
      choice(
        seq(
          optional(seq(field("cluster", $.cluster), ":")),
          field("name", $.index_name),
          optional(seq("::", field("selector", $.selector))),
        ),
        field("name", alias($.string, $.index_name)),
      ),

    cluster: ($) => $._unquoted_source,
    selector: ($) => $._unquoted_source,
    index_name: ($) => $._unquoted_source,

    _index_name: ($) => $._unquoted_source,

    _unquoted_source: (_) => token(prec(-1, /([^:"=|,\[\]/()\s]|\/[^*/:"=|,\[\]()\s])+/)),

    source_subquery: ($) =>
      seq(
        "(",
        field("source", choice($.from_command, $.ts_command, $.row_command)),
        repeat(seq("|", field("command", $._processing_command))),
        ")",
      ),

    metadata: ($) =>
      choice(
        seq(kw("metadata"), commaSep1(field("field", alias($._unquoted_source, $.metadata_field)))),
        // `FROM idx [METADATA _id]`: 8.19 only; 9.0 removed the brackets.
        seq(
          field("bracket", "["),
          kw("metadata"),
          commaSep1(field("field", alias($._unquoted_source, $.metadata_field))),
          "]",
        ),
      ),

    row_command: ($) => seq(kw("row"), $._fields),

    show_command: ($) => seq(kw("show"), kw("info")),

    explain_command: ($) =>
      seq(kw("explain"), "(", field("query", $.query), ")"),

    promql_command: ($) =>
      seq(kw("promql"), repeat($._promql_part)),

    _promql_part: ($) =>
      choice(
        seq("(", repeat($._promql_part), ")"),
        $.string,
        alias(token(prec(-1, /[^|()"\s]+/)), $.promql_text),
      ),

    // ---- Processing commands ----------------------------------------------

    _processing_command: ($) =>
      choice(
        $.where_command,
        $.eval_command,
        $.keep_command,
        $.drop_command,
        $.rename_command,
        $.sort_command,
        $.limit_command,
        $.stats_command,
        $.inline_stats_command,
        $.dissect_command,
        $.grok_command,
        $.enrich_command,
        $.mv_expand_command,
        $.join_command,
        $.change_point_command,
        $.completion_command,
        $.sample_command,
        $.fork_command,
        $.rerank_command,
        $.fuse_command,
        $.uri_parts_command,
        $.registered_domain_command,
        $.user_agent_command,
        $.ip_location_command,
        $.metrics_info_command,
        $.ts_info_command,
        $.ts_collapse_command,
        $.dedup_command,
        $.mmr_command,
        $.highlight_command,
        $.dense_vector_command,
        $.fill_null_command,
        $.unknown_command,
      ),

    where_command: ($) => seq(kw("where"), field("condition", $._boolean_expression)),

    eval_command: ($) => seq(kw("eval"), $._fields),

    keep_command: ($) => seq(kw("keep"), $._name_patterns),

    drop_command: ($) => seq(kw("drop"), $._name_patterns),

    rename_command: ($) => seq(kw("rename"), commaSep1($.rename_clause)),

    rename_clause: ($) =>
      choice(
        seq(field("old", $.name_pattern), kw("as"), field("new", $.name_pattern)),
        seq(field("new", $.name_pattern), "=", field("old", $.name_pattern)),
      ),

    sort_command: ($) => seq(kw("sort"), commaSep1($.order_expression)),

    order_expression: ($) =>
      seq(
        field("key", $._boolean_expression),
        optional(field("direction", choice(kw("asc"), kw("desc")))),
        optional(seq(kw("nulls"), field("nulls", choice(kw("first"), kw("last"))))),
      ),

    limit_command: ($) =>
      seq(
        kw("limit"),
        field("count", $._constant),
        optional(seq(kw("by"), commaSep1(field("by", $._boolean_expression)))),
      ),

    stats_command: ($) =>
      seq(
        kw("stats"),
        optional(commaSep1(field("aggregate", $.aggregate_field))),
        optional(seq(kw("by"), commaSep1(field("by", $.field_assignment_or_expression)))),
      ),

    inline_stats_command: ($) =>
      seq(
        choice(seq(kw("inline"), kw("stats")), kw("inlinestats")),
        commaSep1(field("aggregate", $.aggregate_field)),
        optional(seq(kw("by"), commaSep1(field("by", $.field_assignment_or_expression)))),
      ),

    aggregate_field: ($) =>
      seq(
        $._field,
        optional(seq(kw("where"), field("filter", $._boolean_expression))),
      ),

    _fields: ($) => commaSep1($.field_assignment_or_expression),

    field_assignment_or_expression: ($) => $._field,

    _field: ($) =>
      choice(
        seq(field("name", $.qualified_name), "=", field("value", $._boolean_expression)),
        field("value", $._boolean_expression),
      ),

    dissect_command: ($) =>
      seq(
        kw("dissect"),
        field("input", $._primary_expression),
        field("pattern", $.string),
        optional(commaSep1(field("option", $.command_option))),
      ),

    command_option: ($) =>
      seq(field("name", $.identifier), "=", field("value", $._constant)),

    grok_command: ($) =>
      seq(
        kw("grok"),
        field("input", $._primary_expression),
        commaSep1(field("pattern", $.string)),
      ),

    enrich_command: ($) =>
      seq(
        kw("enrich"),
        field("policy", $.enrich_policy),
        optional(seq(kw("on"), field("match_field", $.name_pattern))),
        optional(seq(kw("with"), commaSep1(field("with", $.enrich_with_clause)))),
      ),

    enrich_policy: ($) =>
      choice(
        $.string,
        seq(
          optional(seq(field("mode", alias($._policy_part, $.enrich_mode)), ":")),
          field("name", alias($._policy_part, $.policy_name)),
        ),
      ),

    _policy_part: (_) => token(prec(-1, /[^\\/?"<>| ,#\t\r\n:()]+/)),

    enrich_with_clause: ($) =>
      seq(
        optional(seq(field("new", $.name_pattern), "=")),
        field("field", $.name_pattern),
      ),

    mv_expand_command: ($) => seq(kw("mv_expand"), field("field", $.qualified_name)),

    join_command: ($) =>
      seq(
        field("kind", choice(kw("lookup"), kw("left"), kw("right"), kw("full"))),
        kw("join"),
        field("target", $.index_pattern),
        optional(seq(optional(kw("as")), field("qualifier", alias($._unquoted_source, $.identifier)))),
        kw("on"),
        commaSep1(field("condition", $._boolean_expression)),
      ),

    change_point_command: ($) =>
      seq(
        kw("change_point"),
        field("value", $.qualified_name),
        optional(seq(kw("on"), field("key", $.qualified_name))),
        optional(
          seq(kw("as"), field("type_name", $.qualified_name), ",", field("pvalue_name", $.qualified_name)),
        ),
        optional(seq(kw("by"), commaSep1(field("by", $._boolean_expression)))),
      ),

    completion_command: ($) =>
      seq(
        kw("completion"),
        optional(seq(field("target", $.qualified_name), "=")),
        field("prompt", $._primary_expression),
        optional(
          choice(
            $._named_parameters,
            // `WITH endpoint`: 8.19 and 9.1; 9.2 and later take `WITH {"inference_id": …}`.
            seq(kw("with"), field("inference_id", choice($.identifier, $.quoted_identifier, $.parameter))),
          ),
        ),
      ),

    rerank_command: ($) =>
      seq(
        kw("rerank"),
        optional(seq(field("target", $.qualified_name), "=")),
        field("query", $._constant),
        kw("on"),
        $._fields,
        optional($._named_parameters),
      ),

    _named_parameters: ($) => seq(kw("with"), field("options", $.map_expression)),

    sample_command: ($) => seq(kw("sample"), field("probability", $._constant)),

    fork_command: ($) => seq(kw("fork"), repeat1($.fork_branch)),

    fork_branch: ($) =>
      seq("(", $._processing_command, repeat(seq("|", $._processing_command)), ")"),

    fuse_command: ($) =>
      seq(
        kw("fuse"),
        optional(field("method", $.identifier)),
        repeat(
          choice(
            seq(kw("score"), kw("by"), field("score", $.qualified_name)),
            seq(kw("key"), kw("by"), commaSep1(field("key", $.qualified_name))),
            seq(kw("group"), kw("by"), field("group", $.qualified_name)),
            $._named_parameters,
          ),
        ),
      ),

    uri_parts_command: ($) => seq(kw("uri_parts"), $._extract_assignment),
    registered_domain_command: ($) => seq(kw("registered_domain"), $._extract_assignment),
    user_agent_command: ($) =>
      seq(kw("user_agent"), $._extract_assignment, optional($._named_parameters)),
    ip_location_command: ($) =>
      seq(kw("ip_location"), $._extract_assignment, optional($._named_parameters)),

    _extract_assignment: ($) =>
      seq(field("target", $.qualified_name), "=", field("input", $._primary_expression)),

    metrics_info_command: (_) => kw("metrics_info"),
    ts_info_command: (_) => kw("ts_info"),
    ts_collapse_command: (_) => kw("ts_collapse"),
    dedup_command: (_) => kw("dedup"),

    mmr_command: ($) =>
      seq(
        kw("mmr"),
        optional(field("query_vector", $._primary_expression)),
        kw("on"),
        field("field", $.qualified_name),
        kw("limit"),
        field("limit", $._constant),
        optional($._named_parameters),
      ),

    highlight_command: ($) =>
      prec.right(
        seq(
          kw("highlight"),
          optional(field("query", $._boolean_expression)),
          optional(seq(kw("on"), $._name_patterns)),
          optional($._named_parameters),
        ),
      ),

    dense_vector_command: ($) =>
      prec.right(
        seq(
          kw("dense_vector"),
          optional(seq(field("target", $.qualified_name), "=")),
          optional(commaSep1(field("field", $._primary_expression))),
          optional($._named_parameters),
        ),
      ),

    fill_null_command: ($) =>
      seq(kw("fillnull"), field("value", $._constant), kw("on"), $._name_patterns),

    unknown_command: ($) =>
      prec.right(
        seq(
          field("name", $.command_name),
          repeat(choice($.string, alias(token(prec(-2, /[^|"\s]+/)), $.unknown_text))),
        ),
      ),

    command_name: (_) => /[^\s\[\]()\/|"]+/,

    // ---- Expressions ------------------------------------------------------

    _boolean_expression: ($) =>
      choice(
        $.not_expression,
        $.and_expression,
        $.or_expression,
        $.in_expression,
        $.is_null_expression,
        $.like_expression,
        $.match_expression,
        $._value_expression,
      ),

    not_expression: ($) => prec(PREC.not, seq(kw("not"), field("operand", $._boolean_expression))),

    and_expression: ($) =>
      prec.left(PREC.and, seq(field("left", $._boolean_expression), kw("and"), field("right", $._boolean_expression))),

    or_expression: ($) =>
      prec.left(PREC.or, seq(field("left", $._boolean_expression), kw("or"), field("right", $._boolean_expression))),

    in_expression: ($) =>
      prec(
        PREC.predicate,
        choice(
          seq(
            field("left", $._value_expression),
            optional(field("negated", kw("not"))),
            kw("in"),
            choice(
              seq("(", commaSep1(field("value", $._value_expression)), ")"),
              // `x IN (FROM …)`: 9.5 and later.
              field("subquery", $.source_subquery),
            ),
          ),
          // `(a, b) IN (FROM …)`: 9.6 and later.
          seq(
            field("left", $.in_tuple),
            optional(field("negated", kw("not"))),
            kw("in"),
            field("subquery", $.source_subquery),
          ),
        ),
      ),

    in_tuple: ($) =>
      seq("(", $._value_expression, repeat1(seq(",", $._value_expression)), ")"),

    is_null_expression: ($) =>
      prec(
        PREC.predicate,
        seq(field("operand", $._value_expression), kw("is"), optional(field("negated", kw("not"))), kw("null")),
      ),

    like_expression: ($) =>
      prec(
        PREC.predicate,
        seq(
          field("left", $._value_expression),
          optional(field("negated", kw("not"))),
          field("operator", choice(kw("like"), kw("rlike"))),
          choice(
            field("pattern", $._primary_expression),
            seq("(", commaSep1(field("pattern", choice($.string, $.parameter))), ")"),
          ),
        ),
      ),

    match_expression: ($) =>
      prec(
        PREC.predicate,
        seq(field("field", $._primary_expression), ":", field("query", $._constant)),
      ),

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
      choice($.unary_expression, $.binary_expression, $._primary_expression),

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

    _primary_expression: ($) =>
      choice(
        $._constant,
        $.qualified_name,
        $.function_call,
        $.parenthesized_expression,
        $.inline_cast,
      ),

    parenthesized_expression: ($) => seq("(", $._boolean_expression, ")"),

    inline_cast: ($) =>
      prec.left(PREC.cast, seq(field("value", $._primary_expression), "::", field("type", $.type_name))),

    type_name: ($) => $.identifier,

    function_call: ($) =>
      prec(
        PREC.cast + 1,
        seq(
          field("name", choice($.identifier, $.parameter, alias(kw("first"), $.identifier), alias(kw("last"), $.identifier))),
          "(",
          optional(
            choice(
              field("arguments", alias("*", $.star)),
              seq(
                commaSep1(field("arguments", $._boolean_expression)),
                optional(seq(",", field("options", $.map_expression))),
              ),
            ),
          ),
          ")",
        ),
      ),

    map_expression: ($) => seq("{", optional(commaSep1($.map_entry)), "}"),

    map_entry: ($) =>
      seq(field("key", $.string), ":", field("value", choice($._constant, $.map_expression))),

    _constant: ($) =>
      choice(
        $.null,
        $.qualified_interval,
        $.number,
        $.boolean,
        $.parameter,
        $.string,
        $.array,
      ),

    null: (_) => kw("null"),

    boolean: (_) => choice(kw("true"), kw("false")),

    qualified_interval: ($) =>
      prec(1, seq(field("value", $.number), field("unit", alias($.identifier, $.time_unit)))),

    number: (_) =>
      token(
        choice(
          /[0-9]+/,
          /[0-9]+\.[0-9]*([eE][+-]?[0-9]+)?/,
          /\.[0-9]+([eE][+-]?[0-9]+)?/,
          /[0-9]+[eE][+-]?[0-9]+/,
        ),
      ),

    array: ($) =>
      seq("[", commaSep1(choice(seq(optional(choice("+", "-")), $.number), $.boolean, $.string)), "]"),

    string: (_) =>
      token(
        choice(
          seq('"""', /([^\r\n"]|"[^\r\n"]|""[^\r\n"])*/, '"""', optional('"'), optional('"')),
          seq('"', repeat(choice(/[^"\\\r\n]/, /\\[tnr"\\]/, /\\./)), '"'),
        ),
      ),

    // ---- Names (last, so equal-length keywords win the tie) ------------------------------------------------------------

    _name_patterns: ($) => commaSep1($.name_pattern),

    name_pattern: ($) =>
      seq($._id_pattern, repeat(seq(".", $._id_pattern))),

    _id_pattern: ($) => choice($.id_pattern, $.quoted_identifier, $.parameter),

    id_pattern: (_) =>
      /([a-zA-Z*][a-zA-Z0-9_*]*|[_@][a-zA-Z0-9_*]+)/,

    qualified_name: ($) =>
      prec.right(seq($._name_part, repeat(seq(".", $._name_part)))),

    _name_part: ($) => choice($.identifier, $.quoted_identifier, prec(-1, $.parameter)),

    identifier: (_) => /([a-zA-Z][a-zA-Z0-9_]*|[_@][a-zA-Z0-9_]+)/,

    quoted_identifier: (_) => token(seq("`", repeat1(choice(/[^`]/, "``")), "`")),

    parameter: (_) =>
      token(choice("?", "??", /\?\??([a-zA-Z_][a-zA-Z0-9_]*|[0-9]+)/)),
  },
});
