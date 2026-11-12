/// <reference types="tree-sitter-cli/dsl" />
// @ts-check

/**
 * Tree-sitter grammar for YARA-L 2.0, the detection and search language of
 * Google Security Operations (opentide yara-l-1.0).
 *
 * Google publishes no grammar for YARA-L: this one is written for the
 * language spec (specifications/specs/languages/yara-l-1.0.md) from
 * Google's syntax pages. It covers both text forms:
 *
 * - a rule (`rule <name> { meta: … events: … }`), with every section a rule
 *   or a search can carry, in any order: the engine (crates/opentide-yaral)
 *   reports `yaral_section_order` and `yaral_section_unavailable`, not the
 *   parser;
 * - a search: the `events` predicates with or without the `events:` label,
 *   the search sections (`dedup`, `order`, `limit`, `select`, `unselect`),
 *   and named `stage <name> { … }` blocks before the root stage.
 *
 * Keywords are case-insensitive. A regular expression per keyword cannot
 * be extracted by `word`, and lexical precedence beats match length in
 * tree-sitter (`metadata` would lex as `meta`), so `kw` spells each keyword
 * lower case, upper case and title case, the forms Google's own rules use;
 * the engine reports nothing on case. Newlines are whitespace: the
 * predicates of `events` are juxtaposed statements, which the engine joins
 * with an implicit `and`. Field paths are `$var` (or, in a search, a bare
 * first segment) followed by `.segment` and `[index]` accessors written
 * without blanks, so a UDM segment named like a keyword (`network.dhcp.options`)
 * stays a field name.
 */

const PREC = {
  or: 1,
  and: 2,
  not: 3,
  comparison: 4,
  additive: 5,
  multiplicative: 6,
  unary: 7,
  quantified: 8,
};

/**
 * A keyword in the spellings rules use (`and`, `AND`, `And`), exposed as the
 * lower-case anonymous node. Strings, not a case-insensitive regex, so
 * `word` extraction lexes an identifier first and only then asks whether it
 * is a keyword: `metadata` stays a name, and `false` is a keyword wherever a
 * name could also stand.
 */
function kw(word) {
  const title = word.charAt(0).toUpperCase() + word.slice(1);
  const spellings = [...new Set([word, word.toUpperCase(), title])];
  return alias(choice(...spellings), word);
}

function commaSep1(rule) {
  return seq(rule, repeat(seq(",", rule)));
}

/** A section: its case-insensitive label, `:`, then its body. */
function section(name, body) {
  return seq(kw(name), ":", body);
}

module.exports = grammar({
  name: "opentide_yaral",

  extras: ($) => [/\s/, $.comment],

  word: ($) => $.identifier,

  conflicts: ($) => [
    [$.data_table_column, $.table_call],
  ],

  rules: {
    source_file: ($) => optional(choice(repeat1($.rule_declaration), $.search_query)),

    comment: (_) =>
      token(choice(seq("//", /[^\n]*/), seq("/*", /[^*]*\*+([^/*][^*]*\*+)*/, "/"))),

    // ── Rules ──────────────────────────────────────────────────────────────

    rule_declaration: ($) =>
      seq(
        kw("rule"),
        field("name", alias($.identifier, $.rule_name)),
        "{",
        repeat($._section),
        "}",
      ),

    _section: ($) =>
      choice(
        $.meta_section,
        $.setup_section,
        $.events_section,
        $.match_section,
        $.outcome_section,
        $.condition_section,
        $.options_section,
        $.export_section,
        $.dedup_section,
        $.order_section,
        $.limit_section,
        $.select_section,
        $.unselect_section,
      ),

    meta_section: ($) => section("meta", repeat($.meta_entry)),

    meta_entry: ($) =>
      seq(
        field("key", alias($.identifier, $.meta_key)),
        "=",
        field("value", $._setting_value),
      ),

    _setting_value: ($) =>
      choice(
        $.string,
        $.raw_string,
        $.integer,
        $.float,
        $.duration,
        $.boolean,
        $.identifier,
      ),

    setup_section: ($) => section("setup", repeat(choice($.graph_operation, $._statement))),

    // graph_override (join), graph_exclude (join), graph_append [$g, %table].
    graph_operation: ($) =>
      choice(
        seq(
          field("operation", choice(kw("graph_override"), kw("graph_exclude"))),
          "(",
          field("join", $._expression),
          ")",
        ),
        seq(field("operation", kw("graph_append")), field("arguments", $.array)),
      ),

    events_section: ($) => section("events", repeat($._statement)),

    match_section: ($) => section("match", optional($.match_clause)),

    match_clause: ($) =>
      seq(
        field("key", $._match_key),
        repeat(seq(",", field("key", $._match_key))),
        optional(field("window", $.match_window)),
      ),

    _match_key: ($) => choice($.variable, $.udm_field, $.bare_field),

    // over <d>, by <d>, over <d> before|after $pivot; a search also takes
    // `over every`, `by first`, and a unit word (`by day`, `by 1 hour`).
    match_window: ($) =>
      seq(
        field("kind", choice(kw("over"), kw("by"))),
        optional(kw("every")),
        optional(kw("first")),
        field("length", choice($.duration, seq(optional($.integer), alias($.identifier, $.time_unit)))),
        optional(
          seq(
            field("direction", choice(kw("before"), kw("after"))),
            field("pivot", $.variable),
          ),
        ),
      ),

    outcome_section: ($) => section("outcome", repeat($._statement)),

    condition_section: ($) => section("condition", repeat($._statement)),

    options_section: ($) => section("options", repeat($.option_entry)),

    option_entry: ($) =>
      seq(
        field("key", alias($.identifier, $.option_key)),
        "=",
        field("value", $._setting_value),
      ),

    export_section: ($) => section("export", repeat($._statement)),

    dedup_section: ($) => section("dedup", optional(commaSep1($._expression))),

    order_section: ($) => section("order", optional(commaSep1($.order_item))),

    order_item: ($) =>
      seq(field("value", $._expression), optional(field("direction", choice(kw("asc"), kw("desc"))))),

    limit_section: ($) => section("limit", optional(field("value", $.integer))),

    select_section: ($) => section("select", optional(commaSep1($._expression))),

    unselect_section: ($) => section("unselect", optional(commaSep1($._expression))),

    // ── Searches ───────────────────────────────────────────────────────────

    search_query: ($) => seq(repeat($.stage), $._search_body),

    _search_body: ($) =>
      choice(seq($.search_events, repeat($._section)), repeat1($._section)),

    // The events of a search written without the `events:` label.
    search_events: ($) => repeat1($._statement),

    stage: ($) =>
      seq(
        kw("stage"),
        field("name", alias($.identifier, $.stage_name)),
        "{",
        optional($._search_body),
        "}",
      ),

    // ── Expressions ────────────────────────────────────────────────────────

    // One predicate, assignment, or condition term. Statements are written
    // one after the other; the engine joins the predicates of `events` with
    // an implicit `and`.
    _statement: ($) => $._expression,

    _expression: ($) =>
      choice(
        $.or_expression,
        $.and_expression,
        $.not_expression,
        $.comparison,
        $.in_expression,
        $.binary_expression,
        $.unary_expression,
        $.of_expression,
        $._primary,
      ),

    or_expression: ($) =>
      prec.left(PREC.or, seq(field("left", $._expression), kw("or"), field("right", $._expression))),

    and_expression: ($) =>
      prec.left(
        PREC.and,
        seq(field("left", $._expression), kw("and"), field("right", $._expression)),
      ),

    not_expression: ($) => prec(PREC.not, seq(kw("not"), field("operand", $._expression))),

    comparison: ($) =>
      prec.left(
        PREC.comparison,
        seq(
          field("left", $._expression),
          field("operator", choice("=", "!=", "<", "<=", ">", ">=")),
          field("right", $._expression),
          optional(field("nocase", kw("nocase"))),
        ),
      ),

    // <expr> in %list, in regex %list, in cidr %list, in %table.column.
    in_expression: ($) =>
      prec.left(
        PREC.comparison,
        seq(
          field("left", $._expression),
          kw("in"),
          optional(field("kind", choice(kw("regex"), kw("cidr")))),
          field("right", choice($.reference_list, $.data_table_column)),
          optional(field("nocase", kw("nocase"))),
        ),
      ),

    binary_expression: ($) =>
      choice(
        prec.left(
          PREC.additive,
          seq(field("left", $._expression), field("operator", choice("+", "-")), field("right", $._expression)),
        ),
        prec.left(
          PREC.multiplicative,
          seq(
            field("left", $._expression),
            field("operator", choice("*", "/", "%")),
            field("right", $._expression),
          ),
        ),
      ),

    unary_expression: ($) =>
      prec(PREC.unary, seq(field("operator", choice("-", "!")), field("operand", $._expression))),

    // any of [$a, $b], all of [...], 2 of [...] (condition).
    of_expression: ($) =>
      seq(
        field("quantifier", choice(kw("any"), kw("all"), $.integer)),
        kw("of"),
        field("terms", $.array),
      ),

    _primary: ($) =>
      choice(
        $.parenthesized_expression,
        $.quantified_field,
        $.udm_field,
        $.bare_field,
        $.variable,
        $.count,
        $.function_call,
        $.if_expression,
        $.table_call,
        $.reference_list,
        $.data_table_column,
        $.array,
        $.string,
        $.raw_string,
        $.regex,
        $.float,
        $.integer,
        $.duration,
        $.boolean,
        $.window_bound,
      ),

    parenthesized_expression: ($) => seq("(", $._expression, ")"),

    // any $e.ip = "…", all $e.ip != "…": a repeated field's modifier.
    quantified_field: ($) =>
      prec(
        PREC.quantified,
        seq(
          field("quantifier", choice(kw("any"), kw("all"))),
          field("field", choice($.udm_field, $.bare_field, $.variable)),
        ),
      ),

    // $e.metadata.event_type, $e.additional.fields["k"], $e.target.ip[0],
    // $stage.window_start.
    udm_field: ($) => seq(field("variable", $.variable), repeat1($._accessor)),

    // A search names fields without an event variable: principal.hostname.
    bare_field: ($) =>
      seq(
        field("root", alias($.identifier, $.field_name)),
        $._member,
        repeat($._accessor),
      ),

    _accessor: ($) => choice($._member, $.index),

    _member: ($) => seq(token.immediate("."), field("segment", $.field_name)),

    field_name: (_) => token.immediate(/[A-Za-z_][A-Za-z0-9_]*/),

    index: ($) =>
      seq(token.immediate("["), field("key", choice($.string, $.raw_string, $.integer)), "]"),

    // strings.to_lower(x), count(x), %table.write_row(col: $v).
    // `re.regex($e.f, `x`) nocase`: the modifier follows the call.
    function_call: ($) =>
      prec.right(
        seq(
          field("function", $.function_name),
          "(",
          optional($.arguments),
          ")",
          optional(field("nocase", kw("nocase"))),
        ),
      ),

    function_name: ($) =>
      choice(
        prec(
          1,
          seq(
            field("namespace", alias($.identifier, $.namespace)),
            token.immediate("."),
            field("name", alias($.field_name, $.name)),
          ),
        ),
        // `count (x)` is a call, not `count` then a parenthesised term.
        prec(1, field("name", alias($.identifier, $.name))),
      ),

    arguments: ($) => commaSep1(choice($.named_argument, $._expression)),

    // write_row(column: $value), metrics.*(period: 1d, principal.user.userid: $u).
    named_argument: ($) =>
      seq(
        field("name", choice(alias($.identifier, $.argument_name), $.bare_field)),
        ":",
        // metrics.*(metric: value_sum, agg: max) names its settings bare.
        field("value", choice($._expression, $.identifier)),
      ),

    table_call: ($) =>
      seq(
        field("table", $.reference_list),
        ".",
        field("function", alias($.identifier, $.name)),
        "(",
        optional($.arguments),
        ")",
      ),

    if_expression: ($) =>
      seq(
        kw("if"),
        "(",
        field("condition", $._expression),
        ",",
        field("then", $._expression),
        optional(seq(",", field("else", $._expression))),
        ")",
      ),

    array: ($) => seq("[", optional(seq(commaSep1($._expression), optional(","))), "]"),

    // ── Tokens ─────────────────────────────────────────────────────────────

    variable: (_) => token(/\$[A-Za-z_][A-Za-z0-9_]*/),

    count: (_) => token(/#[A-Za-z_][A-Za-z0-9_]*/),

    reference_list: (_) => token(/%[A-Za-z_][A-Za-z0-9_]*/),

    // `%table.column`. Google's own community rules break the line before
    // the dot, so the dot is not immediate.
    data_table_column: ($) =>
      seq(field("table", $.reference_list), ".", field("column", alias($.identifier, $.column))),

    // Escapes are checked by the engine (yaral_string_escape).
    string: (_) => token(seq('"', repeat(choice(/[^"\\\n]/, /\\[^\n]/)), '"')),

    raw_string: (_) => token(seq("`", /[^`]*/, "`")),

    // `/…/`: RE2, `\/` a literal slash. A regex never starts with `*` or
    // `/`, so `/*` and `//` stay comments.
    regex: (_) =>
      token(seq("/", choice(/[^/*\\\n]/, /\\[^\n]/), repeat(choice(/[^/\\\n]/, /\\[^\n]/)), "/")),

    integer: (_) => token(/[0-9]+/),

    float: (_) => token(/[0-9]+\.[0-9]+/),

    // 10m, 1h, 2d; a search also takes w and mo. The engine checks the unit.
    duration: (_) => token(/[0-9]+[A-Za-z]+/),

    boolean: (_) => choice(kw("true"), kw("false")),

    // The reserved timestamps of a match window, bare in outcome, condition
    // and order. A keyword elsewhere is never a term: `or or` is an error.
    window_bound: (_) => choice(kw("window_start"), kw("window_end")),

    identifier: (_) => /[A-Za-z_][A-Za-z0-9_]*/,
  },
});
