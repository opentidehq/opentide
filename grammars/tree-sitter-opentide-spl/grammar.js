/// <reference types="tree-sitter-cli/dsl" />
// @ts-check

/**
 * Tree-sitter grammar for Splunk Processing Language (SPL).
 *
 * Authored text is tokenized as written. An implicit leading `| search` is a
 * Splunk runtime default, not a rewrite of the source.
 *
 * Unknown commands parse as `unknown_command` so the engine can emit
 * `spl_unknown_command` instead of silently eating them.
 *
 * Comments are ```triple-backtick``` spans. Single-backtick pairs are macros.
 */
module.exports = grammar({
  name: "opentide_spl",

  extras: ($) => [/\s/, $.comment],

  word: ($) => $.identifier,

  rules: {
    source_file: ($) => $.pipeline,

    // Three backticks both sides. Single-backtick pairs are macros, not comments.
    comment: (_) => token(seq("```", /[^`\n]*/, "```")),

    macro: (_) =>
      token(
        seq(
          "`",
          /[A-Za-z_][A-Za-z0-9_]*/,
          optional(seq("(", /[^)`\n]*/, ")")),
          "`",
        ),
      ),

    pipeline: ($) =>
      seq(
        optional("|"),
        choice($.bare_search, $.command, $.macro),
        repeat(seq("|", choice($.command, $.macro))),
      ),

    // Authored `index=main sourcetype=foo` without a `search` keyword.
    // Requires at least one field=value so it does not steal unknown commands.
    bare_search: ($) =>
      seq(field("first", $.field_value), repeat($.search_term)),

    command: ($) =>
      choice(
        $.search_command,
        $.where_command,
        $.eval_command,
        $.stats_command,
        $.rex_command,
        $.table_command,
        $.rename_command,
        $.fields_command,
        $.dedup_command,
        $.sort_command,
        $.head_command,
        $.tail_command,
        $.join_command,
        $.lookup_command,
        $.makemv_command,
        $.mvexpand_command,
        $.tstats_command,
        $.catalog_command,
        $.unknown_command,
      ),

    search_command: ($) => seq("search", field("clause", repeat($.search_term))),

    search_term: ($) =>
      choice(
        $.in_clause,
        $.term_clause,
        $.case_clause,
        $.macro,
        $.subsearch,
        $.field_value,
        $.string,
        $.identifier,
        $.number,
      ),

    in_clause: ($) =>
      seq(
        field("field", $.identifier),
        "IN",
        $.value_list,
      ),

    term_clause: ($) => seq("TERM", "(", field("value", choice($.string, $.identifier)), ")"),

    case_clause: ($) => seq("CASE", "(", field("value", choice($.string, $.identifier)), ")"),

    value_list: ($) =>
      seq("(", commaSep1(choice($.string, $.identifier, $.number)), ")"),

    subsearch: ($) => seq("[", $.pipeline, "]"),

    where_command: ($) => seq("where", field("predicate", $.expression)),

    eval_command: ($) =>
      seq("eval", field("assignments", commaSep1($.assignment))),

    stats_command: ($) =>
      seq(
        "stats",
        field("aggregates", commaSep1($.aggregate_item)),
        optional(seq("by", field("by", commaSep1($.identifier)))),
      ),

    aggregate_item: ($) =>
      seq(
        choice($.function_call, $.identifier),
        optional(seq(choice("as", "AS"), field("alias", $.identifier))),
      ),

    rex_command: ($) =>
      seq(
        "rex",
        optional(seq("field", "=", field("field", $.identifier))),
        field("pattern", $.string),
      ),

    table_command: ($) => seq("table", field("fields", commaSep1($.identifier))),

    rename_command: ($) =>
      seq("rename", field("renames", commaSep1($.rename_item))),

    fields_command: ($) =>
      seq(
        "fields",
        optional(choice("-", "+")),
        field("fields", commaSep1($.identifier)),
      ),

    dedup_command: ($) =>
      seq("dedup", optional($.number), optional(commaSep1($.identifier))),

    sort_command: ($) =>
      seq("sort", optional($.number), field("keys", commaSep1($.sort_item))),

    sort_item: ($) => seq(optional(choice("+", "-")), $.identifier),

    head_command: ($) => seq("head", optional(field("count", $.number))),

    tail_command: ($) => seq("tail", optional(field("count", $.number))),

    join_command: ($) =>
      seq(
        "join",
        optional(field("type_or_field", $.identifier)),
        $.subsearch,
      ),

    lookup_command: ($) =>
      seq("lookup", field("table", $.identifier), optional(commaSep1($.identifier))),

    makemv_command: ($) =>
      seq(
        "makemv",
        optional(seq("delim", "=", $.string)),
        field("field", $.identifier),
      ),

    mvexpand_command: ($) => seq("mvexpand", field("field", $.identifier)),

    tstats_command: ($) =>
      seq(
        "tstats",
        repeat($.tstats_preamble),
        field("aggregates", commaSep1($.aggregate_item)),
        optional(
          seq(
            "from",
            optional(seq("datamodel", "=")),
            field("datamodel", $.identifier),
          ),
        ),
        optional(seq("where", $.expression)),
        optional(seq("by", commaSep1($.identifier))),
      ),

    tstats_preamble: ($) =>
      choice(
        $.macro,
        seq(
          field(
            "option",
            choice(
              "summariesonly",
              "prestats",
              "allow_old_summaries",
              "fillnull_value",
            ),
          ),
          "=",
          field("value", choice($.boolean, $.identifier, $.string, $.number)),
        ),
      ),

    catalog_command: ($) =>
      seq(field("name", $.catalog_command_name), optional($.argument_list)),

    catalog_command_name: ($) =>
      choice(
        "metadata",
        "inputlookup",
        "makeresults",
        "from",
        "rest",
        "datamodel",
        "inputcsv",
        "loadjob",
        "gentimes",
        "metasearch",
        "mstats",
        "mpreview",
        "pivot",
        "savedsearch",
        "multisearch",
        "set",
        "eventcount",
        "dbinspect",
        "walklex",
        "searchtxn",
        "timechart",
        "chart",
        "top",
        "rare",
        "transaction",
        "eventstats",
        "streamstats",
        "xyseries",
        "geostats",
        "addtotals",
        "contingency",
        "anomalydetection",
        "mvcombine",
        "sistats",
        "sichart",
        "sitimechart",
        "sitop",
        "sirare",
        "timewrap",
        "regex",
        "fillnull",
        "filldown",
        "convert",
        "replace",
        "setfields",
        "fieldformat",
        "reltime",
        "addinfo",
        "spath",
        "xmlkv",
        "extract",
        "kv",
        "erex",
        "kvform",
        "multikv",
        "nomv",
        "strcat",
        "bin",
        "bucket",
        "rangemap",
        "untable",
        "iplocation",
        "tags",
        "xpath",
        "xmlunescape",
        "tojson",
        "fromjson",
        "outputlookup",
        "append",
        "appendcols",
        "appendpipe",
        "selfjoin",
        "return",
        "format",
        "foreach",
        "union",
        "map",
        "reverse",
        "cluster",
        "outlier",
        "fieldsummary",
        "transpose",
        "uniq",
        "concurrency",
        "localop",
        "noop",
        "redistribute",
        "require",
        "collect",
        "delete",
        "sendemail",
        "script",
        "outputcsv",
        "kmeans",
        "highlight",
        "history",
        "mcollect",
        "geom",
        "makecontinuous",
        "localize",
        "scrub",
        "abstract",
        "accum",
        "addcoltotals",
        "analyzefields",
        "anomalies",
        "anomalousvalue",
        "arules",
        "associate",
        "autoregress",
        "bucketdir",
        "cofilter",
        "correlate",
        "delta",
        "diff",
        "findtypes",
        "folderize",
        "gauge",
        "geomfilter",
        "iconify",
        "meventcollect",
        "msearch",
        "outputtext",
        "overlap",
        "predict",
        "rtorder",
        "sendalert",
        "trendline",
        "tscollect",
        "typeahead",
        "typelearner",
        "typer",
        "x11",
      ),

    unknown_command: ($) =>
      seq(field("name", $.identifier), optional($.argument_list)),

    argument_list: ($) =>
      repeat1(
        choice(
          $.macro,
          $.subsearch,
          $.field_value,
          $.string,
          $.identifier,
          $.number,
        ),
      ),

    assignment: ($) =>
      seq(field("name", $.identifier), "=", field("value", $.expression)),

    rename_item: ($) =>
      seq(field("old", $.identifier), "AS", field("new", $.identifier)),

    field_value: ($) =>
      seq(
        field("field", $.identifier),
        "=",
        field("value", choice($.string, $.identifier, $.number, $.value_list)),
      ),

    expression: ($) => $.or_expression,

    or_expression: ($) =>
      prec.left(
        1,
        seq($.and_expression, repeat(seq(choice("OR", "or"), $.and_expression))),
      ),

    and_expression: ($) =>
      prec.left(
        2,
        seq(
          $.comparison_expression,
          repeat(seq(choice("AND", "and"), $.comparison_expression)),
        ),
      ),

    comparison_expression: ($) =>
      prec.left(
        3,
        seq(
          $.additive_expression,
          optional(
            choice(
              seq("IN", $.value_list),
              seq(
                choice("==", "!=", "<", ">", "<=", ">=", "=", "LIKE"),
                $.additive_expression,
              ),
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
      choice(
        seq(choice("NOT", "not", "-", "+"), $.primary_expression),
        $.primary_expression,
      ),

    primary_expression: ($) =>
      choice(
        $.function_call,
        $.macro,
        $.identifier,
        $.string,
        $.number,
        $.boolean,
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

    // Dots allowed so CIM-prefixed fields (Processes.user) are one token.
    identifier: (_) => /[A-Za-z_][A-Za-z0-9_:.]*/,

    string: (_) =>
      token(
        choice(
          seq('"', repeat(choice(/[^"\\]/, /\\./)), '"'),
          seq("'", repeat(choice(/[^'\\]/, /\\./)), "'"),
        ),
      ),

    number: (_) => token(/[0-9]+(\.[0-9]+)?/),

    boolean: (_) => choice("true", "false", "TRUE", "FALSE"),
  },
});

function commaSep1(rule) {
  return seq(rule, repeat(seq(",", rule)));
}
