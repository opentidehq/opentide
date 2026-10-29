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

  // Upper-case boolean operators are reserved in search (`a AND OR b` is an
  // error); lower-case `and`/`or`/`not` are plain search terms.
  reserved: {
    global: (_) => ["AND", "OR", "NOT"],
  },

  rules: {
    source_file: ($) => $.pipeline,

    // Three or more backticks both sides, spanning lines. The body holds no
    // run of three backticks, so the first such run closes the comment.
    // Single-backtick pairs are macros, not comments.
    comment: (_) => token(seq(/`{3,}/, /([^`]|`[^`]|``[^`])*/, /`{3,}/)),

    macro: (_) =>
      token(
        seq(
          "`",
          // ESCU filter macros can start with a digit (`7zip_..._filter`).
          /[A-Za-z0-9_]+/,
          // Arguments may be quoted, hold `)` inside quotes, and span lines.
          optional(seq("(", /[^`]*/, ")")),
          "`",
        ),
      ),

    pipeline: ($) =>
      seq(
        optional("|"),
        choice($.bare_search, $.command, $.macro),
        repeat(seq("|", choice($.command, $.macro))),
      ),

    // Authored `index=main sourcetype=foo` without a `search` keyword. It
    // must not start with a bare word, so a leading unknown command stays an
    // `unknown_command`: it starts with `field=value`, `field IN (...)`, a
    // quoted phrase, `NOT`, a group, `TERM()`/`CASE()`, a value that is not a
    // name, or a macro followed by more terms (a lone macro is its own stage).
    bare_search: ($) =>
      choice(
        seq(field("first", $._bare_search_head), repeat($._search_more)),
        seq(field("first", $.macro), repeat1($._search_more)),
      ),

    _bare_search_head: ($) =>
      choice(
        $._search_not,
        alias($._bare_search_term, $.search_term),
      ),

    _bare_search_term: ($) =>
      choice(
        $.search_group,
        $.in_clause,
        $.term_clause,
        $.case_clause,
        $.subsearch,
        $.field_value,
        $.string,
        $.glob,
        $.number,
        $.search_word,
      ),

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

    search_command: ($) =>
      seq("search", optional(field("clause", $.search_expression))),

    // Splunk search syntax, shared by the base search, `search`, `tstats ...
    // where` and subsearch bodies. Adjacent terms are ANDed; `AND` and `OR`
    // sit between two terms and `NOT` before one. The operators are flat (no
    // precedence tree): the parse only has to accept what Splunk accepts.
    search_expression: ($) => seq($._search_unary, repeat($._search_more)),

    _search_more: ($) =>
      seq(
        optional(alias(choice("AND", "OR"), $.search_boolean)),
        $._search_unary,
      ),

    _search_unary: ($) => choice($._search_not, $.search_term),

    _search_not: ($) => seq(alias("NOT", $.search_boolean), $._search_unary),

    search_term: ($) =>
      choice(
        $.search_group,
        $.in_clause,
        $.term_clause,
        $.case_clause,
        $.prefix_clause,
        $.macro,
        $.subsearch,
        $.field_value,
        $.string,
        $.glob,
        $.identifier,
        $.number,
        $.search_word,
      ),

    // `(EventCode=4624 OR EventCode=4625)`
    search_group: ($) => seq("(", $.search_expression, ")"),

    // `app IN ("a", "b")` or `app IN ("a" "b")`.
    in_clause: ($) =>
      seq(field("field", $._search_field), "IN", $.value_list),

    // TERM, CASE and PREFIX take their contents raw up to the closing `)`:
    // `TERM(EventID=4688)`, `TERM(user=)`, `TERM(a/*)`.
    term_clause: ($) =>
      seq("TERM", "(", optional(field("value", $.term_text)), ")"),

    case_clause: ($) =>
      seq("CASE", "(", optional(field("value", $.term_text)), ")"),

    // tstats `PREFIX(src=)`.
    prefix_clause: ($) =>
      seq("PREFIX", "(", optional(field("value", $.term_text)), ")"),

    term_text: (_) => token(prec(-1, /[^)\s][^)]*/)),

    value_list: ($) => seq("(", sepBy1($._search_value), ")"),

    // A field compared in a search: a name, a quoted name, or any other run
    // of non-breaking characters (`alert.attack-time`, `{}.Id`).
    _search_field: ($) => choice($.identifier, $.string, $.search_word),

    _search_value: ($) =>
      choice($.string, $.glob, $.identifier, $.number, $.macro, $.search_word),

    subsearch: ($) => seq("[", $.pipeline, "]"),

    where_command: ($) => seq("where", field("predicate", $.expression)),

    eval_command: ($) =>
      seq("eval", field("assignments", commaSep1($.assignment))),

    // Aggregations and by-fields are separated by spaces or commas.
    stats_command: ($) =>
      seq(
        "stats",
        field("aggregates", sepBy1($.aggregate_item)),
        optional(seq(choice("by", "BY"), field("by", sepBy1($.identifier)))),
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

    table_command: ($) => seq("table", field("fields", sepBy1($.field_name))),

    // A field list entry: a name or a wildcard pattern (`user*`, `*`).
    field_name: ($) => choice($.identifier, $.glob),

    rename_command: ($) =>
      seq("rename", field("renames", commaSep1($.rename_item))),

    fields_command: ($) =>
      seq(
        "fields",
        optional(choice("-", "+")),
        field("fields", sepBy1($.field_name)),
      ),

    // Splunk requires at least one field.
    dedup_command: ($) =>
      seq(
        "dedup",
        optional($.number),
        repeat($.dedup_option),
        field("fields", sepBy1($.identifier)),
        repeat($.dedup_option),
        optional(seq("sortby", field("sortby", sepBy1($.sort_item)))),
      ),

    dedup_option: ($) =>
      seq(
        choice("keepevents", "keepempty", "consecutive"),
        "=",
        choice($.boolean, $.identifier),
      ),

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
        field("aggregates", sepBy1($.aggregate_item)),
        optional(
          seq(
            choice("from", "FROM"),
            optional(seq("datamodel", "=")),
            field("datamodel", $.identifier),
          ),
        ),
        optional(seq(choice("where", "WHERE"), field("where", $.search_expression))),
        optional(
          seq(
            choice("by", "BY"),
            sepBy1($.identifier),
            optional(seq("span", "=", field("span", choice($.identifier, $.number, $.search_word)))),
          ),
        ),
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

    // `field=value`, `"a.b"=x`, `earliest=-1h@h`, `_index_latest=@m`,
    // `version=2.0.0`, `host=S-RC*`, `domain_rank=-1`.
    field_value: ($) =>
      seq(
        field("field", $._search_field),
        field("operator", choice("=", "!=", "<", ">", "<=", ">=")),
        field("value", choice($._search_value, $.value_list)),
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

    // Broad tokens last: on an equal-length match the earlier rule wins.
    // Search wildcards: any run of non-breaking characters with a `*` in it
    // (`fail*`, `*fail`, `f*il`, `S-RC*`, `C:\\*.exe`, bare `*`). Not part of
    // `identifier`, so `*` in eval stays multiplication. The engine warns on
    // bare, leading, and mid-token globs; a trailing `fail*` is fine.
    glob: (_) => token(/[^\s"()\[\]|=<>!,`*]*\*[^\s"()\[\]|=<>!,`]*/),

    // A search value or field that is neither a name, a number nor a string:
    // `-1h@h`, `2.0.0`, `svc-x`, `10.0.0.0/8`, `{}.Id`, and the time
    // modifier `latest=now()`. Last in the grammar, so an equal-length
    // `identifier`, `string` or `number` wins.
    search_word: (_) => token(choice(/[^\s"()\[\]|=<>!,`*]+/, /[A-Za-z_]+\(\)/)),
  },
});

function sepBy1(rule) {
  return seq(rule, repeat(seq(optional(","), rule)));
}

function commaSep1(rule) {
  return seq(rule, repeat(seq(",", rule)));
}
