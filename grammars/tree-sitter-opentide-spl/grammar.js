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
/** Search comparisons Splunk parses but splits into separate terms. */
const LOOSE_OPERATORS = ["==", "<>", "=>", "=<", "!~"];

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

    // The query. Splunk runs text that does not start with `|` as `search
    // <text>`, so a first stage with no pipe is search terms even when its
    // first word is a command name (`tstats count where ...` searches for the
    // word `tstats`; the engine reports spl_command_without_pipe). After a
    // leading `|` the first stage is a command (`| index=a` is an unknown
    // command to Splunk). Splunk ignores an empty last stage (`... |`); an
    // empty stage anywhere else is an error ("Missing a search command").
    pipeline: ($) =>
      seq(
        choice(
          seq(
            "|",
            choice(
              $.command,
              $.macro,
              alias($._macro_search, $.bare_search),
              alias($._inputlookup_alone, $.inputlookup_command),
            ),
          ),
          choice(
            $.search_command,
            $.macro,
            alias($._unpiped_search, $.bare_search),
          ),
        ),
        repeat(seq("|", choice($.command, $.macro))),
        optional("|"),
      ),

    // A subsearch body. Splunk runs a leading command word here as the
    // command (`[makeresults | ...]`, `[inputlookup t.csv]`), and rejects a
    // trailing empty stage (`[search a |]`).
    _subsearch_pipeline: ($) =>
      seq(
        optional("|"),
        choice(
          $.bare_search,
          $.command,
          $.macro,
          alias($._inputlookup_alone, $.inputlookup_command),
        ),
        repeat(seq("|", choice($.command, $.macro))),
      ),

    // Authored `index=main sourcetype=foo` without a `search` keyword. In a
    // subsearch it must not start with a bare word, so a leading unknown
    // command stays an `unknown_command`: it starts with `field=value`,
    // `field IN (...)`, a quoted phrase, `NOT`, a group, `TERM()`/`CASE()`,
    // a value that is not a name, or a macro followed by more terms (a lone
    // macro is its own stage).
    bare_search: ($) =>
      choice(
        seq(field("first", $._bare_search_head), repeat($._search_more)),
        $._macro_search,
      ),

    _macro_search: ($) => seq(field("first", $.macro), repeat1($._search_more)),

    // The first stage of the query with no leading `|`: any search terms,
    // including a leading bare word (`error`, `tstats count ...`).
    _unpiped_search: ($) =>
      choice(
        seq(
          field(
            "first",
            choice($._bare_search_head, alias($._leading_word, $.search_term)),
          ),
          repeat($._search_more),
        ),
        $._macro_search,
      ),

    _leading_word: ($) => $.identifier,

    // `| inputlookup` with no table, first in a search: Splunk parses it and
    // fails at run time (spl_empty_command). Later in a pipeline Splunk
    // rejects it ("must be the first command").
    _inputlookup_alone: (_) => "inputlookup",

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
        $.fillnull_command,
        $.foreach_command,
        $.spath_command,
        $.tojson_command,
        $.inputlookup_command,
        $.outputlookup_command,
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
    // `TERM(EventID=4688)`, `TERM(user=)`, `TERM(a/*)`. Splunk also accepts
    // the directive left open (`TERM(EventID=4688` at the end of the search
    // or before the next pipe), so the `)` is optional and the contents stop
    // at whitespace.
    term_clause: ($) => directive("TERM", $),

    case_clause: ($) => directive("CASE", $),

    // tstats `PREFIX(src=)`, in a `by` clause or an aggregate. Splunk rejects
    // it as a `where` term, so it is not a search term.
    prefix_clause: ($) => directive("PREFIX", $),

    // A run of non-whitespace up to `)`; a quoted part may hold anything.
    // An unquoted `|` ends the stage, as in Splunk: `TERM(x|y)` is `TERM(x`
    // then a command `y)`.
    term_text: (_) => token(/([^)\s"|]|"([^"\\]|\\.)*")+/),

    value_list: ($) => seq("(", sepBy1($._search_value), ")"),

    // A field compared in a search: a name, a quoted name, or any other run
    // of non-breaking characters (`alert.attack-time`, `{}.Id`).
    // A term followed by `==` is the field of that comparison (`x==1`),
    // not a term before a comparison with no field (`==1`).
    _search_field: ($) => prec(1, choice($.identifier, $.string, $.search_word)),

    _search_value: ($) =>
      choice($.string, $.glob, $.identifier, $.number, $.macro, $.search_word),

    subsearch: ($) => seq("[", alias($._subsearch_pipeline, $.pipeline), "]"),

    // `where` with no predicate keeps every row (spl_empty_command).
    where_command: ($) => seq("where", optional(field("predicate", $.expression))),

    eval_command: ($) =>
      seq("eval", field("assignments", commaSep1($.assignment))),

    // The stats family shares one shape: options, aggregates (each with an
    // optional `as` alias, separated by spaces or commas), then `over` and
    // `by` clauses that may carry options (`by host span=1h limit=0`).
    // Which option a stats-family command takes is the analyzer's business
    // (command-options.toml); the grammar accepts any `name=value`.
    stats_command: ($) =>
      choice(
        // Splunk parses these with no arguments (spl_empty_command).
        seq(
          choice("stats", "eventstats", "streamstats", "sistats"),
          optional(
            seq(
              repeat($.command_option),
              field("aggregates", listOf($._stats_aggregate)),
              statsTail($),
            ),
          ),
        ),
        // chart and timechart may end in `where <agg> in top5` or
        // `where <agg> > 10`.
        seq(
          choice("chart", "timechart", "sichart", "sitimechart"),
          repeat($.command_option),
          field("aggregates", listOf($._stats_aggregate)),
          statsTail($),
          optional($.chart_where),
        ),
        // searchbnf: geostats takes zero or more aggregates. Splunk 10.6.1
        // rejects it with no arguments at all, and a `by` clause with no
        // aggregate.
        seq(
          "geostats",
          choice(
            seq(
              repeat1($.command_option),
              optional(
                seq(field("aggregates", listOf($._stats_aggregate)), statsTail($)),
              ),
            ),
            seq(field("aggregates", listOf($._stats_aggregate)), statsTail($)),
          ),
        ),
      ),

    // A macro may stand for aggregates (`timechart `m` count`).
    _stats_aggregate: ($) => choice($.aggregate_item, $.macro),

    chart_where: ($) =>
      seq(
        kw("where"),
        field("field", choice($.function_call, $._field_name)),
        choice(
          seq(choice(kw("in"), kw("notin")), field("limit", $._field_name)),
          seq(
            field("operator", choice("=", "!=", "<", ">", "<=", ">=")),
            field("value", $.number),
          ),
        ),
      ),

    // `by a, b span=1h`: fields, with options among or after them.
    by_clause: ($) =>
      seq(
        kw("by"),
        field("by", $._by_field),
        repeat(choice(seq(repeat(","), field("by", $._by_field)), $.command_option)),
        repeat(","),
      ),

    // tstats groups by `PREFIX(dst=)` too.
    _by_field: ($) =>
      choice($._field_name, $.prefix_clause, $.string, $.macro, $.subsearch),

    // `count`, `dc(src) as c`, `values(*) as *`, `min(eval(if(...))) as e`,
    // `values(PREFIX(dpt=)) as p`, `earliest(_time) as "earliest"`.
    aggregate_item: ($) =>
      seq(
        field(
          "function",
          choice(alias($.aggregate_call, $.function_call), $.identifier),
        ),
        optional(seq(kw("as"), field("alias", $._alias_name))),
      ),

    aggregate_call: ($) =>
      prec(
        10,
        seq(
          field("name", $.identifier),
          "(",
          field("arguments", optional(commaSep1($._aggregate_argument))),
          ")",
        ),
      ),

    _aggregate_argument: ($) =>
      choice(
        $.function_call,
        $.prefix_clause,
        $.glob,
        $._field_name,
        $.string,
        $.number,
      ),

    _alias_name: ($) => choice($._field_name, $.glob, $.string),

    // `rex [field=f] [max_match=n] [mode=sed] "<regex>"`, options in any
    // order and optionally comma-separated.
    rex_command: ($) =>
      seq(
        "rex",
        repeat(choice($._rex_option, ",")),
        field("pattern", $.string),
        repeat($._rex_option),
      ),

    _rex_option: ($) =>
      choice(
        seq("field", "=", field("field", choice($._field_name, $.string))),
        $.command_option,
      ),

    table_command: ($) => seq("table", field("fields", listOf($.field_name))),

    // A field list entry: a name, a wildcard pattern (`user*`, `*`), or a
    // quoted name.
    field_name: ($) => choice($._field_name, $.glob, $.string, $.macro),

    // `rename a as b, DNS.* as *`. `as` is case-insensitive.
    rename_command: ($) =>
      seq("rename", field("renames", listOf($.rename_item))),

    // The old name may be a field a command named after a call
    // (`IsOutlier(x)`), or one tstats `PREFIX(dst=)` named `dst=`.
    rename_item: ($) =>
      seq(
        field(
          "old",
          choice($._alias_name, $.function_call, alias($._prefix_field, $.identifier)),
        ),
        optional(","),
        kw("as"),
        field("new", $._alias_name),
      ),

    fields_command: ($) =>
      seq(
        "fields",
        optional(choice("-", "+")),
        // No field list keeps every field (spl_empty_command).
        optional(field("fields", listOf($.field_name))),
      ),

    // Splunk requires at least one field.
    dedup_command: ($) =>
      seq(
        "dedup",
        optional($.number),
        repeat($.dedup_option),
        field("fields", sepBy1($.field_name)),
        repeat($.dedup_option),
        optional(seq("sortby", field("sortby", sepBy1($.sort_item)))),
      ),

    dedup_option: ($) =>
      seq(
        choice("keepevents", "keepempty", "consecutive"),
        "=",
        choice($.boolean, $.identifier),
      ),

    // `sort 0 host _time`, `sort -lt limit=0`, `sort limit=0 + src, _time`,
    // `sort num(x) desc`.
    sort_command: ($) =>
      seq(
        "sort",
        optional(field("count", $.number)),
        repeat($.command_option),
        field("keys", sepBy1($.sort_item)),
        repeat($.command_option),
        optional(choice(kw("desc"), kw("d"))),
      ),

    sort_item: ($) =>
      seq(optional(choice("+", "-")), choice($._field_name, $.function_call)),

    head_command: ($) =>
      seq("head", optional(field("count", $.number)), repeat($.command_option)),

    tail_command: ($) => seq("tail", optional(field("count", $.number))),

    // `join type=left a, b [ search ... ]`.
    join_command: ($) =>
      seq(
        "join",
        repeat(choice($.command_option, field("fields", $._field_name), ",")),
        $.subsearch,
      ),

    // `lookup [local=t] <table> f [AS g], ... [OUTPUT|OUTPUTNEW f [AS g], ...]`.
    // Keywords are case-insensitive.
    lookup_command: ($) =>
      seq(
        "lookup",
        // No arguments at all keeps every row (spl_empty_command); options
        // with no table are an error.
        optional(
          seq(
            repeat($.command_option),
            field("table", $._table_name),
            field("inputs", listOf($.lookup_field)),
            // `OUTPUT` with no fields returns every lookup field.
            optional(
              seq(
                choice(kw("output"), kw("outputnew")),
                optional(field("outputs", listOf($.lookup_field))),
              ),
            ),
          ),
        ),
      ),

    lookup_field: ($) =>
      seq(
        field("field", choice($._field_name, $.string)),
        optional(seq(kw("as"), field("alias", choice($._field_name, $.string)))),
      ),

    makemv_command: ($) =>
      seq(
        "makemv",
        repeat(choice(seq("delim", "=", $.string), $.command_option)),
        field("field", $._field_name),
      ),

    mvexpand_command: ($) =>
      seq(
        "mvexpand",
        repeat($.command_option),
        // `mvexpand(x)` also deploys: Splunk splits the name at `(`.
        choice(field("field", $._field_name), seq("(", field("field", $._field_name), ")")),
        repeat($.command_option),
      ),

    tstats_command: ($) =>
      seq(
        "tstats",
        repeat($.tstats_preamble),
        field("aggregates", sepBy1($.aggregate_item)),
        repeat($.tstats_preamble),
        optional(
          seq(
            kw("from"),
            optional(seq("datamodel", "=")),
            field("datamodel", choice($._field_name, $.string)),
          ),
        ),
        optional(seq(kw("where"), field("where", $.search_expression))),
        optional($.by_clause),
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
          field("value", $._option_value),
        ),
        $.command_option,
      ),

    // `fillnull`, `fillnull value="-" a, b`, `fillnull a value=-1`.
    fillnull_command: ($) =>
      seq(
        "fillnull",
        repeat(choice($.command_option, field("fields", $.field_name), ",")),
      ),

    // `foreach * [ eval <<FIELD>>=... ]`, `foreach user* mode=multifield
    // [| eval ...]`. The body is a pipeline in brackets.
    foreach_command: ($) =>
      seq(
        "foreach",
        repeat1(choice($.command_option, field("fields", $.field_name), ",")),
        field("body", $.subsearch),
      ),

    // `spath`, `spath a{}`, `spath input=x path=a{}.b output=y`.
    spath_command: ($) =>
      seq(
        "spath",
        repeat(
          choice(
            $.command_option,
            field("path", choice($._field_name, $.string, $.macro)),
            $.subsearch,
          ),
        ),
      ),

    // `tojson * output_field=j`, `tojson fill_null=true a, b*, str(c)`.
    tojson_command: ($) =>
      seq(
        "tojson",
        repeat(choice($.command_option, field("fields", $.field_name), $.function_call, ",")),
      ),

    // `inputlookup append=t t.csv where (x="a" OR x="b") AND y<=60`.
    inputlookup_command: ($) =>
      seq(
        "inputlookup",
        repeat($.command_option),
        field("table", $._table_name),
        repeat(choice($.command_option, $.subsearch)),
        optional(seq(kw("where"), field("where", $.search_expression))),
      ),

    outputlookup_command: ($) =>
      seq(
        "outputlookup",
        repeat($.command_option),
        field("table", $._table_name),
        repeat($.command_option),
      ),

    // A lookup table: a name, a quoted name or a macro.
    _table_name: ($) => choice($._field_name, $.string, $.macro),

    catalog_command: ($) =>
      choice(
        seq(field("name", $.catalog_command_name), optional($.argument_list)),
        seq(
          field(
            "name",
            alias($._catalog_command_with_arguments, $.catalog_command_name),
          ),
          $.argument_list,
        ),
      ),

    catalog_command_name: ($) =>
      choice(
        "makeresults",
        "datamodel",
        "loadjob",
        "metasearch",
        "mpreview",
        "pivot",
        "eventcount",
        "dbinspect",
        "walklex",
        "searchtxn",
        "addtotals",
        "anomalydetection",
        "filldown",
        "convert",
        "reltime",
        "addinfo",
        "xmlkv",
        "extract",
        "kv",
        "erex",
        "kvform",
        "multikv",
        "untable",
        "tags",
        "xpath",
        "xmlunescape",
        "format",
        "union",
        "reverse",
        "cluster",
        "outlier",
        "fieldsummary",
        "transpose",
        "uniq",
        "localop",
        "noop",
        "redistribute",
        "require",
        "collect",
        "delete",
        "sendemail",
        "outputcsv",
        "kmeans",
        "highlight",
        "history",
        "geom",
        "makecontinuous",
        "localize",
        "scrub",
        "abstract",
        "addcoltotals",
        "anomalies",
        "anomalousvalue",
        "associate",
        "bucketdir",
        "correlate",
        "diff",
        "findtypes",
        "folderize",
        "geomfilter",
        "iconify",
        "meventcollect",
        "msearch",
        "outputtext",
        "overlap",
        "predict",
        "rtorder",
        "sendalert",
        "tscollect",
        "typelearner",
        "typer",
      ),

    // Commands Splunk 10.6.1's parser rejects with no arguments ("No fields
    // were specified", "Usage: ...").
    _catalog_command_with_arguments: (_) =>
      choice(
        "metadata",
        "from",
        "rest",
        "inputcsv",
        "gentimes",
        "mstats",
        "savedsearch",
        "multisearch",
        "set",
        "top",
        "rare",
        "transaction",
        "xyseries",
        "contingency",
        "mvcombine",
        "sitop",
        "sirare",
        "timewrap",
        "regex",
        "replace",
        "setfields",
        "fieldformat",
        "nomv",
        "strcat",
        "bin",
        "bucket",
        "rangemap",
        "iplocation",
        "fromjson",
        "append",
        "appendcols",
        "appendpipe",
        "selfjoin",
        "return",
        "map",
        "concurrency",
        "script",
        "mcollect",
        "accum",
        "analyzefields",
        "arules",
        "autoregress",
        "cofilter",
        "delta",
        "gauge",
        "trendline",
        "typeahead",
      ),

    unknown_command: ($) =>
      seq(field("name", $.identifier), optional($.argument_list)),

    // Arguments of a command with no rule of its own. Permissive on purpose:
    // a known command must never be a syntax error because its arguments are
    // not modelled. Command-specific checks belong in the analyzer
    // (`catalogs/spl/command-options.toml`). `AND`, `OR` and `NOT` are
    // reserved, so a command that takes a search (`metasearch index=a OR
    // index=b`) gets them as booleans here.
    argument_list: ($) =>
      repeat1(
        choice(
          $.macro,
          $.subsearch,
          alias(choice("AND", "OR", "NOT"), $.search_boolean),
          $.command_option,
          $.comparison,
          $.function_call,
          $.string,
          $._field_name,
          $.number,
          $.glob,
          $.search_word,
          ",",
        ),
      ),

    // `name=value`: `limit=0`, `type=left`, `current=f`, `value=-1`,
    // `span=1h`, `path={}`, `timeformat="%Y"`, `x=tostring(y)`.
    command_option: ($) =>
      seq(
        field("name", $._field_name),
        "=",
        field("value", $._option_value),
      ),

    _option_value: ($) =>
      choice(
        $.function_call,
        $.string,
        alias($._quoted_compound, $.string),
        $.number,
        $.boolean,
        $._field_name,
        $.glob,
        $.search_word,
        $.macro,
        $.value_list,
      ),

    // `x!=y`, `x>5` in a command with no rule of its own (`regex _raw!="a"`).
    comparison: ($) =>
      seq(
        field("field", $._field_name),
        field("operator", choice("!=", "<", ">", "<=", ">=")),
        field("value", $._option_value),
      ),

    // A field name outside eval: letters, digits and `_ . : - { } @ $`
    // (`alert.attack-time`, `a{}.b`, `t-include.csv`). Exposed as
    // `identifier`; eval names stay narrow so `a-b` subtracts.
    _field_name: ($) => choice($.identifier, alias($._field_token, $.identifier)),


    assignment: ($) =>
      seq(
        field(
          "name",
          choice(
            $.identifier,
            $.string,
            alias($._dynamic_name, $.identifier),
            alias($._template_name, $.identifier),
          ),
        ),
        "=",
        field("value", $.expression),
      ),

    // `field=value`, `"a.b"=x`, `earliest=-1h@h`, `_index_latest=@m`,
    // `version=2.0.0`, `host=S-RC*`, `domain_rank=-1`.
    //
    // Splunk 10.6.1 also parses `==`, `<>`, `=>`, `=<` and `!~` in a search,
    // with or without a term on either side (`x==1`, `x == 1`, `a==`, `==1`),
    // and splits them into separate terms (`x==1` runs as `x == 1`), so the
    // comparison never matches. They parse here; `tstats ... where` rejects
    // them ("WHERE clause is not an exact query"), which the engine reports.
    // `x=~1` is `=` with the value `~1`, as in Splunk.
    field_value: ($) =>
      choice(
        seq(
          field("field", $._search_field),
          field("operator", choice("=", "!=", "<", ">", "<=", ">=")),
          field("value", choice($._search_value, $.value_list)),
        ),
        prec.right(
          seq(
            optional(field("field", $._search_field)),
            field("operator", choice(...LOOSE_OPERATORS)),
            optional(field("value", $._search_value)),
          ),
        ),
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
                choice("==", "!=", "<", ">", "<=", ">=", "=", "LIKE", "like"),
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
          // `.` concatenates: `a."-".b`.
          repeat(seq(choice("+", "-", "."), $.multiplicative_expression)),
        ),
      ),

    multiplicative_expression: ($) =>
      prec.left(
        5,
        seq($.unary_expression, repeat(seq(choice("*", "/", "%"), $.unary_expression))),
      ),

    unary_expression: ($) =>
      choice(
        seq(choice("NOT", "not", "!", "-", "+"), $.primary_expression),
        $.primary_expression,
      ),

    primary_expression: ($) =>
      choice(
        $.function_call,
        $.macro,
        $.identifier,
        alias($._template_name, $.identifier),
        alias($._token_name, $.identifier),
        $.string,
        $.number,
        $.boolean,
        $.subsearch,
        seq("(", $.expression, ")"),
      ),

    function_call: ($) =>
      prec(
        10,
        seq(
          // `true()` and `false()` are functions; bare `true` is a boolean.
          field("name", choice($.identifier, alias($.boolean, $.identifier))),
          "(",
          field("arguments", optional(commaSep1($.expression))),
          ")",
        ),
      ),

    // Dots allowed so CIM-prefixed fields (Processes.user) are one token,
    // but not at the end, so `a."-".b` is a concatenation.
    identifier: (_) => /[A-Za-z_][A-Za-z0-9_:]*(\.[A-Za-z0-9_:]+)*/,

    // Eval's `{f}=v`: the value of `f` names the field.
    _dynamic_name: (_) => token(/[A-Za-z0-9_]*\{[A-Za-z_][A-Za-z0-9_.]*\}[A-Za-z0-9_]*/),

    // A `$token$` that Splunk substitutes before the search runs.
    _token_name: (_) => token(/\$[A-Za-z_][A-Za-z0-9_.:]*\$/),

    // `foreach` templates: `<<FIELD>>`, `r<<MATCHSTR>>`, `<<ITEM>>`.
    _template_name: (_) =>
      token(/([A-Za-z0-9_.]|<<[A-Z_0-9]+>>)*<<[A-Z_0-9]+>>([A-Za-z0-9_.]|<<[A-Z_0-9]+>>)*/),

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

    // An option value built from quoted and bare parts with no space between
    // them, read as one argument: streamstats `reset_after="("x==\"y\"")"`.
    _quoted_compound: (_) =>
      token(
        seq(
          repeat(choice(/"([^"\\]|\\.)*"/, /\\./, /[^\s"\\|\[\]`]/)),
          choice(/"([^"\\]|\\.)*"/, /\\./),
          repeat1(choice(/"([^"\\]|\\.)*"/, /\\./, /[^\s"\\|\[\]`]/)),
        ),
      ),
    _field_token: (_) => token(/[A-Za-z0-9_@{][A-Za-z0-9_.:@{}$\-]*/),

    // The field tstats `PREFIX(dst=)` creates: `dst=`, `*=`.
    _prefix_field: (_) => token(/[A-Za-z0-9_.*]+=/),

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

/** Case-insensitive keyword, exposed as the lower-case anonymous node. */
function kw(word) {
  const pattern = word
    .split("")
    .map((c) => (/[a-z]/i.test(c) ? `[${c.toLowerCase()}${c.toUpperCase()}]` : c))
    .join("");
  return alias(token(new RegExp(pattern)), word);
}

/** `TERM(...)`, `CASE(...)`, `PREFIX(...)`: raw contents, `)` optional. */
function directive(name, $) {
  return prec.right(
    seq(name, "(", optional(field("value", $.term_text)), optional(")")),
  );
}

/** Options, then `over` and `by`, after the stats-family aggregates. */
function statsTail($) {
  return seq(
    repeat($.command_option),
    optional(seq(kw("over"), field("over", $._by_field), repeat($.command_option))),
    optional($.by_clause),
  );
}

function sepBy1(rule) {
  return seq(rule, repeat(seq(optional(","), rule)));
}

/**
 * A field or aggregate list: entries separated by spaces or commas. Splunk
 * reads a comma as a separator, so it also takes a doubled or trailing one
 * (`a, , b`, `values(x) as x,` before the next pipe).
 */
function listOf(rule) {
  return seq(rule, repeat(seq(repeat(","), rule)), repeat(","));
}

function commaSep1(rule) {
  return seq(rule, repeat(seq(",", rule)));
}
