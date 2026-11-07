/// <reference types="tree-sitter-cli/dsl" />
// @ts-check

/**
 * Tree-sitter grammar for the Lucene classic query syntax, as Elasticsearch
 * `query_string` reads it (Elastic Security rules with `language: lucene`).
 *
 * Token shapes follow Lucene's classic parser (Apache-2.0): `AND`, `OR`, and
 * `NOT` are upper case and reserved (`foo:AND` is an error); `&&`, `||`, and
 * `!` are synonyms; `TO` is a keyword only inside a range. A boost is `^`
 * plus a number with no space. Clauses have no precedence: the engine flags
 * mixed `AND`/`OR`. Elasticsearch extensions (`_exists_:f`, `f:>=10`) are
 * ordinary terms.
 */
// Lucene whitespace: NBSP is a term character, U+3000 is whitespace.
const WS = /[ \t\r\n\u3000]/;
const TERM_START = /[^ \t\r\n\u3000+\-!():^\[\]"{}~*?\\\/]/;
const ESCAPED = /\\[\s\S]/;
const TERM_CHAR = choice(TERM_START, ESCAPED, "-", "+");

module.exports = grammar({
  name: "opentide_lucene",

  extras: (_) => [WS],

  word: ($) => $.term,

  reserved: {
    global: (_) => ["AND", "OR", "NOT"],
  },

  rules: {
    source_file: ($) => optional($._query),

    _query: ($) => choice($.boolean_query, $._clause_item),

    boolean_query: ($) =>
      prec.left(
        seq(
          $._clause_item,
          repeat1(seq(optional(field("operator", $._conjunction)), $._clause_item)),
        ),
      ),

    _conjunction: ($) => choice($.and, $.or),

    and: (_) => choice("AND", "&&"),
    or: (_) => choice("OR", "||"),
    not: (_) => choice("NOT", "!"),

    _clause_item: ($) => choice($.modified_clause, $._clause),

    modified_clause: ($) =>
      seq(field("modifier", choice($.required, $.prohibited, $.not)), $._clause),

    required: (_) => "+",
    prohibited: (_) => "-",

    _clause: ($) => choice($.field_query, $._clause_body),

    field_query: ($) =>
      seq(field("field", $.field_name), ":", field("query", $._clause_body)),

    // Lucene accepts only a term or `*` before `:`. Wildcard terms parse so
    // the engine can say `book.\*:` instead of a bare syntax error.
    field_name: ($) => choice($.term, $.star, $.wildcard_term),

    _clause_body: ($) => choice($.group, $._term_query),

    group: ($) => seq("(", optional($._query), ")", optional($.boost)),

    _term_query: ($) =>
      choice($.term_query, $.phrase_query, $.range_query, $.regexp_query),

    term_query: ($) =>
      seq(
        field("term", choice($.term, $.wildcard_term, $.star, $.bare_operator)),
        optional($._term_suffix),
      ),

    _term_suffix: ($) =>
      choice(seq($.boost, optional($.fuzzy)), seq($.fuzzy, optional($.boost))),

    phrase_query: ($) =>
      seq(field("phrase", $.phrase), optional($._term_suffix)),

    regexp_query: ($) => seq(field("pattern", $.regexp), optional($.boost)),

    range_query: ($) =>
      seq(
        field("open", choice("[", "{")),
        field("lower", $._range_value),
        "TO",
        field("upper", $._range_value),
        field("close", choice("]", "}")),
        optional($.boost),
      ),

    _range_value: ($) => choice($.range_term, $.phrase),

    // RANGE_GOOP stops only at a space, `]`, or `}`: a tab or newline glues
    // `TO` to the next bound, which Lucene rejects.
    range_term: (_) => /[^ \]}"][^ \]}]*/,

    boost: (_) => token(seq("^", /[0-9]+(\.[0-9]+)?/)),

    // Lucene's FUZZY_SLOP: `~` and any run of term characters. Elasticsearch
    // reads it as a fuzziness (`0`, `1`, `2`, `AUTO`); the engine checks it.
    fuzzy: (_) => token(seq("~", repeat(TERM_CHAR))),

    bare_operator: (_) => token(seq(choice("+", "-", "!"), WS)),

    star: (_) => "*",

    term: (_) => token(seq(choice(TERM_START, ESCAPED), repeat(TERM_CHAR))),

    wildcard_term: (_) =>
      token(
        choice(
          seq(
            choice(TERM_START, ESCAPED),
            repeat(TERM_CHAR),
            choice("*", "?"),
            repeat(choice(TERM_CHAR, "*", "?")),
          ),
          seq("?", repeat(choice(TERM_CHAR, "*", "?"))),
          seq("*", repeat1(choice(TERM_CHAR, "*", "?"))),
        ),
      ),

    phrase: (_) => token(seq('"', repeat(choice(/[^"\\]/, ESCAPED)), '"')),

    // Lucene's REGEXPTERM: any character but `/`, or the pair `\/`. Other
    // backslashes are ordinary characters, so `/(^|\\/)x/` is one regex.
    regexp: (_) => token(seq("/", repeat(choice(/[^\/]/, "\\/")), "/")),
  },
});
