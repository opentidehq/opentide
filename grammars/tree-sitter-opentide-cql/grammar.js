/// <reference types="tree-sitter-cli/dsl" />
// @ts-check

/**
 * Tree-sitter grammar for the CrowdStrike Query Language (CQL), the query
 * language of Falcon LogScale (formerly Humio) and Falcon Next-Gen SIEM.
 *
 * Sources: CrowdStrike's "CQL Grammar Subset" EBNF and its appendices A
 * (quirks), C (character table) and D (reserved words) at
 * library.humio.com/lql-grammar/, the CQL reference pages (operators,
 * filters, fields, expressions, conditionals, comments, arrays, user
 * parameters, saved queries, regex flags, correlate()) at
 * library.humio.com/crowdstrike-query-language/, and the LogScale release
 * notes. Where the reference pages and the grammar subset disagree, the
 * grammar subset wins. Shapes the subset leaves out (negated function calls,
 * `like` with a regex, quoted numbers after `<`, a trailing `|`) follow the
 * reference pages and CrowdStrike/logscale-community-content.
 *
 * Two modes share one tokenizer, kept apart by the parse state:
 *
 *   - Filter (pattern) mode: pipeline steps, `case` and `match` bodies,
 *     subqueries, saved-query arguments and query-parameter defaults. A word
 *     on the left of `= != like < <= > >= := =~ match <=>` is a field name,
 *     even quoted (`"foo"=bar`); a word anywhere else is a pattern. An
 *     unquoted pattern may hold `* + - : /` (`https://x/*`, `foo=m/fisk/i`);
 *     a `/` where a filter starts opens a regex (`/fisk/i`) or a comment.
 *   - Expression mode: function arguments and `:=` right-hand sides. A word
 *     is a field reference, `/` divides (`a := m/fisk/i`), there is no regex
 *     literal (`a := /fisk/i` is an error) and no logical and/or.
 *
 * Precedence, from the grammar subset (`LogicalAndFilter ::= LogicalOrFilter
 * ('AND'? LogicalOrFilter)*`, `LogicalOrFilter ::= UnaryFilter ('OR'
 * UnaryFilter)*`, `UnaryFilter ::= 'NOT'* PrimaryFilter`): `not`/`!` binds
 * tightest, then `or`, then `and` and juxtaposition, then `|`. So
 * `foo and not bar or baz` is `foo and ((not bar) or baz)`; this is the
 * reverse of most languages. Expressions: unary `-`/`!` > `* / %` > `+ -` >
 * comparisons (`== != < <= > >= <=>`, left-associative) > `name: value`
 * attributes after an expression.
 *
 * `and`/`or`/`not` are case-insensitive; `case`, `match`, `like`, `true` and
 * `false` are lower case. Function names are not reserved: a word is a
 * function name only when `(` follows it with no space, and the name lookup
 * is case-insensitive (the engine's catalog decides whether it exists).
 * A function call is a pipeline step, never a filter operand: `foo in(...)`
 * and `a and f()` are errors, `!f()` and `not f()` are steps.
 *
 * src/scanner.c lexes the tokens a regular expression cannot, because they
 * depend on what follows them (see its header): function names (a word
 * directly followed by `(`), unquoted patterns (which end before `:=`), the
 * slash that closes a regex (which a `//` comment would otherwise swallow),
 * and a pattern that ends in `//` (an error). Everything else is lexed here.
 *
 * Decisions on points the sources leave open: block comments do not nest;
 * strings may span lines (CrowdStrike's own dashboards do); a `/` inside a
 * regex character class is text; the whole query may end with `|`; an empty
 * `case {}` parses; `$name` must be directly followed by `(` like a function;
 * `!`/`not` negate a function call but not a saved query; there is no
 * trailing comma, no empty pipeline step and no empty `match` guard.
 */

const PREC = {
  and: 2,
  or: 3,
  not: 4,
  attribute: 1,
  comparison: 2,
  additive: 3,
  multiplicative: 4,
  unary: 5,
};

// Appendix C "FieldChar": the characters of an unquoted field name, which
// are also pattern characters. Latin-1 punctuation is excluded; other
// Unicode is accepted (the grammar subset: "LogScale accepts the full
// Unicode character set").
const FIELD_CHAR = String.raw`#%&.0-9@A-Z\\^_a-z~\u00A1-\u00AA\u00AC\u00AE-\u00BA\u00BC-\uFFFF`;
const FIELD_CHAR_NO_HASH = String.raw`%&.0-9@A-Z\\^_a-z~\u00A1-\u00AA\u00AC\u00AE-\u00BA\u00BC-\uFFFF`;
// JSON array-index segments: `a[0]`, `users[0].name`, whole-array `hosts[]`.
const INDEX = String.raw`(\[[0-9]*\][${FIELD_CHAR}]*)*`;

/** Every upper/lower-case spelling of a keyword, as strings so `word` extraction applies. */
function caseVariants(word) {
  let out = [""];
  for (const c of word) {
    const next = [];
    for (const prefix of out) {
      next.push(prefix + c.toLowerCase());
      next.push(prefix + c.toUpperCase());
    }
    out = next;
  }
  return out;
}

/** `|`? step (`|` step)*, spliced into both pipeline rules. */
// Steps are separated by `|`, which may be left out: `A B` is shorthand for
// `A | B`. Since 1.224 a word directly followed by `(` is a call, so `ERROR`
// then `groupBy(host)` on the next line is a filter and a call (grammar
// subset, Appendix A), and CrowdStrike's own function examples write
// `x := 1.0` then `y := 1.0`, `groupBy(...)` then `_count < 5`, and a filter
// then `payload := ...`, with no pipe. Without a pipe an assignment is
// followed only by another assignment or a call: a filter there would make
// `x := a - 1` read as `x := a` and the free text `- 1`. Two filters side by
// side stay one implicit AND: joining them binds tighter (`PREC.and`) than
// ending a step.
function pipelineSteps($) {
  const step = (rule) => field("step", rule);
  // Steps with no pipe between them: ((filter | call) | assignment+ call)*
  // assignment*.
  const run = seq(
    repeat1(choice(step($._filter), step($._call_step), seq(repeat1(step($.assignment)), step($._call_step)))),
    repeat(step($.assignment)),
  );
  const runOrAssignments = choice(run, repeat1(step($.assignment)));
  return [optional("|"), runOrAssignments, repeat(seq("|", runOrAssignments))];
}

function commaSep1(rule) {
  return seq(rule, repeat(seq(",", rule)));
}

module.exports = grammar({
  name: "opentide_cql",

  extras: ($) => [/[ \t\n\r\f]/, $.line_comment, $.block_comment],

  externals: ($) => [
    $.function_name,
    $.unquoted_pattern,
    $._value_pattern,
    $._regex_end,
    $._pattern_error,
    $._assign_field,
  ],

  word: ($) => $._word,

  // `and`, `or` and `not` are keywords in every position, in any case: `a
  // and and b` is an error, not a search for the text "and". `case`,
  // `match`, `like`, `true` and `false` stay contextual (`x=true` is a
  // pattern).
  reserved: {
    global: (_) => [
      ...caseVariants("and"),
      ...caseVariants("or"),
      ...caseVariants("not"),
    ],
  },

  rules: {
    // The whole query may also end with `|`, as LogScale exports some
    // dashboards and parsers; a nested pipeline may not.
    source_file: ($) => optional(alias($._query_pipeline, $.pipeline)),

    _query_pipeline: ($) => seq(...pipelineSteps($), optional("|")),

    // A pipeline may start with `|`: the main query always could, a
    // subquery since 1.230 (RN-230).
    pipeline: ($) => seq(...pipelineSteps($)),

    // Every step but a filter and an assignment.
    _call_step: ($) =>
      choice(
        $.function_call,
        $.negated_function_call,
        $.field_shorthand,
        $.stats_shorthand,
        $.case_statement,
        $.match_statement,
        $.saved_query,
        $.link_constraint,
      ),

    // ---- Filters (pattern mode) --------------------------------------------

    _filter: ($) =>
      choice($.and_filter, $.or_filter, $.not_filter, $._primary_filter),

    // Juxtaposition is AND: `src="client" ip="127.0.0.1"`.
    and_filter: ($) =>
      prec.left(
        PREC.and,
        seq(
          field("left", $._filter),
          optional(field("operator", $.and)),
          field("right", $._filter),
        ),
      ),

    or_filter: ($) =>
      prec.left(
        PREC.or,
        seq(field("left", $._filter), field("operator", $.or), field("right", $._filter)),
      ),

    not_filter: ($) =>
      prec(
        PREC.not,
        seq(
          field("operator", choice($.not, "!")),
          field("operand", choice($.not_filter, $._primary_filter)),
        ),
      ),

    _primary_filter: ($) =>
      choice($.field_filter, $.free_text, $.boolean, $.parenthesized_filter),

    parenthesized_filter: ($) => seq("(", field("filter", $._filter), ")"),

    field_filter: ($) =>
      choice(
        seq(
          field("field", $._field),
          field("operator", choice("=", "!=")),
          field("value", choice($._value, $.regex, $.query_parameter)),
        ),
        // The grammar subset has no regex after `like`; the operators page
        // shows `class like /Bucket/`.
        seq(
          field("field", $._field),
          field("operator", "like"),
          field("value", choice($._value, $.regex, $.query_parameter)),
        ),
        // The grammar subset allows a number only; real queries also
        // compare with a quoted number (`Severity >= "80"`) or a parameter.
        seq(
          field("field", $._field),
          field("operator", choice("<", "<=", ">", ">=")),
          field("value", choice($.number, $.string, $.query_parameter)),
        ),
      ),

    // A free-text filter: a non-anchored pattern, a regex over every field,
    // or a parameter.
    free_text: ($) =>
      field("value", choice($._anchored_pattern, $.regex, $.query_parameter)),

    // An unquoted word in a pattern position is a pattern, never a field
    // (`myField = myOtherField` compares with the text "myOtherField").
    _anchored_pattern: ($) =>
      choice(
        $.unquoted_pattern,
        alias($._word, $.unquoted_pattern),
        alias($.tag, $.unquoted_pattern),
        $.string,
      ),

    // The same after `=`, `!=` and `like`, in saved-query arguments and in
    // parameter defaults, where a word followed by `(` is not a call (`#category=Request(uri=/x/ or
    // uri=/y/)` is `Request` and a group, as LogScale's own dashboards
    // write it).
    _value: ($) =>
      choice(
        alias($._value_pattern, $.unquoted_pattern),
        alias($._word, $.unquoted_pattern),
        alias($.tag, $.unquoted_pattern),
        $.string,
      ),

    // A field name: unquoted, a `#tag`, or quoted (`"host-name"=*`).
    _field: ($) => choice($.field_name, $.tag, $.string),

    field_name: ($) => $._word,

    // ---- Steps other than filters ------------------------------------------

    // `!in(...)`, `not test(...)` (OPS "Negating the Result of Filter Functions").
    negated_function_call: ($) =>
      seq(field("operator", choice($.not, "!")), field("function", $.function_call)),

    // `field := expression`; `field := f(...)` is the eval-function shorthand.
    // No `name: value` attributes here (they belong to correlate()'s
    // arguments): `x := 1.0` then `y := 2` on the next line is two steps.
    assignment: ($) =>
      seq(
        field("field", choice(alias($._assign_field, $.field_name), $._field)),
        ":=",
        field("value", $._comparative_expression),
      ),

    // `field =~ f(...)` passes `field=` to f.
    field_shorthand: ($) =>
      seq(
        field("field", $._field),
        "=~",
        field("function", choice($.function_call, $.negated_function_call)),
      ),

    // `[min(x), max(x)]` is `stats([min(x), max(x)])`.
    stats_shorthand: ($) =>
      seq("[", optional(commaSep1(field("element", $._array_element))), "]"),

    // `user.email <=> LoginFail1.user.id` inside correlate() query nodes.
    link_constraint: ($) =>
      seq(field("left", $._field), "<=>", field("right", $._field)),

    // `case { a | x := 1; b; * }`. An empty body parses: LogScale exports
    // parsers with `case {\n}` (which drops every event).
    case_statement: ($) =>
      seq(
        "case",
        "{",
        optional(
          seq(
            field("branch", $.case_branch),
            repeat(seq(";", field("branch", $.case_branch))),
            optional(";"),
          ),
        ),
        "}",
      ),

    case_branch: ($) => field("pipeline", $.pipeline),

    match_statement: ($) =>
      seq(
        field("field", $._field),
        "match",
        "{",
        field("branch", $.match_branch),
        repeat(seq(";", field("branch", $.match_branch))),
        optional(";"),
        "}",
      ),

    // A guard is `*` (everything), `**` (the field exists), an anchored
    // pattern, a regex, a filter function, or a parameter. An empty guard is
    // an error.
    match_branch: ($) =>
      seq(
        field(
          "guard",
          choice(
            $._anchored_pattern,
            $.regex,
            $.function_call,
            $.negated_function_call,
            $.query_parameter,
            $.boolean,
          ),
        ),
        "=>",
        field("body", $.pipeline),
      ),

    // `$name(args)`, `$"quoted name"()`, `$falcon/helper:enrich(field=x)`,
    // `$query://view:name()`. Arguments are patterns, not expressions.
    saved_query: ($) =>
      seq(
        "$",
        field(
          "name",
          choice(
            $.saved_query_name,
            alias(token.immediate(/"([^"\\\n]|\\.)*"/), $.string),
          ),
        ),
        token.immediate("("),
        optional(commaSep1(field("argument", $.saved_query_argument))),
        ")",
      ),

    saved_query_name: (_) =>
      token.immediate(new RegExp(String.raw`[${FIELD_CHAR}*+\-:/]+`)),

    saved_query_argument: ($) =>
      seq(
        field("name", choice(alias($._word, $.argument_name), $.string)),
        "=",
        field("value", choice($._value, $.query_parameter, $.array)),
      ),

    // `?name`, `?"quoted name"`, `?{name=default}`.
    query_parameter: ($) =>
      choice(
        seq(
          "?",
          field(
            "name",
            choice(
              alias(token.immediate(new RegExp(String.raw`[${FIELD_CHAR}\-]+`)), $.parameter_name),
              alias(token.immediate(/"([^"\\\n]|\\.)*"/), $.string),
            ),
          ),
        ),
        seq(
          "?{",
          field(
            "name",
            choice(alias($._word, $.parameter_name), alias($._value_pattern, $.parameter_name), $.string),
          ),
          "=",
          field("default", $._value),
          "}",
        ),
      ),

    // ---- Function calls ----------------------------------------------------

    function_call: ($) =>
      seq(
        field("name", $.function_name),
        token.immediate("("),
        optional(field("arguments", $.argument_list)),
        ")",
      ),

    argument_list: ($) =>
      commaSep1(choice($.argument, $.named_argument)),

    // GS allows at most one unnamed argument (a semantic check); correlate() takes
    // several named subqueries.
    argument: ($) => field("value", $._expression),

    named_argument: ($) =>
      seq(
        field("name", choice(alias($._word, $.argument_name), $.string)),
        "=",
        field("value", $._expression),
      ),

    // ---- Expressions -------------------------------------------------------

    _expression: ($) => choice($._comparative_expression, $.attributed_expression),

    // `{ ... } include: [a, b] after: "Login"` (v1.192+, correlate()).
    attributed_expression: ($) =>
      prec.right(
        PREC.attribute,
        seq(
          field("expression", $._comparative_expression),
          repeat1(field("attribute", $.expression_attribute)),
        ),
      ),

    expression_attribute: ($) =>
      seq(
        field("name", alias($._word, $.identifier)),
        ":",
        field("value", $._comparative_expression),
      ),

    _comparative_expression: ($) => choice($.binary_expression, $._unary_operand),

    binary_expression: ($) =>
      choice(
        ...[
          [PREC.comparison, choice("==", "!=", "<", "<=", ">", ">=", "<=>")],
          [PREC.additive, choice("+", "-")],
          [PREC.multiplicative, choice("*", "/", "%")],
        ].map(([p, op]) =>
          prec.left(
            /** @type {number} */ (p),
            seq(
              field("left", $._comparative_expression),
              field("operator", /** @type {RuleOrLiteral} */ (op)),
              field("right", $._comparative_expression),
            ),
          ),
        ),
      ),

    _unary_operand: ($) => choice($.unary_expression, $._primary_expression),

    unary_expression: ($) =>
      prec(PREC.unary, seq(field("operator", choice("-", "!")), field("operand", $._primary_expression))),

    _primary_expression: ($) =>
      choice(
        $.parenthesized_expression,
        $.subquery,
        $.named_subquery,
        $.function_call,
        $.array,
        $.query_parameter,
        $.number,
        $.boolean,
        $.string,
        alias($._word, $.field_name),
        $.tag,
        // A bareword that starts with a character a field name cannot:
        // `pattern=*h*rse*`, `include=*`.
        alias($._expression_pattern, $.unquoted_pattern),
      ),

    parenthesized_expression: ($) => seq("(", field("expression", $._expression), ")"),

    subquery: ($) => seq("{", optional(field("pipeline", $.pipeline)), "}"),

    // `LoginFail1: { ... }` (correlate()); names are unquoted identifiers.
    named_subquery: ($) =>
      seq(field("name", alias($._word, $.identifier)), ":", field("query", $.subquery)),

    array: ($) =>
      seq("[", optional(commaSep1(field("element", $._array_element))), "]"),

    // `[min_response := min(responsetime), ...]`.
    _array_element: ($) => choice($.assignment, $._expression),

    // ---- Tokens ------------------------------------------------------------

    and: (_) => choice(...caseVariants("and")),
    or: (_) => choice(...caseVariants("or")),
    not: (_) => choice(...caseVariants("not")),

    boolean: (_) => choice("true", "false"),

    // `/regex/flags`: the body goes to the regex engine as written; `\/`
    // escapes a slash, and a `/` inside a character class is text
    // (`/[-/][ix]/`, as CrowdStrike's FLTR queries write it). One line.
    // Flags are lexed as any letters so the engine can name an unknown one
    // (d g i m F are defined). The closing slash comes from the scanner so
    // that `/a//b/` is two regexes, not a regex and a `//` comment.
    regex: ($) =>
      seq(
        "/",
        field("pattern", $.regex_pattern),
        alias($._regex_end, "/"),
        optional(field("flags", $.regex_flags)),
      ),

    regex_pattern: (_) =>
      token.immediate(
        /([^/\\\[\r\n]|\\[^\r\n]|\[\^?\]?([^\]\\\r\n]|\\[^\r\n])*\])+/,
      ),

    regex_flags: (_) => token.immediate(/[A-Za-z]+/),

    // Double-quoted; `\"` and `\\` escape, other `\x` pairs stay as written
    // (the regex engine sees `\d`). The grammar subset says a string cannot
    // span lines, but CrowdStrike's Next-Gen SIEM dashboards ship multi-line
    // strings (`createEvents(["{\n ... }"])`), so a raw newline is text.
    string: (_) => token(/"([^"\\]|\\(.|\r?\n))*"/),

    // Defined before `_word` so `42` is a number where both are valid; a
    // longer bareword (`5min`, `10.0.0.0`) still wins.
    number: (_) => token(/-?[0-9]+(\.[0-9]+)?([eE][+-]?[0-9]+)?/),

    tag: (_) => token(new RegExp(String.raw`#[${FIELD_CHAR}]*${INDEX}`)),

    // A bare word that cannot start a field name is a pattern (the grammar
    // subset's "Bare Words"): `*h*rse*`, and a sign followed by more
    // (`-1h`, `+1`), which beats the number `-1` by being longer. A lone `-`
    // stays the unary operator, so `-(a + b)` still parses.
    _expression_pattern: (_) =>
      token(new RegExp(String.raw`(\*[${FIELD_CHAR}*+\-:/]*|[+\-][${FIELD_CHAR}*+\-:/]+)`)),

    _word: (_) => token(new RegExp(String.raw`[${FIELD_CHAR_NO_HASH}][${FIELD_CHAR}]*${INDEX}`)),

    line_comment: (_) => token(seq("//", /[^\r\n]*/)),

    block_comment: (_) => token(seq("/*", /[^*]*\*+([^/*][^*]*\*+)*/, "/")),
  },
});
