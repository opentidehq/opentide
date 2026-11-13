/// <reference types="tree-sitter-cli/dsl" />
// @ts-check

/**
 * Tree-sitter grammar for YARA signatures (yara-1.0: HarfangLab, Bitdefender).
 *
 * Written from libyara 4.5's `libyara/grammar.y`, `lexer.l` and
 * `hex_grammar.y` (BSD-3-Clause), with YARA-X's `yara-x-parser` grammar
 * comments as a cross-check. The dialect is libyara's: what only YARA-X
 * accepts (`with`, hex and octal jump bounds) is left out.
 *
 * Operator precedence is grammar.y's, loosest first:
 *   or < and < not, defined < == != contains icontains startswith
 *   istartswith endswith iendswith iequals matches < < <= > >= < | < ^ <
 *   & < << >> < + - < * \ % < ~ unary-minus.
 * `\` is division, so `/` always starts a regular expression. A hex string
 * only follows `=` in a strings section, so `{` there is a hex string, not a
 * rule body.
 *
 * This grammar drives highlighting and editor structure. Diagnostics come from
 * `yara-x-parser` and the semantic pass (crates/opentide-yara); an agreement
 * test keeps the two parsers aligned (crates/opentide-yara/tests).
 */

const PREC = {
  or: 1,
  and: 2,
  not: 3,
  equality: 4,
  relational: 5,
  bit_or: 6,
  bit_xor: 7,
  bit_and: 8,
  shift: 9,
  additive: 10,
  multiplicative: 11,
  unary: 12,
  of: 13,
  postfix: 14,
};

const STRING_OPERATORS = [
  "==",
  "!=",
  "contains",
  "icontains",
  "startswith",
  "istartswith",
  "endswith",
  "iendswith",
  "iequals",
];

module.exports = grammar({
  name: "opentide_yara",

  extras: ($) => [/\s/, $.comment],

  word: ($) => $.identifier,

  conflicts: ($) => [
    // `50% of them` against `50 % 7`: the percent quantifier is a primary
    // followed by `%` and `of`, which only the token after `%` decides.
    [$.percent_quantifier, $.arithmetic_expression],
  ],

  rules: {
    source_file: ($) => repeat(choice($.import, $.include, $.rule)),

    comment: (_) =>
      token(choice(seq("//", /[^\n]*/), seq("/*", /[^*]*\*+([^/*][^*]*\*+)*/, "/"))),

    import: ($) => seq("import", field("module", $.text_string)),

    // libyara resolves includes in the lexer; a platform has no file system,
    // so the engine reports `yara_include`.
    include: ($) => seq("include", field("path", $.text_string)),

    rule: ($) =>
      seq(
        repeat(field("modifier", $.rule_modifier)),
        "rule",
        field("name", $.identifier),
        optional($.tags),
        "{",
        optional($.meta_section),
        optional($.strings_section),
        $.condition_section,
        "}",
      ),

    rule_modifier: (_) => choice("private", "global"),

    tags: ($) => seq(":", repeat1(field("tag", $.tag))),

    tag: ($) => $.identifier,

    meta_section: ($) => seq("meta", ":", repeat1($.meta_definition)),

    meta_definition: ($) =>
      seq(
        field("key", $.identifier),
        "=",
        field(
          "value",
          choice($.text_string, $.integer, $.negative_integer, $.boolean),
        ),
      ),

    negative_integer: ($) => seq("-", $.integer),

    strings_section: ($) => seq("strings", ":", repeat1($.string_definition)),

    string_definition: ($) =>
      seq(
        field("identifier", $.string_identifier),
        "=",
        choice(
          seq(field("value", $.text_string), repeat($._string_modifier)),
          seq(field("value", $.regexp), repeat($._string_modifier)),
          seq(field("value", $.hex_string), repeat($._string_modifier)),
        ),
      ),

    // Which modifier a kind of string may take is libyara's check
    // (`yara_string_modifier`), not the grammar's.
    _string_modifier: ($) =>
      choice($.string_modifier, $.xor_modifier, $.base64_modifier),

    string_modifier: (_) =>
      choice("nocase", "wide", "ascii", "fullword", "private"),

    xor_modifier: ($) =>
      seq(
        "xor",
        optional(
          seq(
            "(",
            field("from", $.integer),
            optional(seq("-", field("to", $.integer))),
            ")",
          ),
        ),
      ),

    base64_modifier: ($) =>
      seq(
        choice("base64", "base64wide"),
        optional(seq("(", field("alphabet", $.text_string), ")")),
      ),

    // --- Hex strings (hex_grammar.y) ---

    hex_string: ($) => seq("{", repeat1($._hex_token), "}"),

    _hex_token: ($) =>
      choice($.hex_byte, $.hex_not, $.hex_jump, $.hex_alternative),

    // Two nibbles, each a hex digit or `?`.
    hex_byte: (_) => token(/[0-9A-Fa-f?][0-9A-Fa-f?]/),

    hex_not: ($) => seq("~", $.hex_byte),

    hex_jump: ($) =>
      seq(
        "[",
        choice(
          field("length", $.hex_jump_bound),
          seq(
            optional(field("from", $.hex_jump_bound)),
            "-",
            optional(field("to", $.hex_jump_bound)),
          ),
        ),
        "]",
      ),

    hex_jump_bound: (_) => /[0-9]+/,

    hex_alternative: ($) =>
      seq(
        "(",
        $.hex_alternative_branch,
        repeat1(seq("|", $.hex_alternative_branch)),
        ")",
      ),

    hex_alternative_branch: ($) => repeat1($._hex_token),

    // --- Condition (grammar.y `expression` and `primary_expression`) ---

    condition_section: ($) =>
      seq("condition", ":", field("expression", $._expression)),

    // grammar.y `expression`: what may stand as a boolean.
    _expression: ($) =>
      choice(
        $.boolean,
        $.string_identifier,
        $.string_match,
        $.parenthesized_expression,
        $.not_expression,
        $.and_expression,
        $.or_expression,
        $.comparison,
        $.of_expression,
        $.for_expression,
        $._primary,
      ),

    // grammar.y `primary_expression`: integers, floats, strings, references.
    _primary: ($) =>
      choice(
        $.integer,
        $.float,
        $.text_string,
        $.regexp,
        $.filesize,
        $.entrypoint,
        $.string_count,
        $.string_offset,
        $.string_length,
        $.string_count_in_range,
        $.indexed_string,
        $._reference,
        $.parenthesized_primary,
        $.unary_expression,
        $.arithmetic_expression,
      ),

    boolean: (_) => choice("true", "false"),

    filesize: (_) => "filesize",

    entrypoint: (_) => "entrypoint",

    parenthesized_expression: ($) => seq("(", $._expression, ")"),

    parenthesized_primary: ($) => prec(1, seq("(", $._primary, ")")),

    not_expression: ($) =>
      prec.right(
        PREC.not,
        seq(field("operator", choice("not", "defined")), field("operand", $._expression)),
      ),

    and_expression: ($) =>
      prec.left(
        PREC.and,
        seq(field("left", $._expression), "and", field("right", $._expression)),
      ),

    or_expression: ($) =>
      prec.left(
        PREC.or,
        seq(field("left", $._expression), "or", field("right", $._expression)),
      ),

    comparison: ($) =>
      choice(
        prec.left(
          PREC.equality,
          seq(
            field("left", $._primary),
            field("operator", choice(...STRING_OPERATORS)),
            field("right", $._primary),
          ),
        ),
        prec.left(
          PREC.equality,
          seq(field("left", $._primary), field("operator", "matches"), field("right", $.regexp)),
        ),
        prec.left(
          PREC.relational,
          seq(
            field("left", $._primary),
            field("operator", choice("<", "<=", ">", ">=")),
            field("right", $._primary),
          ),
        ),
      ),

    unary_expression: ($) =>
      prec(
        PREC.unary,
        seq(field("operator", choice("-", "~")), field("operand", $._primary)),
      ),

    arithmetic_expression: ($) => {
      /** @type {[number, string[]][]} */
      const table = [
        [PREC.bit_or, ["|"]],
        [PREC.bit_xor, ["^"]],
        [PREC.bit_and, ["&"]],
        [PREC.shift, ["<<", ">>"]],
        [PREC.additive, ["+", "-"]],
        [PREC.multiplicative, ["*", "\\", "%"]],
      ];
      return choice(
        ...table.map(([p, ops]) =>
          prec.left(
            p,
            seq(
              field("left", $._primary),
              field("operator", ops.length === 1 ? ops[0] : choice(...ops)),
              field("right", $._primary),
            ),
          ),
        ),
      );
    },

    // `#a in (0..100)`.
    string_count_in_range: ($) =>
      prec(PREC.postfix, seq(field("string", $.string_count), "in", field("range", $.range))),

    // `@a[2]`, `!a[i]`.
    indexed_string: ($) =>
      seq(
        field("string", choice($.string_offset, $.string_length)),
        "[",
        field("index", $._primary),
        "]",
      ),

    // grammar.y `identifier`: a name, a module member, an index, a call.
    _reference: ($) =>
      choice($.identifier, $.member_expression, $.index_expression, $.call_expression),

    member_expression: ($) =>
      prec(PREC.postfix, seq(field("object", $._reference), ".", field("member", $.identifier))),

    index_expression: ($) =>
      prec(
        PREC.postfix,
        seq(field("object", $._reference), "[", field("index", $._primary), "]"),
      ),

    // `uint16(0)`, `pe.exports("x")`, `math.entropy(0, filesize)`.
    call_expression: ($) =>
      prec(
        PREC.postfix,
        seq(
          field("function", $._reference),
          "(",
          optional(seq($._expression, repeat(seq(",", $._expression)))),
          ")",
        ),
      ),

    // `$a`, `$a at 100`, `$a in (0..100)`.
    string_match: ($) =>
      prec.left(
        PREC.equality,
        seq(
          field("string", $.string_identifier),
          choice(
            seq("at", field("offset", $._primary)),
            seq("in", field("range", $.range)),
          ),
        ),
      ),

    range: ($) =>
      seq("(", field("from", $._primary), "..", field("to", $._primary), ")"),

    // `any of them`, `2 of ($a*)`, `50% of them`, `all of (rule_a, rule_b*)`,
    // `any of them in (0..100)`, `any of ($a, $b) at 0`.
    of_expression: ($) =>
      prec.right(
        PREC.of,
        seq(
          field("quantifier", $._quantifier),
          "of",
          choice(
            seq(
              field("set", choice($.them, $.string_set)),
              optional(
                choice(
                  seq("in", field("range", $.range)),
                  seq("at", field("offset", $._primary)),
                ),
              ),
            ),
            field("set", $.rule_set),
          ),
        ),
      ),

    // grammar.y `for_expression`, plus `primary_expression '%'`.
    _quantifier: ($) =>
      choice($.quantifier_keyword, $.percent_quantifier, $._primary),

    quantifier_keyword: (_) => choice("all", "any", "none"),

    percent_quantifier: ($) => prec(PREC.multiplicative, seq($._primary, "%")),

    them: (_) => "them",

    string_set: ($) =>
      seq(
        "(",
        choice($.string_identifier, $.string_wildcard),
        repeat(seq(",", choice($.string_identifier, $.string_wildcard))),
        ")",
      ),

    rule_set: ($) =>
      seq(
        "(",
        choice($.identifier, $.rule_wildcard),
        repeat(seq(",", choice($.identifier, $.rule_wildcard))),
        ")",
      ),

    // `for any of ($a*) : ( @ > 10 )`, `for all i in (1..#a) : ( @a[i] > 0 )`,
    // `for any section in pe.sections : ( section.name == ".text" )`.
    for_expression: ($) =>
      seq(
        "for",
        field("quantifier", $._quantifier),
        choice(
          seq("of", field("set", choice($.them, $.string_set))),
          seq(
            field("variables", $.loop_variables),
            "in",
            field("iterable", choice($.range, $.integer_enumeration, $._reference)),
          ),
        ),
        ":",
        "(",
        field("body", $._expression),
        ")",
      ),

    loop_variables: ($) => seq($.identifier, repeat(seq(",", $.identifier))),

    integer_enumeration: ($) =>
      seq("(", $._primary, repeat(seq(",", $._primary)), ")"),

    // --- Tokens ---

    identifier: (_) => /[A-Za-z_][A-Za-z0-9_]*/,

    rule_wildcard: (_) => token(/[A-Za-z_][A-Za-z0-9_]*\*/),

    // `$` alone is the anonymous string (and the current one inside `for`).
    string_identifier: (_) => token(/\$[A-Za-z0-9_]*/),

    string_wildcard: (_) => token(/\$[A-Za-z0-9_]*\*/),

    string_count: (_) => token(/#[A-Za-z0-9_]*/),

    string_offset: (_) => token(/@[A-Za-z0-9_]*/),

    string_length: (_) => token(/![A-Za-z0-9_]*/),

    integer: (_) =>
      token(choice(/0x[0-9A-Fa-f]+/, /0o[0-7]+/, /[0-9]+(KB|MB)?/)),

    float: (_) => token(/[0-9]+\.[0-9]+/),

    text_string: (_) => token(seq('"', repeat(choice(/[^"\\\n]+/, /\\./)), '"')),

    regexp: (_) =>
      token(seq("/", repeat1(choice(/[^/\\\n]/, /\\./)), "/", /[is]*/)),
  },
});
