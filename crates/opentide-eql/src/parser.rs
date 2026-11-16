//! EQL's grammar, as functions over [`opentide_parse::Parser`]. It follows
//! `grammars/tree-sitter-opentide-eql/grammar.js`, which `eql.ungram` restates as a tree:
//! a query (`sequence`, `sample`, `join` or `category where condition`), then pipes.
//!
//! Expressions are one Pratt loop. From the loosest: `or`, `and`, `not` and lineage
//! (`descendant of [...]`), a comparison (not associative), `+ -`, `* / %`, a unary sign, and
//! a predicate (`in`, `:`, `like`, `regex`) after a primary. A run of one operator level is
//! one flat node, so a 20,000-term `or` chain is two levels deep, not 20,000.
//!
//! Every keyword is reserved, in lower case only: a word whose text is one is re-kinded before
//! parsing, wherever it stands. `in~`, `like~` and `regex~` are operators only after an
//! operand; elsewhere they are names.

use crate::lexer::lex;
use crate::syntax::{SyntaxKind as K, SyntaxNode};
use opentide_parse::{
    CompletedMarker, Grammar, Input, Lexeme, Parse, Parser, TokenSet, build, debug_errors,
    debug_tree,
};

/// Nesting deeper than this is one error. A level is a parenthesis, a call, a sign, a `not`, a
/// list, a subquery, or an operand under an operator of a looser level (so `(a or b == c` is
/// two levels in the parenthesis). The tree-sitter engine took 10,000 levels; the floor every language keeps is
/// `deep_queries`' `NESTING_CEILING` (1,000). Elasticsearch itself stops at 250 (the
/// `eql_expression_depth` check).
pub(crate) const MAX_DEPTH: u32 = 1_024;

/// The toolkit's view of EQL's kinds.
pub(crate) const GRAMMAR: Grammar = Grammar {
    eof: K::EOF.raw(),
    error: K::ERROR.raw(),
    trivia: K::set(&[K::WHITESPACE, K::LINE_COMMENT, K::BLOCK_COMMENT]),
    max_depth: MAX_DEPTH,
};

/// The reserved words and their kinds.
const KEYWORDS: &[(&str, K)] = &[
    ("and", K::AND_KW),
    ("any", K::ANY_KW),
    ("by", K::BY_KW),
    ("false", K::FALSE_KW),
    ("in", K::IN_KW),
    ("join", K::JOIN_KW),
    ("like", K::LIKE_KW),
    ("maxspan", K::MAXSPAN_KW),
    ("not", K::NOT_KW),
    ("null", K::NULL_KW),
    ("of", K::OF_KW),
    ("or", K::OR_KW),
    ("regex", K::REGEX_KW),
    ("sample", K::SAMPLE_KW),
    ("sequence", K::SEQUENCE_KW),
    ("true", K::TRUE_KW),
    ("until", K::UNTIL_KW),
    ("where", K::WHERE_KW),
    ("with", K::WITH_KW),
];

/// The case-insensitive operators, cut as a `TILDE_WORD`.
const TILDE_OPERATORS: &[(&str, K)] = &[
    ("in~", K::IN_TILDE),
    ("like~", K::LIKE_TILDE),
    ("regex~", K::REGEX_TILDE),
];

/// What may start an expression.
const EXPR_START: TokenSet = K::set(&[
    K::NOT_KW,
    K::L_PAREN,
    K::MINUS,
    K::PLUS,
    K::NULL_KW,
    K::TRUE_KW,
    K::FALSE_KW,
    K::NUMBER_TOKEN,
    K::STRING_TOKEN,
    K::WORD,
    K::TILDE_WORD,
    K::QUOTED_IDENT_TOKEN,
    K::QUESTION,
]);

/// Where a failed expression stops: a rule above it takes these.
const RECOVERY: TokenSet = K::set(&[
    K::R_PAREN,
    K::R_BRACK,
    K::COMMA,
    K::PIPE,
    K::BY_KW,
    K::WITH_KW,
    K::UNTIL_KW,
    K::WHERE_KW,
    K::AND_KW,
    K::OR_KW,
    K::L_BRACK,
    K::BANG_L_BRACK,
]);

const COMPARISON_OPS: TokenSet = K::set(&[K::EQ_EQ, K::NOT_EQ, K::LT, K::LT_EQ, K::GT, K::GT_EQ]);
const ADDITIVE_OPS: TokenSet = K::set(&[K::PLUS, K::MINUS]);
const MULTIPLICATIVE_OPS: TokenSet = K::set(&[K::STAR, K::SLASH, K::PERCENT]);
const CONSTANTS: TokenSet = K::set(&[
    K::NULL_KW,
    K::TRUE_KW,
    K::FALSE_KW,
    K::NUMBER_TOKEN,
    K::STRING_TOKEN,
]);
const OPENS: TokenSet = K::set(&[K::L_BRACK, K::BANG_L_BRACK]);
const CATEGORY_NAMES: TokenSet = K::set(&[K::WORD, K::STRING_TOKEN]);
const SUBQUERY_STOP: TokenSet = K::set(&[K::R_BRACK, K::PIPE]);

/// The operator levels, from the loosest. `not` and lineage are prefixes at [`NOT`]; their
/// operand is a comparison or tighter.
const OR: u8 = 1;
const AND: u8 = 2;
const NOT: u8 = 3;
const COMPARISON: u8 = 4;
const ADDITIVE: u8 = 5;
const MULTIPLICATIVE: u8 = 6;
const UNARY: u8 = 7;

/// Error messages the analysis words as its own.
pub(crate) const EXPECTED_EXPRESSION: &str = "an expression is missing";
pub(crate) const UNEXPECTED: &str = "unexpected token";

/// Re-kinds the reserved words: Elasticsearch reserves every keyword, so a word with a
/// keyword's text is that keyword wherever it stands.
fn keywords(source: &str, mut lexemes: Vec<Lexeme>) -> Vec<Lexeme> {
    for lexeme in &mut lexemes {
        if lexeme.kind == K::WORD.raw() {
            let text = &source[std::ops::Range::<usize>::from(lexeme.range)];
            if let Some((_, kind)) = KEYWORDS.iter().find(|(word, _)| *word == text) {
                lexeme.kind = kind.raw();
            }
        }
    }
    lexemes
}

/// Parses `source`.
pub(crate) fn parse(source: &str) -> Parse {
    let input = Input::new(source, keywords(source, lex(source)), GRAMMAR);
    let mut p = Parser::new(&input);
    let root = p.start();
    if at(&mut p, K::PIPE) {
        p.error("a query is missing before the first pipe");
    } else if !p.at_eof() {
        query(&mut p);
    }
    while !p.at_eof() {
        if at(&mut p, K::PIPE) {
            pipe_stage(&mut p);
        } else {
            p.err_until(UNEXPECTED, K::set(&[K::PIPE]));
        }
    }
    root.complete(&mut p, K::SOURCE_FILE.raw());
    build(&input, p.finish())
}

/// The tree of `source` and its errors as indented text, for the snapshot tests.
pub(crate) fn debug(source: &str) -> String {
    let parse = parse(source);
    let root = SyntaxNode::new_root(parse.green.clone());
    let mut out = debug_tree(&root, |k| format!("{k:?}"));
    out.push_str(&debug_errors(&parse.errors, |k| {
        K::from_raw(k).describe().to_owned()
    }));
    out
}

// The rules that recurse (an expression, a call, a subquery) run about six frames deep per
// nesting level, and 1,024 levels must fit a 1 MB stack in a debug build. A `TokenSet` is 64
// bytes: one built or copied in a recursive rule's own frame stays there while the rule
// recurses. These helpers keep every set in a frame of their own, gone before the recursion.

/// Whether the current token is in `set` (recorded as expected, as `Parser::at_set`).
#[inline(never)]
fn at_any(p: &mut Parser<'_>, set: &TokenSet) -> bool {
    p.at_set(*set)
}

/// Whether `kind` is in `set`.
#[inline(never)]
fn in_set(set: &TokenSet, kind: K) -> bool {
    set.contains(kind.raw())
}

/// The tokens up to one of `stop`, in one error node.
#[inline(never)]
fn skip_until(p: &mut Parser<'_>, stop: &TokenSet) {
    p.err_until(UNEXPECTED, *stop);
}

fn at(p: &mut Parser<'_>, kind: K) -> bool {
    p.at(kind.raw())
}

fn eat(p: &mut Parser<'_>, kind: K) -> bool {
    p.eat(kind.raw())
}

fn expect(p: &mut Parser<'_>, kind: K) -> bool {
    p.expect(kind.raw(), format!("missing {}", kind.describe()))
}

/// The current token in a node of its own.
fn leaf(p: &mut Parser<'_>, kind: K) -> CompletedMarker {
    let m = p.start();
    p.bump();
    m.complete(p, kind.raw())
}

/// An identifier, or an error.
fn identifier(p: &mut Parser<'_>) -> bool {
    if at(p, K::WORD) {
        leaf(p, K::IDENTIFIER);
        true
    } else {
        p.error("a name is missing");
        false
    }
}

// ---- Queries ------------------------------------------------------------------------------

fn query(p: &mut Parser<'_>) {
    match K::from_raw(p.current()) {
        K::SEQUENCE_KW => sequence(p),
        K::SAMPLE_KW => sample(p),
        K::JOIN_KW => join(p),
        _ => {
            let m = p.start();
            event_filter(p);
            m.complete(p, K::EVENT_QUERY.raw());
        }
    }
}

/// `category where condition`.
fn event_filter(p: &mut Parser<'_>) {
    if at(p, K::ANY_KW) {
        leaf(p, K::ANY);
    } else if at_any(p, &CATEGORY_NAMES) {
        let m = p.start();
        if at(p, K::WORD) {
            leaf(p, K::IDENTIFIER);
        } else {
            leaf(p, K::STRING);
        }
        m.complete(p, K::EVENT_CATEGORY.raw());
    } else {
        p.error("an event category is missing");
    }
    if expect(p, K::WHERE_KW) {
        expr_bp(p, OR);
    }
}

fn sequence(p: &mut Parser<'_>) {
    let m = p.start();
    p.bump();
    if at(p, K::BY_KW) {
        join_keys(p);
        if at(p, K::WITH_KW) {
            sequence_params(p);
        }
    } else if at(p, K::WITH_KW) {
        sequence_params(p);
        if at(p, K::BY_KW) {
            join_keys(p);
        }
    }
    terms(p, K::SEQUENCE_TERM);
    if eat(p, K::UNTIL_KW) {
        term(p, K::SEQUENCE_TERM);
    }
    m.complete(p, K::SEQUENCE.raw());
}

fn sequence_params(p: &mut Parser<'_>) {
    let m = p.start();
    p.bump();
    if expect(p, K::MAXSPAN_KW) && expect(p, K::EQ) {
        let unit = p.start();
        if at(p, K::NUMBER_TOKEN) {
            leaf(p, K::NUMBER);
            if at(p, K::WORD) {
                leaf(p, K::IDENTIFIER);
            }
        } else {
            p.error("a time span is missing");
        }
        unit.complete(p, K::TIME_UNIT.raw());
    }
    m.complete(p, K::SEQUENCE_PARAMS.raw());
}

fn sample(p: &mut Parser<'_>) {
    let m = p.start();
    p.bump();
    if at(p, K::BY_KW) {
        join_keys(p);
    }
    terms(p, K::JOIN_TERM);
    m.complete(p, K::SAMPLE.raw());
}

fn join(p: &mut Parser<'_>) {
    let m = p.start();
    p.bump();
    if at(p, K::BY_KW) {
        join_keys(p);
    }
    // A join needs two terms: `join` with one is a syntax error, as in tree-sitter's grammar.
    if terms(p, K::JOIN_TERM) == 1 {
        p.error("a second subquery `[ ... ]` is missing");
    }
    if eat(p, K::UNTIL_KW) {
        term(p, K::JOIN_TERM);
    }
    m.complete(p, K::JOIN.raw());
}

/// One term or more; how many.
fn terms(p: &mut Parser<'_>, kind: K) -> usize {
    term(p, kind);
    let mut n = 1;
    while p.at_set(OPENS) {
        term(p, kind);
        n += 1;
    }
    n
}

/// `[...] by keys` and, in a sequence, `with runs=n`.
fn term(p: &mut Parser<'_>, kind: K) {
    let m = p.start();
    if !p.at_set(OPENS) {
        m.abandon(p);
        p.error("a subquery `[ ... ]` is missing");
        return;
    }
    subquery(p);
    if at(p, K::BY_KW) {
        join_keys(p);
    }
    if kind == K::SEQUENCE_TERM && at(p, K::WITH_KW) {
        let option = p.start();
        p.bump();
        if identifier(p) && expect(p, K::EQ) {
            if at(p, K::NUMBER_TOKEN) {
                leaf(p, K::NUMBER);
            } else {
                fail(p, "a number is missing");
            }
        }
        option.complete(p, K::TERM_OPTION.raw());
    }
    m.complete(p, kind.raw());
}

/// `[ category where condition ]` or `![ ... ]`, at `[` or `![`.
fn subquery(p: &mut Parser<'_>) {
    if !p.enter() {
        return;
    }
    let m = p.start();
    if at(p, K::BANG_L_BRACK) {
        leaf(p, K::MISSING_EVENT_OPEN);
    } else {
        p.bump();
    }
    event_filter(p);
    if !at(p, K::R_BRACK) && !p.at_eof() {
        skip_until(p, &SUBQUERY_STOP);
    }
    expect(p, K::R_BRACK);
    m.complete(p, K::SUBQUERY.raw());
    p.exit();
}

/// `by expr, expr, ...`.
fn join_keys(p: &mut Parser<'_>) {
    let m = p.start();
    p.bump();
    list(p);
    m.complete(p, K::JOIN_KEYS.raw());
}

/// `expr (, expr)*`.
fn list(p: &mut Parser<'_>) {
    expr_bp(p, OR);
    while eat(p, K::COMMA) {
        expr_bp(p, OR);
    }
}

/// `| name arguments`.
fn pipe_stage(p: &mut Parser<'_>) {
    let m = p.start();
    p.bump();
    if identifier(p) && p.at_set(EXPR_START) {
        list(p);
    }
    if !p.at_eof() && !at(p, K::PIPE) {
        p.err_until(UNEXPECTED, K::set(&[K::PIPE]));
    }
    m.complete(p, K::PIPE_STAGE.raw());
}

// ---- Expressions --------------------------------------------------------------------------

pub(crate) fn expr(p: &mut Parser<'_>) {
    expr_bp(p, OR);
}

/// The infix level of the current token.
fn infix(p: &mut Parser<'_>) -> Option<u8> {
    let kind = K::from_raw(p.current());
    Some(match kind {
        K::OR_KW => OR,
        K::AND_KW => AND,
        _ if COMPARISON_OPS.contains(kind.raw()) => COMPARISON,
        _ if ADDITIVE_OPS.contains(kind.raw()) => ADDITIVE,
        _ if MULTIPLICATIVE_OPS.contains(kind.raw()) => MULTIPLICATIVE,
        _ => return None,
    })
}

fn level_kind(level: u8) -> K {
    match level {
        OR => K::OR_EXPRESSION,
        AND => K::AND_EXPRESSION,
        COMPARISON => K::COMPARISON,
        _ => K::BINARY_EXPRESSION,
    }
}

/// An expression whose operators are all at `min` or tighter.
///
/// An operand under an operator is one nesting level (`enter`): a parenthesis holding every
/// level, `(a or b and c == d + e * (...`, recurses through each, and its stack is bounded by
/// the levels it enters, not by its parentheses alone.
fn expr_bp(p: &mut Parser<'_>, min: u8) {
    let Some((mut lhs, mut ceiling)) = prefix(p, min) else {
        return;
    };
    loop {
        // Records what may follow, for an error's expected set.
        expect_infix(p, min, ceiling);
        let Some(level) = infix(p) else {
            break;
        };
        if level < min || level > ceiling {
            break;
        }
        let m = lhs.precede(p);
        let kind = level_kind(level);
        if level == COMPARISON {
            // Not associative: a comparison is no operand of another.
            p.bump();
            if p.enter() {
                expr_bp(p, ADDITIVE);
                p.exit();
            }
        } else {
            while infix(p) == Some(level) {
                p.bump();
                if p.enter() {
                    expr_bp(p, level + 1);
                    p.exit();
                }
            }
        }
        // Only a looser level may follow a run: `a and b == c` is no comparison's operand.
        ceiling = level - 1;
        lhs = m.complete(p, kind.raw());
    }
}

/// Records the infix operators from level `min` to `ceiling` as expected here.
#[inline(never)]
fn expect_infix(p: &mut Parser<'_>, min: u8, ceiling: u8) {
    let levels = [
        (OR, K::set(&[K::OR_KW])),
        (AND, K::set(&[K::AND_KW])),
        (COMPARISON, COMPARISON_OPS),
        (ADDITIVE, ADDITIVE_OPS),
        (MULTIPLICATIVE, MULTIPLICATIVE_OPS),
    ];
    for (level, set) in levels {
        if (min..=ceiling).contains(&level) {
            p.at_set(set);
        }
    }
}

/// A prefix (`not`, lineage, a sign) or an operand with its predicate; and the loosest infix
/// level that may follow it.
fn prefix(p: &mut Parser<'_>, min: u8) -> Option<(CompletedMarker, u8)> {
    if min <= COMPARISON && at(p, K::NOT_KW) {
        let m = p.start();
        p.bump();
        if p.enter() {
            expr_bp(p, COMPARISON);
            p.exit();
        }
        return Some((m.complete(p, K::NOT_EXPRESSION.raw()), AND));
    }
    if min <= COMPARISON && at(p, K::WORD) && p.nth(1) == K::OF_KW.raw() {
        let m = p.start();
        leaf(p, K::IDENTIFIER);
        p.bump();
        if at_any(p, &OPENS) {
            subquery(p);
        } else {
            p.error("a subquery `[ ... ]` is missing");
        }
        return Some((m.complete(p, K::RELATIONSHIP.raw()), AND));
    }
    if at_any(p, &ADDITIVE_OPS) {
        let m = p.start();
        p.bump();
        if p.enter() {
            expr_bp(p, UNARY);
            p.exit();
        }
        return Some((m.complete(p, K::UNARY_EXPRESSION.raw()), MULTIPLICATIVE));
    }
    let operand = primary(p, min)?;
    Some((predicate(p, operand), MULTIPLICATIVE))
}

/// `subject [not] in (...)`, or `subject : constant` (and `like`, `regex`, their `~` forms).
fn predicate(p: &mut Parser<'_>, subject: CompletedMarker) -> CompletedMarker {
    let negated = at(p, K::NOT_KW) && matches!(tilde_operator(p, 1), Some(K::IN_KW | K::IN_TILDE));
    let operator = if negated {
        tilde_operator(p, 1)
    } else {
        tilde_operator(p, 0)
    };
    let Some(operator) = operator else {
        return subject;
    };
    let m = subject.precede(p);
    if negated {
        p.bump();
    }
    p.bump_as(operator.raw());
    if matches!(operator, K::IN_KW | K::IN_TILDE) {
        parenthesized_list(p, true);
    } else if at(p, K::L_PAREN) {
        parenthesized_list(p, false);
    } else {
        constant(p);
    }
    m.complete(p, K::PREDICATE_EXPRESSION.raw())
}

/// The predicate operator `n` tokens ahead, as the kind it takes.
fn tilde_operator(p: &mut Parser<'_>, n: usize) -> Option<K> {
    let kind = K::from_raw(p.nth(n));
    if n == 0 {
        p.at_set(K::set(&[
            K::IN_KW,
            K::IN_TILDE,
            K::COLON,
            K::LIKE_KW,
            K::LIKE_TILDE,
            K::REGEX_KW,
            K::REGEX_TILDE,
        ]));
    }
    match kind {
        K::IN_KW | K::COLON | K::LIKE_KW | K::REGEX_KW => Some(kind),
        K::TILDE_WORD => TILDE_OPERATORS
            .iter()
            .find(|(text, _)| *text == p.nth_text(n))
            .map(|(_, kind)| *kind),
        _ => None,
    }
}

/// `( item, item, ... )`: expressions after `in`, constants after a pattern operator.
fn parenthesized_list(p: &mut Parser<'_>, expressions: bool) {
    if !expect(p, K::L_PAREN) || !p.enter() {
        return;
    }
    let item = |p: &mut Parser<'_>| {
        if expressions {
            expr_bp(p, OR);
        } else {
            constant(p);
        }
    };
    item(p);
    while eat(p, K::COMMA) {
        item(p);
    }
    close(p, K::R_PAREN);
    p.exit();
}

/// `)` or `]`; anything before it is one error node.
fn close(p: &mut Parser<'_>, kind: K) {
    if !at(p, kind) && !p.at_eof() && !p.at_set(K::set(&[K::PIPE, K::R_BRACK])) {
        p.err_until(UNEXPECTED, K::set(&[kind, K::PIPE, K::R_BRACK]));
    }
    expect(p, kind);
}

/// `null`, a number, `true`, `false` or a string.
fn constant(p: &mut Parser<'_>) -> Option<CompletedMarker> {
    let node = match K::from_raw(p.current()) {
        K::NULL_KW => K::NULL,
        K::TRUE_KW | K::FALSE_KW => K::BOOLEAN,
        K::NUMBER_TOKEN => K::NUMBER,
        K::STRING_TOKEN => K::STRING,
        _ => {
            p.at_set(CONSTANTS);
            fail(p, "a constant is missing");
            return None;
        }
    };
    Some(leaf(p, node))
}

/// An error before the current token, which is wrapped in an error node unless a rule above
/// takes it.
fn fail(p: &mut Parser<'_>, message: &str) {
    p.err_recover(message, RECOVERY);
}

/// A constant, a call, a field or a parenthesized expression; `min` is the loosest level the
/// expression it stands in may take (`not` and lineage only down to a comparison).
fn primary(p: &mut Parser<'_>, min: u8) -> Option<CompletedMarker> {
    let kind = K::from_raw(p.current());
    if in_set(&CONSTANTS, kind) {
        return constant(p);
    }
    match kind {
        K::L_PAREN => {
            if !p.enter() {
                return None;
            }
            let m = p.start();
            p.bump();
            expr_bp(p, OR);
            close(p, K::R_PAREN);
            p.exit();
            Some(m.complete(p, K::PARENTHESIZED_EXPRESSION.raw()))
        }
        K::WORD | K::TILDE_WORD if p.nth(1) == K::L_PAREN.raw() => function_call(p),
        K::WORD | K::QUOTED_IDENT_TOKEN | K::QUESTION => Some(field(p)),
        _ => {
            missing_expression(p, min);
            None
        }
    }
}

/// "an expression is missing", expecting what may start one at level `min`.
#[inline(never)]
fn missing_expression(p: &mut Parser<'_>, min: u8) {
    let mut start = EXPR_START;
    if min > COMPARISON {
        start = TokenSet::EMPTY;
        for kind in EXPR_START.iter().filter(|&k| k != K::NOT_KW.raw()) {
            start = start.with(kind);
        }
    }
    p.at_set(start);
    fail(p, EXPECTED_EXPRESSION);
}

fn function_call(p: &mut Parser<'_>) -> Option<CompletedMarker> {
    if !p.enter() {
        return None;
    }
    let m = p.start();
    if at(p, K::TILDE_WORD) {
        leaf(p, K::CASE_INSENSITIVE_NAME);
    } else {
        leaf(p, K::IDENTIFIER);
    }
    p.bump();
    if !at(p, K::R_PAREN) {
        // `list`, inline: one frame less per nested call.
        expr_bp(p, OR);
        while eat(p, K::COMMA) {
            expr_bp(p, OR);
        }
    }
    close(p, K::R_PAREN);
    p.exit();
    Some(m.complete(p, K::FUNCTION_CALL.raw()))
}

/// `?a.b[0].`c``.
fn field(p: &mut Parser<'_>) -> CompletedMarker {
    let m = p.start();
    if at(p, K::QUESTION) {
        leaf(p, K::OPTIONAL_MARKER);
    }
    name_part(p);
    loop {
        if at(p, K::DOT) {
            p.bump();
            name_part(p);
        } else if at(p, K::INDEX_TOKEN) {
            leaf(p, K::INDEX);
        } else {
            break;
        }
    }
    m.complete(p, K::FIELD.raw())
}

fn name_part(p: &mut Parser<'_>) {
    if at(p, K::WORD) {
        leaf(p, K::IDENTIFIER);
    } else if at(p, K::QUOTED_IDENT_TOKEN) {
        leaf(p, K::QUOTED_IDENTIFIER);
    } else {
        fail(p, "a field name is missing");
    }
}
