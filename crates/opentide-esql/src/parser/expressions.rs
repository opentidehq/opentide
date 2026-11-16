//! Expressions, constants and names: a Pratt loop in which `or` and `and`
//! chains and runs of `+ -` or `* / %` are one flat node each.
//!
//! Binding powers, as the grammar's precedences: `or` 1, `and` 2, `not` 3
//! (prefix), the predicates (`in`, `is null`, `like`, `rlike`, `:`) 4,
//! comparison 5, additive 6, multiplicative 7, unary 8, cast `::` 9.

use super::{at_kw, comma_list, eat_kw, expect_kw, nth_kw, token_node};
use crate::syntax::SyntaxKind as K;
use opentide_parse::{CompletedMarker, Parser, TokenSet};

/// Where an expression that went wrong stops eating tokens.
const RECOVERY: TokenSet = K::set(&[
    K::PIPE,
    K::COMMA,
    K::SEMI,
    K::R_PAREN,
    K::R_BRACK,
    K::R_BRACE,
]);

/// The words Elasticsearch's lexer reserves in an expression: after a number
/// they are keywords (or an error), never the unit of an interval; every other
/// word is a unit (`5 foo`, `5 from`, `5 minutes`). Checked against
/// `@elastic/esql` 4.33.0 for every keyword of the grammar after `EVAL x = 5`.
/// tree-sitter lexed by parser state and took some of these as units
/// (`LIMIT 1 LIKE`, `x > 1 on`), which Elasticsearch rejects.
const NOT_A_UNIT: [&str; 19] = [
    "and", "asc", "by", "desc", "false", "first", "in", "is", "last", "like", "not", "null",
    "nulls", "on", "or", "rlike", "true", "where", "with",
];

/// Nodes that are not an operand of `+`, `==`, `like` ... : a boolean
/// operator's result, which such an operator cannot take on its left.
const BOOLEAN: [K; 7] = [
    K::OR_EXPRESSION,
    K::AND_EXPRESSION,
    K::NOT_EXPRESSION,
    K::IN_EXPRESSION,
    K::IS_NULL_EXPRESSION,
    K::LIKE_EXPRESSION,
    K::MATCH_EXPRESSION,
];

/// Nodes of `_primary_expression`: what `::` and `:` take on their left.
const PRIMARY: [K; 11] = [
    K::QUALIFIED_NAME,
    K::FUNCTION_CALL,
    K::PARENTHESIZED_EXPRESSION,
    K::INLINE_CAST,
    K::NULL,
    K::NUMBER,
    K::QUALIFIED_INTERVAL,
    K::BOOLEAN,
    K::PARAMETER,
    K::STRING,
    K::ARRAY,
];

#[derive(Clone, Copy, PartialEq, Eq)]
enum Infix {
    Or,
    And,
    In { not: bool },
    IsNull,
    Like { not: bool },
    Match,
    Comparison,
    Additive,
    Multiplicative,
    Cast,
}

/// The operator the parser is at, and its binding power.
fn infix(p: &mut Parser<'_>) -> Option<(u8, Infix)> {
    let op = match p.current() {
        k if k == K::EQ_EQ.raw() => (5, Infix::Comparison),
        k if [K::NOT_EQ, K::LT, K::LT_EQ, K::GT, K::GT_EQ]
            .map(K::raw)
            .contains(&k) =>
        {
            (5, Infix::Comparison)
        }
        k if k == K::PLUS.raw() || k == K::MINUS.raw() => (6, Infix::Additive),
        k if [K::STAR_TOKEN, K::SLASH, K::PERCENT]
            .map(K::raw)
            .contains(&k) =>
        {
            (7, Infix::Multiplicative)
        }
        k if k == K::COLON_COLON.raw() => (9, Infix::Cast),
        k if k == K::COLON.raw() => (4, Infix::Match),
        k if k == K::WORD.raw() => {
            let is = |w: &str| p.current_text().eq_ignore_ascii_case(w);
            let not = is("not");
            let after = |w: &str| p.nth_text(1).eq_ignore_ascii_case(w);
            if is("or") {
                (1, Infix::Or)
            } else if is("and") {
                (2, Infix::And)
            } else if is("in") || (not && after("in")) {
                (4, Infix::In { not })
            } else if is("is") {
                (4, Infix::IsNull)
            } else if is("like") || is("rlike") || (not && (after("like") || after("rlike"))) {
                (4, Infix::Like { not })
            } else {
                return None;
            }
        }
        _ => return None,
    };
    Some(op)
}

/// An expression: `expr(p)` takes any, `expr_bp` only operators that bind
/// at least as tight as `min`. `None` when nothing could be parsed (an error
/// is recorded) or the nesting limit was reached.
pub(super) fn expr(p: &mut Parser<'_>) -> Option<CompletedMarker> {
    expr_bp(p, 0)
}

fn expr_bp(p: &mut Parser<'_>, min: u8) -> Option<CompletedMarker> {
    if !p.enter() {
        return None;
    }
    let done = operators(p, min);
    p.exit();
    done
}

fn operators(p: &mut Parser<'_>, min: u8) -> Option<CompletedMarker> {
    let mut lhs = prefix(p, min)?;
    loop {
        let Some((bp, op)) = infix(p) else {
            let _ = p.at_set(K::set(&[K::OR_KW, K::AND_KW]));
            break;
        };
        let lhs_kind = lhs.kind();
        let boolean = BOOLEAN.map(K::raw).contains(&lhs_kind);
        let ok = match op {
            Infix::Or | Infix::And => true,
            Infix::Cast | Infix::Match => PRIMARY.map(K::raw).contains(&lhs_kind),
            Infix::Comparison => !boolean && lhs_kind != K::COMPARISON.raw(),
            _ => !boolean,
        };
        if bp < min || !ok {
            break;
        }
        lhs = rest(p, lhs, op);
    }
    Some(lhs)
}

/// The node of the infix operator `op` the parser is at, over `lhs`: a
/// function of its own so that the frame of the recursion (`expr_bp`,
/// `operators`, `prefix`, `atom`) stays small on a 1 MB stack.
#[inline(never)]
fn rest(p: &mut Parser<'_>, lhs: CompletedMarker, op: Infix) -> CompletedMarker {
    let lhs_kind = lhs.kind();
    let m = lhs.precede(p);
    match op {
        Infix::Or | Infix::And => {
            let (kw, node, rhs_bp) = if op == Infix::Or {
                (K::OR_KW, K::OR_EXPRESSION, 2)
            } else {
                (K::AND_KW, K::AND_EXPRESSION, 3)
            };
            while eat_kw(p, kw) {
                expr_bp(p, rhs_bp);
            }
            m.complete(p, node.raw())
        }
        Infix::In { not } => {
            if not {
                p.bump_as(K::NOT_KW.raw());
            }
            p.bump_as(K::IN_KW.raw());
            in_values(p, lhs_kind == K::IN_TUPLE.raw());
            m.complete(p, K::IN_EXPRESSION.raw())
        }
        Infix::IsNull => {
            p.bump_as(K::IS_KW.raw());
            eat_kw(p, K::NOT_KW);
            expect_kw(p, K::NULL_KW);
            m.complete(p, K::IS_NULL_EXPRESSION.raw())
        }
        Infix::Like { not } => {
            if not {
                p.bump_as(K::NOT_KW.raw());
            }
            if !eat_kw(p, K::LIKE_KW) {
                eat_kw(p, K::RLIKE_KW);
            }
            patterns(p);
            m.complete(p, K::LIKE_EXPRESSION.raw())
        }
        Infix::Match => {
            p.bump();
            constant(p);
            m.complete(p, K::MATCH_EXPRESSION.raw())
        }
        Infix::Comparison => {
            p.bump();
            expr_bp(p, 6);
            m.complete(p, K::COMPARISON.raw())
        }
        Infix::Additive | Infix::Multiplicative => {
            let (ops, rhs_bp): (&[K], u8) = if op == Infix::Additive {
                (&[K::PLUS, K::MINUS], 7)
            } else {
                (&[K::STAR_TOKEN, K::SLASH, K::PERCENT], 8)
            };
            while ops.iter().any(|k| k.raw() == p.current()) {
                p.bump();
                expr_bp(p, rhs_bp);
            }
            m.complete(p, K::BINARY_EXPRESSION.raw())
        }
        Infix::Cast => {
            p.bump();
            let t = p.start();
            if p.at(K::IDENT.raw()) || p.current() == K::WORD.raw() {
                token_node(p, K::IDENT, K::IDENTIFIER);
            } else {
                p.error("expected a type name after `::`");
            }
            t.complete(p, K::TYPE_NAME.raw());
            m.complete(p, K::INLINE_CAST.raw())
        }
    }
}

/// `not x`, `-x`, `+x`, or an atom.
fn prefix(p: &mut Parser<'_>, min: u8) -> Option<CompletedMarker> {
    // `not` is a keyword only where a boolean expression may start: as the
    // operand of an arithmetic or comparison operator it is a name
    // (`a == not 2` is an error, and so is `a / not in (...)`).
    if min <= 3 && at_kw(p, K::NOT_KW) {
        let m = p.start();
        p.bump_as(K::NOT_KW.raw());
        expr_bp(p, 3);
        return Some(m.complete(p, K::NOT_EXPRESSION.raw()));
    }
    if p.at(K::MINUS.raw()) || p.at(K::PLUS.raw()) {
        let m = p.start();
        p.bump();
        expr_bp(p, 8);
        return Some(m.complete(p, K::UNARY_EXPRESSION.raw()));
    }
    atom(p)
}

/// `_primary_expression`.
fn atom(p: &mut Parser<'_>) -> Option<CompletedMarker> {
    let kind = p.current();
    if kind == K::L_PAREN.raw() {
        Some(parenthesized(p))
    } else if kind == K::WORD.raw() {
        word_atom(p)
    } else if kind == K::QUOTED_IDENT.raw() {
        Some(qualified_name(p))
    } else if kind == K::PARAM.raw() {
        param_atom(p)
    } else if [K::NUMBER_LIT, K::STRING_LIT, K::L_BRACK]
        .map(K::raw)
        .contains(&kind)
    {
        constant(p)
    } else {
        p.err_recover("expected an expression", RECOVERY);
        None
    }
}

#[inline(never)]
fn word_atom(p: &mut Parser<'_>) -> Option<CompletedMarker> {
    let text = p.current_text();
    let is = |w: &str| text.eq_ignore_ascii_case(w);
    if is("null") || is("true") || is("false") {
        constant(p)
    } else if p.nth(1) == K::L_PAREN.raw() {
        Some(function_call(p))
    } else if is("first") || is("last") {
        // A keyword here, as in tree-sitter's lexer: only a function name.
        p.err_recover(
            "`first` and `last` name functions: quote a field of that name",
            RECOVERY,
        );
        None
    } else {
        Some(qualified_name(p))
    }
}

#[inline(never)]
fn param_atom(p: &mut Parser<'_>) -> Option<CompletedMarker> {
    let next = p.nth(1);
    if next == K::DOT.raw() {
        Some(qualified_name(p))
    } else if next == K::L_PAREN.raw() {
        Some(function_call(p))
    } else {
        constant(p)
    }
}

/// `( expr )`, or the `( a, b )` of a tuple before `IN`.
fn parenthesized(p: &mut Parser<'_>) -> CompletedMarker {
    let m = p.start();
    p.bump();
    expr(p);
    let tuple = p.at(K::COMMA.raw());
    while p.eat(K::COMMA.raw()) {
        expr_bp(p, 5);
    }
    p.expect(K::R_PAREN.raw(), "expected `)`");
    if tuple && !(at_kw(p, K::IN_KW) || at_kw(p, K::NOT_KW)) {
        p.error("a tuple of values is only valid before `in`");
    }
    let kind = if tuple {
        K::IN_TUPLE
    } else {
        K::PARENTHESIZED_EXPRESSION
    };
    m.complete(p, kind.raw())
}

/// The values of `IN (...)`, or a subquery.
fn in_values(p: &mut Parser<'_>, tuple: bool) {
    if p.current() == K::L_PAREN.raw() && is_subquery(p) {
        super::commands::source_subquery(p);
        return;
    }
    if tuple {
        p.error("a tuple compares only against a subquery: `(a, b) in (from ...)`");
    }
    if p.expect(K::L_PAREN.raw(), "expected `(` after `in`") {
        comma_list(p, |p| {
            expr_bp(p, 5);
        });
        p.expect(K::R_PAREN.raw(), "expected `)`");
    }
}

/// Whether the `(` ahead opens `(FROM ...)`, `(TS ...)` or `(ROW ...)`.
fn is_subquery(p: &Parser<'_>) -> bool {
    [K::FROM_KW, K::TS_KW, K::ROW_KW]
        .iter()
        .any(|&kw| nth_kw(p, 1, kw))
}

/// The pattern of `LIKE`: a primary expression, or a parenthesised list of
/// strings and parameters.
fn patterns(p: &mut Parser<'_>) {
    if p.eat(K::L_PAREN.raw()) {
        comma_list(p, |p| {
            if p.current() == K::PARAM.raw() {
                token_node(p, K::PARAM, K::PARAMETER);
            } else if p.current() == K::STRING_LIT.raw() {
                token_node(p, K::STRING_LIT, K::STRING);
            } else {
                p.err_recover("expected a string or a parameter", RECOVERY);
            }
        });
        p.expect(K::R_PAREN.raw(), "expected `)`");
    } else {
        primary(p);
    }
}

/// A primary expression and its casts.
pub(super) fn primary(p: &mut Parser<'_>) {
    if let Some(atom) = atom(p) {
        cast_chain(p, atom);
    }
}

/// `x::type::type`: a primary expression with its casts.
fn cast_chain(p: &mut Parser<'_>, mut lhs: CompletedMarker) {
    while p.at(K::COLON_COLON.raw()) {
        let m = lhs.precede(p);
        p.bump();
        token_node(p, K::IDENT, K::IDENTIFIER);
        lhs = m.complete(p, K::INLINE_CAST.raw());
    }
}

/// The arguments of a call, and its `)`.
fn call_arguments(p: &mut Parser<'_>) {
    if p.at(K::STAR_TOKEN.raw()) {
        token_node(p, K::STAR_TOKEN, K::STAR);
    } else if !p.at(K::R_PAREN.raw()) {
        loop {
            expr(p);
            if !p.eat(K::COMMA.raw()) {
                break;
            }
            if p.at(K::L_BRACE.raw()) {
                map_expression(p);
                break;
            }
        }
    }
    p.expect(K::R_PAREN.raw(), "expected `)` after the arguments");
}

/// `name(args)`, `?param(args)`.
#[inline(never)]
fn function_call(p: &mut Parser<'_>) -> CompletedMarker {
    let m = p.start();
    if p.current() == K::PARAM.raw() {
        token_node(p, K::PARAM, K::PARAMETER);
    } else {
        token_node(p, K::IDENT, K::IDENTIFIER);
    }
    p.bump();
    // A call is charged two levels (this and its argument's): its frames are
    // twice a parenthesis's, and `max_depth` is set for parentheses.
    if p.enter() {
        call_arguments(p);
        p.exit();
    }
    m.complete(p, K::FUNCTION_CALL.raw())
}

/// `{ "key": value, ... }`.
pub(super) fn map_expression(p: &mut Parser<'_>) {
    let m = p.start();
    if !p.at(K::L_BRACE.raw()) {
        p.error("expected `{`");
    } else if p.enter() {
        p.bump();
        if !p.at(K::R_BRACE.raw()) {
            comma_list(p, |p| {
                let entry = p.start();
                if p.at(K::STRING_LIT.raw()) {
                    token_node(p, K::STRING_LIT, K::STRING);
                } else {
                    p.error("expected a string key");
                }
                p.expect(K::COLON.raw(), "expected `:` after the key");
                if p.at(K::L_BRACE.raw()) {
                    map_expression(p);
                } else {
                    constant_before(p, &[]);
                }
                entry.complete(p, K::MAP_ENTRY.raw());
            });
        }
        p.expect(K::R_BRACE.raw(), "expected `}`");
        p.exit();
    }
    m.complete(p, K::MAP_EXPRESSION.raw());
}

/// `_constant`: null, an interval, a number, a boolean, a parameter, a string or an array.
pub(super) fn constant(p: &mut Parser<'_>) -> Option<CompletedMarker> {
    constant_before(p, &NOT_A_UNIT)
}

/// A constant, where the words `follow` are keywords after a number and not
/// its unit: tree-sitter lexed a word as a keyword only where the grammar
/// could take it, so `LIMIT 5 WITH` reads `WITH` as the unit of `5`.
pub(super) fn constant_before(p: &mut Parser<'_>, follow: &[&str]) -> Option<CompletedMarker> {
    let kind = p.current();
    let word = |p: &Parser<'_>, w: &str| p.current_text().eq_ignore_ascii_case(w);
    if kind == K::WORD.raw() && word(p, "null") {
        let m = p.start();
        p.bump_as(K::NULL_KW.raw());
        Some(m.complete(p, K::NULL.raw()))
    } else if kind == K::WORD.raw() && (word(p, "true") || word(p, "false")) {
        let m = p.start();
        p.bump_as(
            if word(p, "true") {
                K::TRUE_KW
            } else {
                K::FALSE_KW
            }
            .raw(),
        );
        Some(m.complete(p, K::BOOLEAN.raw()))
    } else if kind == K::NUMBER_LIT.raw() {
        let number = number(p);
        let unit = p.current() == K::WORD.raw()
            && !follow
                .iter()
                .any(|w| p.current_text().eq_ignore_ascii_case(w));
        if !unit {
            return Some(number);
        }
        let m = number.precede(p);
        token_node(p, K::IDENT, K::TIME_UNIT);
        Some(m.complete(p, K::QUALIFIED_INTERVAL.raw()))
    } else if kind == K::STRING_LIT.raw() {
        let m = p.start();
        p.bump();
        Some(m.complete(p, K::STRING.raw()))
    } else if kind == K::PARAM.raw() {
        let m = p.start();
        p.bump();
        Some(m.complete(p, K::PARAMETER.raw()))
    } else if kind == K::L_BRACK.raw() {
        Some(array(p))
    } else {
        p.err_recover("expected a constant", RECOVERY);
        None
    }
}

fn number(p: &mut Parser<'_>) -> CompletedMarker {
    let m = p.start();
    p.bump();
    m.complete(p, K::NUMBER.raw())
}

/// `[1, 2]`, `["a"]`, `[true]`.
fn array(p: &mut Parser<'_>) -> CompletedMarker {
    let m = p.start();
    p.bump();
    comma_list(p, |p| {
        if p.current() == K::PLUS.raw() || p.current() == K::MINUS.raw() {
            p.bump();
            if p.at(K::NUMBER_LIT.raw()) {
                number(p);
            } else {
                p.error("expected a number");
            }
        } else if p.at(K::NUMBER_LIT.raw()) {
            number(p);
        } else if p.at(K::STRING_LIT.raw()) {
            token_node(p, K::STRING_LIT, K::STRING);
        } else if !(at_kw(p, K::TRUE_KW) || at_kw(p, K::FALSE_KW)) {
            p.err_recover("expected an array element", RECOVERY);
        } else {
            constant(p);
        }
    });
    p.expect(K::R_BRACK.raw(), "expected `]`");
    m.complete(p, K::ARRAY.raw())
}

/// One part of a name: an identifier, a quoted identifier or a parameter.
pub(super) fn name_part(p: &mut Parser<'_>) {
    let kind = p.current();
    if kind == K::WORD.raw() {
        token_node(p, K::IDENT, K::IDENTIFIER);
    } else if kind == K::QUOTED_IDENT.raw() {
        token_node(p, K::QUOTED_IDENT, K::QUOTED_IDENTIFIER);
    } else if kind == K::PARAM.raw() {
        token_node(p, K::PARAM, K::PARAMETER);
    } else {
        let _ = p.at(K::IDENT.raw());
        p.err_recover("expected a name", RECOVERY);
    }
}

/// `a.b.c`.
pub(super) fn qualified_name(p: &mut Parser<'_>) -> CompletedMarker {
    let m = p.start();
    name_part(p);
    while p.eat(K::DOT.raw()) {
        name_part(p);
    }
    m.complete(p, K::QUALIFIED_NAME.raw())
}

/// `a*.b`: a name pattern, where a word may hold `*`.
pub(super) fn name_pattern(p: &mut Parser<'_>) {
    let m = p.start();
    loop {
        let kind = p.current();
        if kind == K::WORD.raw() {
            token_node(p, K::ID_PATTERN_TEXT, K::ID_PATTERN);
        } else if kind == K::QUOTED_IDENT.raw() {
            token_node(p, K::QUOTED_IDENT, K::QUOTED_IDENTIFIER);
        } else if kind == K::PARAM.raw() {
            token_node(p, K::PARAM, K::PARAMETER);
        } else {
            let _ = p.at(K::ID_PATTERN_TEXT.raw());
            p.err_recover("expected a name pattern", RECOVERY);
        }
        if !p.eat(K::DOT.raw()) {
            break;
        }
    }
    m.complete(p, K::NAME_PATTERN.raw());
}
