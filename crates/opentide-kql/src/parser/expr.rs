//! Expressions, by precedence: `or`, `and`, `not`, a comparison, `+ -`,
//! `* / %`, a sign, then a primary with its `.member` and `[index]`.
//! A chain of `or` (or `and`, `+`, `*`) is one node with all its operands.

use super::{P, tabular};
use crate::syntax::SyntaxKind as K;
use opentide_parse::CompletedMarker;

const NOT_AN_EXPRESSION: &str = "expected an expression";
const MATERIALIZE_IN_SCALAR: &str = "`materialize` takes a tabular expression and is not a scalar function; if it is meant as a name, bracket it as ['materialize']";

/// An expression, or an error where one was expected. `false` when the
/// nesting limit was reached.
pub(super) fn expr(p: &mut P<'_>) -> bool {
    if !p.enter() {
        return false;
    }
    if or_expr(p).is_none() {
        p.error(NOT_AN_EXPRESSION);
    }
    p.exit();
    true
}

/// Whether an expression can start at the current token.
pub(super) fn at_expr_start(p: &P<'_>) -> bool {
    matches!(
        p.current(),
        K::STRING
            | K::NUMBER
            | K::TIMESPAN
            | K::TYPED_LITERAL
            | K::QUOTED_IDENT
            | K::L_PAREN
            | K::MINUS
            | K::PLUS
    ) || p.name_at(0)
}

/// One level of a flat chain: `operand (op operand)*` as one `kind` node.
fn chain(
    p: &mut P<'_>,
    kind: K,
    is_op: fn(&mut P<'_>) -> bool,
    operand: fn(&mut P<'_>) -> Option<CompletedMarker>,
) -> Option<CompletedMarker> {
    let first = operand(p)?;
    if !is_op(p) {
        return Some(first);
    }
    let m = p.precede(first);
    while is_op(p) {
        p.bump();
        if operand(p).is_none() {
            p.error(NOT_AN_EXPRESSION);
            break;
        }
    }
    Some(p.done(m, kind))
}

fn or_expr(p: &mut P<'_>) -> Option<CompletedMarker> {
    chain(p, K::OR_EXPR, |p| p.at(K::OR_KW), and_expr)
}

fn and_expr(p: &mut P<'_>) -> Option<CompletedMarker> {
    chain(p, K::AND_EXPR, |p| p.at(K::AND_KW), not_expr)
}

/// `not` takes a comparison, and only one: `not not a` is an error, as it
/// was in the tree-sitter grammar.
fn not_expr(p: &mut P<'_>) -> Option<CompletedMarker> {
    if p.current() != K::NOT_KW {
        return comparison(p);
    }
    let m = p.start();
    p.bump();
    if comparison(p).is_none() {
        p.error(NOT_AN_EXPRESSION);
    }
    Some(p.done(m, K::NOT_EXPR))
}

/// `a == b`, `a matches regex b`, `a in (..)`, `a between (x .. y)`: one
/// operator, not a chain.
fn comparison(p: &mut P<'_>) -> Option<CompletedMarker> {
    let mut lhs = additive(p)?;
    let mut next = p.current();
    // `a : "x" == true`: the search term binds first. Read from the token the
    // operator match reads anyway: a level of its own cost every operand a
    // call (parse +1.0% on the external corpus).
    let mut term = false;
    if next == K::COLON {
        lhs = colon_rest(p, lhs);
        next = p.current();
        term = true;
    }
    // A search term stands where a string operator does: after one, only an
    // equality or ordering, a set or a range test (`a : "x" == true`, `a :
    // "x" in (…)`); `a : "x" has "y"` is an error, as in Kusto.
    let (kind, shape) = match next {
        K::CMP_OP if !term || equality_or_ordering(p.nth_text(0)) => {
            (K::COMPARISON_EXPR, Shape::Operand)
        }
        K::MATCHES_KW if !term => (K::COMPARISON_EXPR, Shape::Matches),
        K::IN_KW if p.nth(1) == K::L_PAREN => (K::IN_EXPR, Shape::List),
        K::SET_OP => (K::IN_EXPR, Shape::List),
        K::BETWEEN_OP => (K::BETWEEN_EXPR, Shape::Range),
        _ => return Some(lhs),
    };
    let equality = shape == Shape::Operand && equality_or_ordering(p.nth_text(0));
    let m = p.precede(lhs);
    p.bump();
    match shape {
        // `a == "x" : true`; after a string operator the right side is no
        // search term (`a has "y" : "x"` is an error).
        Shape::Operand if equality => operand_or_error(p, colon_operand),
        Shape::Operand => operand_or_error(p, additive),
        Shape::Matches => {
            p.expect(K::REGEX_KW);
            operand_or_error(p, additive);
        }
        Shape::List => expression_list(p),
        Shape::Range => range(p),
    }
    Some(p.done(m, kind))
}

/// `Column : "value"`, a search term, from its `:`: Kusto reads `:`
/// anywhere an expression goes, binding tighter than `==` (`a : "x" == true`,
/// `a == "x" : true`) and once (`a : b : c` is an error). The callers test the
/// token with `current`, not `at`: a missing operator's message names no `:`.
fn colon_rest(p: &mut P<'_>, lhs: CompletedMarker) -> CompletedMarker {
    let m = p.precede(lhs);
    p.bump();
    operand_or_error(p, additive);
    p.done(m, K::COMPARISON_EXPR)
}

/// The right operand of a comparison, a search term included.
fn colon_operand(p: &mut P<'_>) -> Option<CompletedMarker> {
    let rhs = additive(p)?;
    Some(if p.current() == K::COLON {
        colon_rest(p, rhs)
    } else {
        rhs
    })
}

/// `==`, `!=`, `<>` and the orderings: the comparisons a search term goes with.
fn equality_or_ordering(op: &str) -> bool {
    matches!(op, "==" | "!=" | "<>" | "<" | "<=" | ">" | ">=")
}

#[derive(PartialEq, Eq)]
enum Shape {
    Operand,
    Matches,
    List,
    Range,
}

fn operand_or_error(p: &mut P<'_>, operand: fn(&mut P<'_>) -> Option<CompletedMarker>) {
    if operand(p).is_none() {
        p.error(NOT_AN_EXPRESSION);
    }
}

fn additive(p: &mut P<'_>) -> Option<CompletedMarker> {
    chain(
        p,
        K::ADDITIVE_EXPR,
        |p| p.at(K::PLUS) || p.at(K::MINUS),
        multiplicative,
    )
}

fn multiplicative(p: &mut P<'_>) -> Option<CompletedMarker> {
    chain(
        p,
        K::MULTIPLICATIVE_EXPR,
        |p| p.at(K::STAR) || p.at(K::SLASH) || p.at(K::PERCENT),
        unary,
    )
}

/// A sign, once, then a primary: `--a` is an error.
pub(super) fn unary(p: &mut P<'_>) -> Option<CompletedMarker> {
    if !matches!(p.current(), K::MINUS | K::PLUS) {
        return primary(p);
    }
    let m = p.start();
    p.bump();
    if primary(p).is_none() {
        p.error(NOT_AN_EXPRESSION);
    }
    Some(p.done(m, K::UNARY_EXPR))
}

/// A primary expression and its `.member`, `[index]`: no sign and no binary
/// operator (a legacy `render … title=` value), or an error.
pub(super) fn postfix(p: &mut P<'_>) {
    if primary(p).is_none() {
        p.error(NOT_AN_EXPRESSION);
    }
}

/// A primary expression and the `.member` and `[index]` that follow it.
fn primary(p: &mut P<'_>) -> Option<CompletedMarker> {
    let mut lhs = match p.current() {
        K::STRING | K::NUMBER | K::TIMESPAN | K::TYPED_LITERAL | K::BOOLEAN | K::NULL_KW => {
            let m = p.start();
            p.bump();
            p.done(m, K::LITERAL)
        }
        K::DYNAMIC_KW if p.nth(1) == K::L_PAREN => dynamic_literal(p),
        K::TOSCALAR_KW if p.nth(1) == K::L_PAREN => toscalar(p),
        K::L_PAREN => {
            let m = p.start();
            p.bump();
            expr(p);
            p.expect(K::R_PAREN);
            p.done(m, K::PAREN_EXPR)
        }
        K::QUOTED_IDENT => name_ref(p),
        // `* has "x"`: every column, as Kusto's term search takes it, on the
        // left of a string operator (`has`, `contains`, `startswith`, `=~`,
        // `matches regex`, ...), `==` or the search term's `:`, and of nothing
        // else: not `!=`, `<` or `>=`, not `in` or `has_any`.
        K::STAR
            if matches!(p.nth(1), K::MATCHES_KW | K::COLON)
                || (p.nth(1) == K::CMP_OP
                    && !matches!(p.0.nth_text(1), "!=" | "<>" | "<" | "<=" | ">" | ">=")) =>
        {
            let m = p.start();
            p.bump();
            p.done(m, K::STAR_EXPR)
        }
        // In an expression, `dynamic` and `toscalar` only open
        // `dynamic(...)` and `toscalar(...)`: never a column, as in the old
        // grammar (found by the switch's full differential, seed 3).
        K::DYNAMIC_KW | K::TOSCALAR_KW => return None,
        // `materialize(...)` takes a tabular expression: a keyword of the
        // tabular grammar, never a scalar function (#1638). Kusto reports it
        // as a missing expression and hints at the bracketed name; the call
        // is still read, so that nothing after it is noise.
        K::MATERIALIZE_KW if p.nth(1) == K::L_PAREN => {
            p.error(MATERIALIZE_IN_SCALAR);
            function_call(p)
        }
        _ if p.name_at(0) => {
            if p.nth(1) == K::L_PAREN {
                function_call(p)
            } else {
                name_ref(p)
            }
        }
        _ => {
            p.hyphen_keyword_in_expression();
            return None;
        }
    };
    loop {
        p.quoted_name_after_value();
        match (p.current(), p.nth(1)) {
            (K::DOT, K::L_BRACKET) | (K::L_BRACKET, _) => {
                let m = p.precede(lhs);
                p.eat(K::DOT);
                p.bump();
                expr(p);
                p.expect(K::R_BRACKET);
                lhs = p.done(m, K::INDEX_EXPR);
            }
            (K::DOT, _) => {
                let m = p.precede(lhs);
                p.bump();
                p.expect_name();
                lhs = p.done(m, K::MEMBER_EXPR);
            }
            _ => return Some(lhs),
        }
    }
}

/// A range bound of a graph edge, `*1..3`: a signed primary, no operator.
pub(super) fn graph_bound(p: &mut P<'_>) {
    if unary(p).is_none() {
        p.error(NOT_AN_EXPRESSION);
    }
}

/// A name token of a graph edge, as a bare token (the edge's own `name`).
pub(super) fn name_ref_token(p: &mut P<'_>) {
    if p.at(K::QUOTED_IDENT) {
        p.bump();
    } else {
        p.bump_as(K::IDENT);
    }
}

pub(super) fn name_ref(p: &mut P<'_>) -> CompletedMarker {
    let m = p.start();
    if p.current() == K::QUOTED_IDENT {
        p.bump();
    } else {
        p.bump_as(K::IDENT);
    }
    p.done(m, K::NAME_REF)
}

/// `name(arg, name = arg, *)`
pub(super) fn function_call(p: &mut P<'_>) -> CompletedMarker {
    let m = p.start();
    p.bump_as(K::IDENT);
    p.bump();
    if p.current() != K::R_PAREN {
        loop {
            argument(p);
            if !p.eat(K::COMMA) {
                break;
            }
        }
    }
    p.expect(K::R_PAREN);
    p.done(m, K::FUNCTION_CALL)
}

fn argument(p: &mut P<'_>) {
    if p.current() == K::STAR && matches!(p.nth(1), K::COMMA | K::R_PAREN) {
        let m = p.start();
        p.bump();
        p.done(m, K::STAR_ARG);
    } else if p.name_at(0) && p.nth(1) == K::EQ {
        let m = p.start();
        p.bump_as(K::IDENT);
        p.bump();
        expr(p);
        p.done(m, K::NAMED_ARGUMENT);
    } else {
        expr(p);
    }
}

/// `(a, b)`, or `(T | project x)`.
fn expression_list(p: &mut P<'_>) {
    let m = p.start();
    let tabular = p.paren_is_tabular(0);
    if p.expect(K::L_PAREN) {
        if tabular {
            if p.enter() {
                tabular::tabular_expression(p);
                p.exit();
            }
        } else if p.current() != K::R_PAREN {
            loop {
                expr(p);
                if !p.eat(K::COMMA) {
                    break;
                }
            }
        }
        p.expect(K::R_PAREN);
    }
    p.done(m, K::EXPRESSION_LIST);
}

/// `(from .. to)`
fn range(p: &mut P<'_>) {
    let m = p.start();
    if p.expect(K::L_PAREN) {
        expr(p);
        p.expect(K::DOT_DOT);
        expr(p);
        p.expect(K::R_PAREN);
    }
    p.done(m, K::RANGE);
}

/// `toscalar(T | ...)`
fn toscalar(p: &mut P<'_>) -> CompletedMarker {
    let m = p.start();
    p.bump();
    p.bump();
    if p.enter() {
        tabular::tabular_expression(p);
        p.exit();
    }
    p.expect(K::R_PAREN);
    p.done(m, K::TOSCALAR_EXPR)
}

/// `dynamic([1, "a"])`, `dynamic({"k": null})`, `dynamic(null)`.
pub(super) fn dynamic_literal(p: &mut P<'_>) -> CompletedMarker {
    let m = p.start();
    p.bump();
    p.bump();
    if p.current() != K::R_PAREN && p.enter() {
        json_value(p);
        p.exit();
    }
    p.expect(K::R_PAREN);
    p.done(m, K::DYNAMIC_LITERAL)
}

fn json_value(p: &mut P<'_>) {
    match p.current() {
        K::L_BRACKET => {
            let m = p.start();
            p.bump();
            json_items(p, K::R_BRACKET, |p| {
                if p.enter() {
                    json_value(p);
                    p.exit();
                }
            });
            p.done(m, K::JSON_ARRAY);
        }
        K::L_BRACE => {
            let m = p.start();
            p.bump();
            json_items(p, K::R_BRACE, |p| {
                let property = p.start();
                p.expect(K::STRING);
                p.expect(K::COLON);
                if p.enter() {
                    json_value(p);
                    p.exit();
                }
                p.done(property, K::JSON_PROPERTY);
            });
            p.done(m, K::JSON_OBJECT);
        }
        K::STRING | K::MINUS | K::NUMBER | K::BOOLEAN | K::NULL_KW => {
            let m = p.start();
            if p.eat(K::MINUS) {
                p.expect(K::NUMBER);
            } else {
                p.bump();
            }
            p.done(m, K::JSON_SCALAR);
        }
        _ => p.error("expected a JSON value"),
    }
}

/// `item, item,` up to `close`: a trailing comma is allowed.
fn json_items(p: &mut P<'_>, close: K, item: fn(&mut P<'_>)) {
    while p.current() != close && !p.at_eof() {
        item(p);
        if !p.eat(K::COMMA) {
            break;
        }
    }
    p.expect(close);
}
