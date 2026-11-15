//! A tabular expression: a source and the operators after its pipes.
//! This file holds the skeleton and the operators of the first PR; the
//! others read as an unknown operator until the next PR adds them.

use super::{P, expr};
use crate::syntax::SyntaxKind as K;

/// `source | operator | operator`
pub(super) fn tabular_expression(p: &mut P<'_>) {
    let m = p.start();
    if p.enter() {
        let s = p.start();
        source(p);
        p.done(s, K::TABULAR_SOURCE);
        while p.at(K::PIPE) {
            p.bump();
            operator(p);
        }
        p.exit();
    }
    p.done(m, K::TABULAR_EXPRESSION);
}

/// A table, a call, a parenthesised pipeline, `materialize(...)`.
fn source(p: &mut P<'_>) {
    match p.current() {
        K::L_PAREN => {
            let m = p.start();
            p.bump();
            tabular_expression(p);
            p.expect(K::R_PAREN);
            p.done(m, K::PAREN_TABULAR);
        }
        K::MATERIALIZE_KW if p.nth(1) == K::L_PAREN => {
            let m = p.start();
            p.bump();
            p.bump();
            tabular_expression(p);
            p.expect(K::R_PAREN);
            p.done(m, K::MATERIALIZE_EXPRESSION);
        }
        _ if p.name_at(0) && p.nth(1) == K::L_PAREN => {
            expr::function_call(p);
        }
        _ => {
            let m = p.start();
            p.expect_name();
            p.done(m, K::TABLE_REF);
        }
    }
}

/// One operator after a pipe.
fn operator(p: &mut P<'_>) {
    let m = p.start();
    match p.current() {
        K::WHERE_KW | K::FILTER_KW => {
            let kind = if p.current() == K::WHERE_KW {
                K::WHERE_OPERATOR
            } else {
                K::FILTER_OPERATOR
            };
            p.bump();
            expr::expr(p);
            p.done(m, kind);
        }
        K::TAKE_KW | K::LIMIT_KW => {
            let kind = if p.current() == K::TAKE_KW {
                K::TAKE_OPERATOR
            } else {
                K::LIMIT_OPERATOR
            };
            p.bump();
            p.expect(K::NUMBER);
            p.done(m, kind);
        }
        K::COUNT_KW => {
            p.bump();
            p.done(m, K::COUNT_OPERATOR);
        }
        _ => {
            p.expect_name();
            if expr::at_expr_start(p) {
                expr::expr(p);
            }
            p.done(m, K::UNKNOWN_OPERATOR);
        }
    }
}
