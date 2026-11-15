//! The statements: `let`, a function definition, a type, a control command.

use super::{P, expr, tabular};
use crate::syntax::SyntaxKind as K;
use opentide_parse::TokenSet;

/// `SourceFile = LetStatement* (Query | ControlCommand)?`
pub(super) fn source_file(p: &mut P<'_>) {
    let m = p.start();
    while p.current() == K::LET_KW {
        let_statement(p);
    }
    if p.current() == K::DOT {
        control_command(p);
    } else if !p.at_eof() {
        let q = p.start();
        tabular::tabular_expression(p);
        p.done(q, K::QUERY);
    }
    if !p.at_eof() {
        p.err_until("unexpected input after the query", TokenSet::EMPTY);
    }
    p.done(m, K::SOURCE_FILE);
}

/// `let name = value;`
fn let_statement(p: &mut P<'_>) {
    let m = p.start();
    p.bump();
    p.expect_name();
    p.expect(K::EQ);
    let_value(p);
    p.expect(K::SEMICOLON);
    p.done(m, K::LET_STATEMENT);
}

/// What a `let` binds: a function, a tabular expression or a scalar. A lone
/// name or call (`let x = T;`, `let x = f(1);`) is tabular, as it was in the
/// tree-sitter grammar; `T + 1` is a scalar.
pub(super) fn let_value(p: &mut P<'_>) {
    if p.current() == K::L_PAREN && p.nth(p.after_group(0)) == K::L_BRACE {
        function_definition(p);
    } else if is_tabular(p) {
        tabular::tabular_expression(p);
    } else {
        expr::expr(p);
    }
}

/// Whether the value that starts here is a tabular expression.
fn is_tabular(p: &P<'_>) -> bool {
    let after_value = |n: usize| {
        matches!(
            p.nth(n),
            K::SEMICOLON | K::PIPE | K::R_BRACE | K::R_PAREN | K::EOF
        )
    };
    match p.nth(0) {
        K::L_PAREN => p.paren_is_tabular(0),
        K::PRINT_KW
        | K::UNION_KW
        | K::DATATABLE_KW
        | K::EXTERNALDATA_KW
        | K::EXTERNAL_DATA_KW
        | K::MATERIALIZE_KW
        | K::SEARCH_KW
        | K::FIND_KW => true,
        K::RANGE_KW if p.name_at(1) && p.nth(2) == K::FROM_KW => true,
        K::DYNAMIC_KW | K::TOSCALAR_KW if p.nth(1) == K::L_PAREN => false,
        K::BOOLEAN | K::NULL_KW => false,
        _ if p.name_at(0) => {
            let end = if p.nth(1) == K::L_PAREN {
                p.after_group(1)
            } else {
                1
            };
            after_value(end)
        }
        _ => false,
    }
}

/// `(a: int, t: (*)) { let y = 1; body }`
fn function_definition(p: &mut P<'_>) {
    let m = p.start();
    p.bump();
    if p.current() != K::R_PAREN {
        loop {
            parameter(p);
            if !p.eat(K::COMMA) {
                break;
            }
        }
    }
    p.expect(K::R_PAREN);
    p.expect(K::L_BRACE);
    while p.current() == K::LET_KW {
        let_statement(p);
    }
    let_value(p);
    p.eat(K::SEMICOLON);
    p.expect(K::R_BRACE);
    p.done(m, K::FUNCTION_DEFINITION);
}

/// `name: type = default`
pub(super) fn parameter(p: &mut P<'_>) {
    let m = p.start();
    p.expect_name();
    p.expect(K::COLON);
    type_(p);
    if p.eat(K::EQ) {
        expr::expr(p);
    }
    p.done(m, K::PARAMETER);
}

/// A scalar type, or `(*)` or `(col: type, ...)` for a table.
pub(super) fn type_(p: &mut P<'_>) {
    let m = p.start();
    if p.current() == K::L_PAREN {
        let table = p.start();
        p.bump();
        if !p.eat(K::STAR) {
            loop {
                let column = p.start();
                p.expect_name();
                p.expect(K::COLON);
                if p.enter() {
                    type_(p);
                    p.exit();
                }
                p.done(column, K::TABLE_COLUMN);
                if !p.eat(K::COMMA) {
                    break;
                }
            }
        }
        p.expect(K::R_PAREN);
        p.done(table, K::TABLE_TYPE);
    } else if p.current() == K::DYNAMIC_KW {
        p.bump();
    } else {
        p.expect_name();
    }
    p.done(m, K::TYPE);
}

/// `.show tables`: parsed so that the engine can report it.
fn control_command(p: &mut P<'_>) {
    let m = p.start();
    p.bump();
    p.expect_name();
    while p.name_at(0) {
        p.bump_as(K::IDENT);
    }
    p.done(m, K::CONTROL_COMMAND);
}
