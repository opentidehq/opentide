//! Statements and expressions, by precedence climbing, in the order of the
//! tree-sitter grammar's `PREC`: `or`, `and`, `not`, comparisons (and `in`),
//! `+ -`, `* / %`, a sign, a quantified field. A chain of `or` (or `and`,
//! `+ -`, `* / %`) is one node with all its operands; comparisons nest to the
//! left, as `a = b = c` did.
//!
//! Statements are written one after the other, so an operator that can also
//! start a statement (`-`, `!`) is taken as a binary operator after an
//! operand, as the LR parser did.

use super::P;
use crate::syntax::SyntaxKind as K;
use opentide_parse::CompletedMarker;

const NOT_AN_EXPRESSION: &str = "expected an expression";

/// The precedence of the operator at the cursor, when it is an infix one.
fn infix_prec(kind: K) -> Option<u8> {
    Some(match kind {
        K::OR_KW => 1,
        K::AND_KW => 2,
        K::EQ | K::NOT_EQ | K::LT | K::LT_EQ | K::GT | K::GT_EQ | K::IN_KW => 4,
        K::PLUS | K::MINUS => 5,
        K::STAR | K::SLASH | K::PERCENT => 6,
        _ => return None,
    })
}

/// What a `not` takes: a comparison and what binds tighter.
const NOT_OPERAND: u8 = 4;

/// Whether a statement (an expression, or `cross join`) can start here.
pub(super) fn at_statement_start(p: &P<'_>) -> bool {
    matches!(
        p.current(),
        K::VAR_TOKEN
            | K::COUNT_TOKEN
            | K::REF_LIST_TOKEN
            | K::IDENT
            | K::STRING
            | K::RAW_STRING
            | K::REGEX_LIT
            | K::INTEGER
            | K::FLOAT
            | K::DURATION
            | K::TRUE_KW
            | K::FALSE_KW
            | K::WINDOW_START_KW
            | K::WINDOW_END_KW
            | K::L_PAREN
            | K::L_BRACK
            | K::MINUS
            | K::BANG
            | K::NOT_KW
            | K::ANY_KW
            | K::ALL_KW
            | K::IF_KW
    )
}

/// A statement: an expression, or `cross join $a, $b` (`cross` is a keyword
/// wherever a statement starts).
pub(super) fn statement(p: &mut P<'_>) {
    if p.at_word(0, "cross") {
        cross_join(p);
    } else {
        expr(p);
    }
}

fn cross_join(p: &mut P<'_>) {
    let m = p.start();
    p.bump_word(K::CROSS_KW);
    if p.at_word(0, "join") {
        p.bump_word(K::JOIN_KW);
    } else {
        p.error("expected `join`");
    }
    loop {
        if p.at(K::VAR_TOKEN) {
            variable(p);
        } else {
            p.error("expected a variable such as `$e`");
        }
        if !p.eat(K::COMMA) {
            break;
        }
    }
    p.done(m, K::CROSS_JOIN);
}

/// An expression, or an error where one was expected. `false` when there was
/// none (or the nesting limit was reached).
pub(super) fn expr(p: &mut P<'_>) -> bool {
    let found = expr_bp(p, 1).is_some();
    if !found {
        p.error(NOT_AN_EXPRESSION);
    }
    found
}

/// Operators of precedence `min` and above.
fn expr_bp(p: &mut P<'_>, min: u8) -> Option<CompletedMarker> {
    let mut lhs = prefix(p)?;
    while let Some(prec) = infix_prec(p.current()).filter(|&prec| prec >= min) {
        lhs = if prec == 4 {
            comparison(p, lhs)
        } else {
            chain(p, lhs, prec)
        };
    }
    Some(lhs)
}

/// `a or b or c`, `a + b - c`: one node for the whole run of one precedence.
fn chain(p: &mut P<'_>, lhs: CompletedMarker, prec: u8) -> CompletedMarker {
    let kind = match prec {
        1 => K::OR_EXPR,
        2 => K::AND_EXPR,
        _ => K::BINARY_EXPR,
    };
    let m = p.precede(lhs);
    while infix_prec(p.current()) == Some(prec) {
        p.bump();
        if expr_bp(p, prec + 1).is_none() {
            p.error(NOT_AN_EXPRESSION);
            break;
        }
    }
    p.done(m, kind)
}

/// `a = b nocase`, `a in regex %list nocase`.
fn comparison(p: &mut P<'_>, lhs: CompletedMarker) -> CompletedMarker {
    let m = p.precede(lhs);
    let kind = if p.at(K::IN_KW) {
        p.bump();
        if !p.eat(K::REGEX_KW) {
            p.eat(K::CIDR_KW);
        }
        list(p);
        K::IN_EXPR
    } else {
        p.bump();
        if expr_bp(p, 5).is_none() {
            p.error(NOT_AN_EXPRESSION);
        }
        K::COMPARISON
    };
    p.eat(K::NOCASE_KW);
    p.done(m, kind)
}

/// The right side of `in`: `%list` or `%table.column`.
fn list(p: &mut P<'_>) {
    if p.at(K::REF_LIST_TOKEN) {
        reference_list(p, false);
    } else {
        p.error("expected a reference list such as `%list`");
    }
}

/// Prefix operators and primaries.
fn prefix(p: &mut P<'_>) -> Option<CompletedMarker> {
    if !p.enter() {
        return None;
    }
    let done = match p.current() {
        K::NOT_KW => {
            let m = p.start();
            p.bump();
            if expr_bp(p, NOT_OPERAND).is_none() {
                p.error(NOT_AN_EXPRESSION);
            }
            Some(p.done(m, K::NOT_EXPR))
        }
        K::MINUS | K::BANG => {
            let m = p.start();
            p.bump();
            if prefix(p).is_none() {
                p.error(NOT_AN_EXPRESSION);
            }
            Some(p.done(m, K::UNARY_EXPR))
        }
        K::ANY_KW | K::ALL_KW if p.nth(1) == K::OF_KW => Some(of_expr(p)),
        K::INTEGER if p.nth(1) == K::OF_KW => Some(of_expr(p)),
        K::ANY_KW | K::ALL_KW => Some(quantified_field(p)),
        _ => primary(p),
    };
    p.exit();
    done
}

/// `any of [$a, $b]`, `2 of [...]`.
fn of_expr(p: &mut P<'_>) -> CompletedMarker {
    let m = p.start();
    p.bump();
    p.bump();
    if p.at(K::L_BRACK) {
        array(p);
    } else {
        p.error("expected `[`");
    }
    p.done(m, K::OF_EXPR)
}

/// `any $e.ip`, `all $e.ip`.
fn quantified_field(p: &mut P<'_>) -> CompletedMarker {
    let m = p.start();
    p.bump();
    field_ref(p);
    p.done(m, K::QUANTIFIED_FIELD)
}

/// A variable, a UDM path (`$e.a.b`) or a bare path (`a.b`). `false` (and an
/// error) when none is there.
pub(super) fn field_ref(p: &mut P<'_>) -> bool {
    match p.current() {
        K::VAR_TOKEN => {
            variable(p);
            true
        }
        K::IDENT if is_accessor(p.nth(1)) => {
            bare_field(p);
            true
        }
        _ => {
            p.error("expected a field such as `$e.field`");
            false
        }
    }
}

fn is_accessor(kind: K) -> bool {
    matches!(kind, K::ACCESS_DOT | K::INDEX_L_BRACK)
}

/// A variable, and the accessors after it: a `UdmField`.
fn variable(p: &mut P<'_>) -> CompletedMarker {
    let m = p.start();
    p.bump();
    let var = p.done(m, K::VARIABLE);
    if !is_accessor(p.current()) {
        return var;
    }
    let m = p.precede(var);
    accessors(p);
    p.done(m, K::UDM_FIELD)
}

fn bare_field(p: &mut P<'_>) -> CompletedMarker {
    let m = p.start();
    p.bump();
    accessors(p);
    p.done(m, K::BARE_FIELD)
}

/// `.segment` and `["key"]`, written with no blank before them.
fn accessors(p: &mut P<'_>) {
    loop {
        let m = p.start();
        match p.current() {
            K::ACCESS_DOT => {
                p.bump();
                p.expect(K::FIELD_NAME);
                p.done(m, K::MEMBER);
            }
            K::INDEX_L_BRACK => {
                p.bump();
                if matches!(p.current(), K::STRING | K::RAW_STRING | K::INTEGER) {
                    p.bump();
                } else {
                    p.error("expected a string or an integer key");
                }
                p.expect(K::R_BRACK);
                p.done(m, K::INDEX);
            }
            _ => {
                p.abandon(m);
                return;
            }
        }
    }
}

fn primary(p: &mut P<'_>) -> Option<CompletedMarker> {
    Some(match p.current() {
        K::L_PAREN => {
            let m = p.start();
            p.bump();
            expr(p);
            p.expect(K::R_PAREN);
            p.done(m, K::PAREN_EXPR)
        }
        K::VAR_TOKEN => variable(p),
        K::COUNT_TOKEN => leaf(p, K::COUNT_REF),
        K::REF_LIST_TOKEN => reference_list(p, true),
        K::IDENT => ident(p),
        K::IF_KW => if_expr(p),
        K::L_BRACK => array(p),
        K::STRING
        | K::RAW_STRING
        | K::REGEX_LIT
        | K::INTEGER
        | K::FLOAT
        | K::DURATION
        | K::TRUE_KW
        | K::FALSE_KW => leaf(p, K::LITERAL),
        K::WINDOW_START_KW | K::WINDOW_END_KW => leaf(p, K::WINDOW_BOUND),
        _ => return None,
    })
}

/// A token wrapped in a node of `kind`.
fn leaf(p: &mut P<'_>, kind: K) -> CompletedMarker {
    let m = p.start();
    p.bump();
    p.done(m, kind)
}

/// A name: a call (`count(x)`, `strings.to_lower(x)`), a bare path
/// (`principal.hostname`) or a bare name.
fn ident(p: &mut P<'_>) -> CompletedMarker {
    let call = p.nth(1) == K::L_PAREN
        || (p.nth(1) == K::ACCESS_DOT && p.nth(2) == K::FIELD_NAME && p.nth(3) == K::L_PAREN);
    if call {
        function_call(p)
    } else if is_accessor(p.nth(1)) {
        bare_field(p)
    } else {
        leaf(p, K::NAME_REF)
    }
}

/// `name(args) nocase`, `namespace.name(args) nocase`.
fn function_call(p: &mut P<'_>) -> CompletedMarker {
    let m = p.start();
    let name = p.start();
    p.bump();
    if p.at(K::ACCESS_DOT) {
        p.bump();
        p.bump();
    }
    p.done(name, K::FUNCTION_NAME);
    call_arguments(p);
    p.eat(K::NOCASE_KW);
    p.done(m, K::FUNCTION_CALL)
}

/// `(` arguments `)`.
fn call_arguments(p: &mut P<'_>) {
    p.expect(K::L_PAREN);
    if !p.at(K::R_PAREN) {
        let m = p.start();
        loop {
            argument(p);
            if !p.eat(K::COMMA) {
                break;
            }
        }
        p.done(m, K::ARGUMENTS);
    }
    p.expect(K::R_PAREN);
}

/// Whether a named argument (`name:` or `a.b.c:`) starts here.
fn named_ahead(p: &P<'_>) -> bool {
    if p.current() != K::IDENT {
        return false;
    }
    let mut i = 1;
    loop {
        match p.nth(i) {
            K::ACCESS_DOT if p.nth(i + 1) == K::FIELD_NAME => i += 2,
            K::INDEX_L_BRACK
                if matches!(p.nth(i + 1), K::STRING | K::RAW_STRING | K::INTEGER)
                    && p.nth(i + 2) == K::R_BRACK =>
            {
                i += 3;
            }
            _ => return p.nth(i) == K::COLON,
        }
    }
}

/// `name: value`, `a.b: value`, `name: *`, or an expression.
fn argument(p: &mut P<'_>) {
    if !named_ahead(p) {
        expr(p);
        return;
    }
    let m = p.start();
    let name = p.start();
    if is_accessor(p.nth(1)) {
        bare_field(p);
    } else {
        p.bump();
    }
    p.done(name, K::ARGUMENT_NAME);
    p.expect(K::COLON);
    if !p.eat(K::STAR) {
        expr(p);
    }
    p.done(m, K::NAMED_ARGUMENT);
}

/// `%list`, and with `call` allowed `%table.column` and `%table.fn(args)`.
fn reference_list(p: &mut P<'_>, call: bool) -> CompletedMarker {
    let list = leaf(p, K::REFERENCE_LIST);
    if !p.at(K::DOT) {
        return list;
    }
    let m = p.precede(list);
    p.bump();
    let is_call = call && p.current() == K::IDENT && p.nth(1) == K::L_PAREN;
    p.expect(K::IDENT);
    if is_call {
        call_arguments(p);
        p.done(m, K::TABLE_CALL)
    } else {
        p.done(m, K::DATA_TABLE_COLUMN)
    }
}

/// `if(condition, then[, else])`.
fn if_expr(p: &mut P<'_>) -> CompletedMarker {
    let m = p.start();
    p.bump();
    p.expect(K::L_PAREN);
    expr(p);
    if p.expect(K::COMMA) {
        expr(p);
        if p.eat(K::COMMA) {
            expr(p);
        }
    }
    p.expect(K::R_PAREN);
    p.done(m, K::IF_EXPR)
}

/// `[a, b,]`.
fn array(p: &mut P<'_>) -> CompletedMarker {
    let m = p.start();
    p.bump();
    while !p.at(K::R_BRACK) {
        if !expr(p) || !p.eat(K::COMMA) {
            break;
        }
    }
    p.expect(K::R_BRACK);
    p.done(m, K::ARRAY_EXPR)
}
