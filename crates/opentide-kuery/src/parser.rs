//! Kibana KQL's grammar, as functions over [`opentide_parse::Parser`]. It
//! follows `grammars/tree-sitter-opentide-kuery/grammar.js` (Kibana's
//! `grammar.peggy`): `or` < `and` < `not`; a run of `and` (or `or`) is one
//! flat node, so a 20 000-term chain is not 20 000 levels deep.

use crate::syntax::{SyntaxKind as K, SyntaxNode, lex};
use opentide_parse::{Grammar, Input, Parse, Parser, TokenSet, build};

/// Nesting (`(`, `field:(`, `field:{`) deeper than this is one error. Kibana's
/// own PEG parser recurses too; real rules nest a handful of levels.
pub const MAX_DEPTH: u32 = 256;

/// Error messages the analysis maps to its own text.
pub(crate) const MISSING_PAREN: &str = "missing `)`";
pub(crate) const MISSING_BRACE: &str = "missing `}`";
pub(crate) const MISSING_VALUE: &str = "missing a value";
pub(crate) const UNEXPECTED: &str = "unexpected";

const WORDISH: TokenSet = K::set(&[K::Word, K::OrKw, K::AndKw, K::NotKw]);
const RANGE_OPS: TokenSet = K::set(&[K::Lt, K::Lte, K::Gt, K::Gte]);

/// Parses `source` (with Kibana's trailing-keyword masking when `mask`).
pub fn parse(source: &str, mask: bool) -> (SyntaxNode, Parse) {
    let grammar = Grammar {
        eof: K::Eof.raw(),
        error: K::Error.raw(),
        trivia: K::set(&[K::Whitespace]),
        max_depth: MAX_DEPTH,
    };
    let input = Input::new(lex(source, mask), grammar);
    let mut p = Parser::new(&input);
    let root = p.start();
    if !p.at_eof() {
        query(&mut p);
    }
    // What follows a complete query cannot continue it (KQL has no implicit
    // `and`): skip a token, and read on as tree-sitter's recovery does.
    at(&mut p, K::Eof);
    while !p.at_eof() {
        p.err_and_bump(UNEXPECTED);
        let next = p.current();
        if next == K::LParen.raw() || next == K::QuotedString.raw() || WORDISH.contains(next) {
            query(&mut p);
        }
    }
    root.complete(&mut p, K::SourceFile.raw());
    let parse = build(source, &input, p.finish());
    (SyntaxNode::new_root(parse.green.clone()), parse)
}

fn at(p: &mut Parser<'_>, kind: K) -> bool {
    p.at(kind.raw())
}

/// `_query`: `or` chains of `and` chains of `not`/sub-queries.
fn query(p: &mut Parser<'_>) {
    chain(p, K::OrKw, K::OrQuery, |p| {
        chain(p, K::AndKw, K::AndQuery, unary);
    });
}

/// `operand (op operand)*` as one node of `kind` when an `op` follows.
fn chain(p: &mut Parser<'_>, op: K, kind: K, operand: fn(&mut Parser<'_>)) {
    let m = p.start();
    operand(p);
    if !at(p, op) {
        m.abandon(p);
        return;
    }
    while at(p, op) {
        p.bump();
        operand(p);
    }
    m.complete(p, kind.raw());
}

fn unary(p: &mut Parser<'_>) {
    if at(p, K::NotKw) {
        let m = p.start();
        p.bump();
        sub_query(p);
        m.complete(p, K::NotQuery.raw());
    } else {
        sub_query(p);
    }
}

/// `_sub_query`: a group, or a literal that may turn out to be a field.
fn sub_query(p: &mut Parser<'_>) {
    if at(p, K::LParen) {
        if !p.enter() {
            return;
        }
        let m = p.start();
        p.bump();
        query(p);
        close(p, K::RParen, MISSING_PAREN);
        m.complete(p, K::Group.raw());
        p.exit();
        return;
    }
    let outer = p.start();
    let field = p.start();
    if !literal(p) {
        field.abandon(p);
        outer.abandon(p);
        p.error(MISSING_VALUE);
        return;
    }
    if at(p, K::Colon) {
        field.complete(p, K::Field.raw());
        p.bump();
        if at(p, K::LBrace) {
            if !p.enter() {
                return;
            }
            p.bump();
            query(p);
            close(p, K::RBrace, MISSING_BRACE);
            outer.complete(p, K::NestedQuery.raw());
            p.exit();
        } else {
            value(p);
            outer.complete(p, K::FieldValueExpression.raw());
        }
    } else if p.at_set(RANGE_OPS) {
        field.complete(p, K::Field.raw());
        p.bump();
        if !literal(p) {
            p.error(MISSING_VALUE);
        }
        outer.complete(p, K::RangeExpression.raw());
    } else {
        field.abandon(p);
        outer.complete(p, K::ValueExpression.raw());
    }
}

/// `)` or `}`; anything else before it is one error node.
fn close(p: &mut Parser<'_>, kind: K, missing: &str) {
    if at(p, kind) {
        p.bump();
        return;
    }
    if p.at_eof() {
        p.error(missing);
        return;
    }
    p.err_until(UNEXPECTED, K::set(&[kind]));
    if at(p, kind) {
        p.bump();
    } else {
        p.error(missing);
    }
}

/// `_literal`: a quoted string, or a run of words (`and`/`or` end it, `not`
/// does not: Kibana's grammar has no keyword there).
fn literal(p: &mut Parser<'_>) -> bool {
    // What fits here, for an error's expected set: a word or a quoted string
    // (`and`, `or` and `not` are words here, so they are not named).
    p.at_set(K::set(&[K::Word, K::QuotedString]));
    // A character no token takes (a lone `\`, an unclosed `"`) is an error
    // node; the literal may follow it.
    while p.current() == K::ErrorToken.raw() {
        p.err_and_bump(UNEXPECTED);
    }
    if p.current() == K::QuotedString.raw() {
        p.bump();
        return true;
    }
    if !WORDISH.contains(p.current()) {
        return false;
    }
    let m = p.start();
    p.bump_as(K::Word.raw());
    // A further word continues the value: valid, but not worth naming in an
    // error's expected set, so the lookahead is not recorded.
    while matches!(p.current(), k if k == K::Word.raw() || k == K::NotKw.raw()) {
        p.bump_as(K::Word.raw());
    }
    m.complete(p, K::UnquotedLiteral.raw());
    true
}

/// After `field:`: a `( list )` or a literal.
fn value(p: &mut Parser<'_>) {
    if at(p, K::LParen) {
        value_list(p);
    } else if !literal(p) {
        p.error(MISSING_VALUE);
    }
}

fn value_list(p: &mut Parser<'_>) {
    if !p.enter() {
        return;
    }
    let m = p.start();
    p.bump();
    chain(p, K::OrKw, K::OrList, |p| {
        chain(p, K::AndKw, K::AndList, list_unary);
    });
    close(p, K::RParen, MISSING_PAREN);
    m.complete(p, K::ValueList.raw());
    p.exit();
}

fn list_unary(p: &mut Parser<'_>) {
    let m = (at(p, K::NotKw)).then(|| {
        let m = p.start();
        p.bump();
        m
    });
    if at(p, K::LParen) {
        value_list(p);
    } else if !literal(p) {
        p.error(MISSING_VALUE);
    }
    if let Some(m) = m {
        m.complete(p, K::NotList.raw());
    }
}
