//! The typed AST and the conformance helper, end to end on a tiny language
//! (`fixture.ungram`): a logos lexer, a parser on the toolkit, the AST
//! `cargo xtask codegen` generates (`generated/ast.rs`, kept current by
//! `codegen --check`), and conformance of good and broken trees.

#![expect(missing_docs, reason = "a language for tests: its kinds need no docs")]

use logos::Logos;
use opentide_parse::ast::AstNode;
use opentide_parse::conformance::{assert_conforms, check};
use opentide_parse::{Grammar, Input, Parser, TokenSet, build, lex};

#[path = "generated/ast.rs"]
mod ast;

use ast::{Args, Binary, Call, Expr, Literal, Name, Paren, RULES, Root};

#[derive(Logos, Clone, Copy, Debug, PartialEq, Eq)]
enum Tok {
    #[regex(r"[ \t\r\n]+")]
    Ws,
    #[regex(r"[a-z]+")]
    Ident,
    #[regex(r"[0-9]+")]
    Number,
    #[token("+")]
    Plus,
    #[token("-")]
    Minus,
    #[token("(")]
    LParen,
    #[token(")")]
    RParen,
    #[token(",")]
    Comma,
}

/// Token kinds first, then node kinds, as `opentide-parse` asks of a language.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u16)]
#[expect(
    non_camel_case_types,
    reason = "the kinds are written as rust-analyzer's are"
)]
pub enum SyntaxKind {
    WS,
    IDENT,
    NUMBER,
    PLUS,
    MINUS,
    L_PAREN,
    R_PAREN,
    COMMA,
    ERROR,
    EOF,
    ROOT,
    CALL,
    ARGS,
    BINARY,
    PAREN,
    NAME,
    LITERAL,
}

const KINDS: [SyntaxKind; 17] = {
    use SyntaxKind::*;
    [
        WS, IDENT, NUMBER, PLUS, MINUS, L_PAREN, R_PAREN, COMMA, ERROR, EOF, ROOT, CALL, ARGS,
        BINARY, PAREN, NAME, LITERAL,
    ]
};

impl SyntaxKind {
    const fn raw(self) -> rowan::SyntaxKind {
        rowan::SyntaxKind(self as u16)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Lang {}

impl rowan::Language for Lang {
    type Kind = SyntaxKind;
    fn kind_from_raw(raw: rowan::SyntaxKind) -> SyntaxKind {
        KINDS[usize::from(raw.0)]
    }
    fn kind_to_raw(kind: SyntaxKind) -> rowan::SyntaxKind {
        kind.raw()
    }
}

pub type SyntaxNode = rowan::SyntaxNode<Lang>;
pub type SyntaxToken = rowan::SyntaxToken<Lang>;

/// The kind of each token of `fixture.ungram`.
#[macro_export]
macro_rules! T {
    [ident] => { $crate::SyntaxKind::IDENT };
    [number] => { $crate::SyntaxKind::NUMBER };
    [+] => { $crate::SyntaxKind::PLUS };
    [-] => { $crate::SyntaxKind::MINUS };
    ['('] => { $crate::SyntaxKind::L_PAREN };
    [')'] => { $crate::SyntaxKind::R_PAREN };
    [,] => { $crate::SyntaxKind::COMMA };
}

const GRAMMAR: Grammar = Grammar {
    eof: SyntaxKind::EOF.raw(),
    error: SyntaxKind::ERROR.raw(),
    trivia: TokenSet::new(&[SyntaxKind::WS.raw()]),
    max_depth: 64,
};

fn expr(p: &mut Parser<'_>) -> bool {
    let Some(mut lhs) = atom(p) else {
        return false;
    };
    while p.at(T![+].raw()) || p.at(T![-].raw()) {
        let binary = lhs.precede(p);
        p.bump();
        atom_or_error(p);
        lhs = binary.complete(p, SyntaxKind::BINARY.raw());
    }
    true
}

fn atom_or_error(p: &mut Parser<'_>) {
    if atom(p).is_none() {
        p.error("expected an expression");
    }
}

fn atom(p: &mut Parser<'_>) -> Option<opentide_parse::CompletedMarker> {
    let kind = p.current();
    if kind == T![ident].raw() {
        let name = p.start();
        p.bump();
        let name = name.complete(p, SyntaxKind::NAME.raw());
        if !p.at(T!['('].raw()) {
            return Some(name);
        }
        let call = name.precede(p);
        p.bump();
        if !p.at(T![')'].raw()) {
            let args = p.start();
            expr(p);
            while p.eat(T![,].raw()) {
                expr(p);
            }
            args.complete(p, SyntaxKind::ARGS.raw());
        }
        p.expect(T![')'].raw(), "expected `)`");
        Some(call.complete(p, SyntaxKind::CALL.raw()))
    } else if kind == T![number].raw() {
        let literal = p.start();
        p.bump();
        Some(literal.complete(p, SyntaxKind::LITERAL.raw()))
    } else if kind == T!['('].raw() {
        let paren = p.start();
        p.bump();
        if p.enter() {
            expr(p);
            p.exit();
        }
        p.expect(T![')'].raw(), "expected `)`");
        Some(paren.complete(p, SyntaxKind::PAREN.raw()))
    } else {
        None
    }
}

fn parse(source: &str) -> (SyntaxNode, usize) {
    let lexemes = lex::<Tok>(source, |token, _| match token {
        Ok(Tok::Ws) => SyntaxKind::WS.raw(),
        Ok(Tok::Ident) => SyntaxKind::IDENT.raw(),
        Ok(Tok::Number) => SyntaxKind::NUMBER.raw(),
        Ok(Tok::Plus) => SyntaxKind::PLUS.raw(),
        Ok(Tok::Minus) => SyntaxKind::MINUS.raw(),
        Ok(Tok::LParen) => SyntaxKind::L_PAREN.raw(),
        Ok(Tok::RParen) => SyntaxKind::R_PAREN.raw(),
        Ok(Tok::Comma) => SyntaxKind::COMMA.raw(),
        Err(()) => SyntaxKind::ERROR.raw(),
    });
    let input = Input::new(source, lexemes, GRAMMAR);
    let mut p = Parser::new(&input);
    let root = p.start();
    while !p.at_eof() {
        if !expr(&mut p) {
            p.err_and_bump("expected an expression");
        }
    }
    root.complete(&mut p, SyntaxKind::ROOT.raw());
    let parse = build(&input, p.finish());
    assert_eq!(parse.green.to_string(), source, "the tree is lossless");
    (SyntaxNode::new_root(parse.green), parse.errors.len())
}

const SOURCES: [&str; 6] = [
    "",
    "a",
    "f(a, 1) + (b - 2)",
    "f()\n g(h(1), 2 + 3, (4)) 5",
    "a + b - c + d",
    "((((1))))",
];

#[test]
fn parsed_trees_conform_to_the_grammar() {
    for source in SOURCES {
        let (root, errors) = parse(source);
        assert_eq!(errors, 0, "{source:?}");
        assert_conforms(&root, RULES, GRAMMAR);
    }
}

#[test]
fn accessors_follow_the_grammar() {
    let (root, _) = parse("f(a, 1) + (b - 2)");
    let root = Root::cast(root).unwrap();
    let exprs: Vec<Expr> = root.exprs().collect();
    let [Expr::Binary(binary)] = exprs.as_slice() else {
        panic!("one binary expression, got {exprs:?}");
    };
    let Some(Expr::Call(call)) = binary.lhs() else {
        panic!("the left side is a call");
    };
    let Some(Expr::Paren(paren)) = binary.rhs() else {
        panic!("the right side is a group");
    };
    assert_eq!(binary.op().map(|t| t.kind()), Some(SyntaxKind::PLUS));
    assert_eq!(call.callee().unwrap().ident_token().unwrap().text(), "f");
    assert!(call.l_paren_token().is_some() && call.r_paren_token().is_some());
    let args = call.args().unwrap();
    assert!(matches!(
        args.exprs().collect::<Vec<_>>().as_slice(),
        [Expr::Name(_), Expr::Literal(_)]
    ));
    assert_eq!(args.comma_token().unwrap().text(), ",");
    let Some(Expr::Literal(one)) = args.exprs().nth(1) else {
        panic!("a number");
    };
    assert_eq!(one.number_token().unwrap().text(), "1");
    assert!(paren.l_paren_token().is_some() && paren.r_paren_token().is_some());
    let Some(Expr::Binary(inner)) = paren.expr() else {
        panic!("a subtraction in the group");
    };
    assert_eq!(inner.op().map(|t| t.kind()), Some(SyntaxKind::MINUS));
    assert_eq!(inner.rhs().unwrap().syntax().text(), "2");
    // `can_cast` and `cast` agree, and an enum casts what its variants do.
    assert!(Expr::can_cast(SyntaxKind::NAME) && !Expr::can_cast(SyntaxKind::ARGS));
    assert!(Name::cast(call.syntax().clone()).is_none());
    assert!(Call::can_cast(SyntaxKind::CALL) && Binary::can_cast(SyntaxKind::BINARY));
    assert!(Args::can_cast(SyntaxKind::ARGS) && Paren::can_cast(SyntaxKind::PAREN));
    assert!(Literal::can_cast(SyntaxKind::LITERAL));
}

#[test]
fn a_call_without_arguments_has_none() {
    let (root, _) = parse("f()");
    let Some(Expr::Call(call)) = Root::cast(root).unwrap().exprs().next() else {
        panic!("a call");
    };
    assert!(call.args().is_none());
}

#[test]
fn every_mismatch_is_reported_with_its_range() {
    // `f(` is missing its `)`; `a +` its right side; the stray `)` is an error node.
    let (root, errors) = parse("f( a + )");
    assert!(errors > 0);
    let found = check(&root, RULES, GRAMMAR);
    let text: Vec<String> = found.iter().map(ToString::to_string).collect();
    assert!(
        text.iter()
            .any(|m| m.starts_with("BINARY at 3..6:") && m.contains("Binary = ")),
        "{text:#?}"
    );
    assert!(found.iter().all(|m| !m.range.is_empty()), "{text:#?}");

    // Broken by hand: a call with no callee, a binary with three operands, an
    // empty argument list, a root holding what is not an expression.
    let mut b = rowan::GreenNodeBuilder::new();
    let leaf = |b: &mut rowan::GreenNodeBuilder<'_>, kind: SyntaxKind, text: &str| {
        b.start_node(SyntaxKind::NAME.raw());
        b.token(kind.raw(), text);
        b.finish_node();
    };
    b.start_node(SyntaxKind::ROOT.raw());
    b.start_node(SyntaxKind::CALL.raw());
    b.token(SyntaxKind::L_PAREN.raw(), "(");
    b.token(SyntaxKind::R_PAREN.raw(), ")");
    b.finish_node();
    b.start_node(SyntaxKind::BINARY.raw());
    leaf(&mut b, SyntaxKind::IDENT, "a");
    leaf(&mut b, SyntaxKind::IDENT, "b");
    b.token(SyntaxKind::PLUS.raw(), "+");
    leaf(&mut b, SyntaxKind::IDENT, "c");
    b.finish_node();
    b.start_node(SyntaxKind::ARGS.raw());
    b.finish_node();
    b.start_node(SyntaxKind::ERROR.raw());
    b.token(SyntaxKind::COMMA.raw(), ",");
    b.finish_node();
    b.finish_node();
    let root = SyntaxNode::new_root(b.finish());
    let found: Vec<String> = check(&root, RULES, GRAMMAR)
        .iter()
        .map(ToString::to_string)
        .collect();
    assert_eq!(
        found,
        [
            "ROOT at 0..7: child 2 (ARGS) is not allowed here; `Root = Expr*`",
            "CALL at 0..2: child 0 (L_PAREN) is not allowed here; `Call = callee:Name '(' args:Args? ')'`",
            "BINARY at 2..6: child 1 (NAME) is not allowed here; `Binary = lhs:Expr op:('+' | '-') rhs:Expr`",
            "ARGS at 6..6: the children end before the rule does; `Args = Expr (',' Expr)*`",
            "ERROR at 6..7: a syntax error node",
        ]
    );
}

#[test]
#[should_panic(expected = "does not conform")]
fn assert_conforms_panics_on_a_mismatch() {
    let (root, _) = parse("(");
    assert_conforms(&root, RULES, GRAMMAR);
}
