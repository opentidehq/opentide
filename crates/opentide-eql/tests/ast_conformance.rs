//! The typed AST of `eql.ungram` (`src/generated/ast.rs`, written by `cargo xtask codegen`, kept
//! current by `codegen --check`), compiled and read. The parser is not in this PR yet, so the
//! trees here are built by hand, as the parser will build them: the typed accessors read them,
//! the generated `RULES` accept them, and a tree of the wrong shape is reported. The corpus-wide
//! conformance test comes with the parser.

#![expect(dead_code, reason = "the included modules are used in part")]

#[path = "../src/generated/ast.rs"]
mod ast;
#[path = "../src/syntax.rs"]
mod syntax;

use opentide_parse::Grammar;
use opentide_parse::ast::AstNode;
use opentide_parse::conformance::check;
use rowan::GreenNodeBuilder;
pub(crate) use syntax::{Lang, SyntaxKind, SyntaxNode, SyntaxToken};

use SyntaxKind as K;

const GRAMMAR: Grammar = Grammar {
    eof: K::EOF.raw(),
    error: K::ERROR.raw(),
    trivia: SyntaxKind::set(&[K::WHITESPACE, K::LINE_COMMENT, K::BLOCK_COMMENT]),
    max_depth: 1_024,
};

/// A tree written as nested items: a token `(kind, text)` or a node `[kind, children]`.
enum Item {
    Token(SyntaxKind, &'static str),
    Node(SyntaxKind, Vec<Item>),
}

fn tok(kind: SyntaxKind, text: &'static str) -> Item {
    Item::Token(kind, text)
}

fn node(kind: SyntaxKind, children: Vec<Item>) -> Item {
    Item::Node(kind, children)
}

fn ws() -> Item {
    tok(K::WHITESPACE, " ")
}

fn ident(text: &'static str) -> Item {
    node(K::IDENTIFIER, vec![tok(K::WORD, text)])
}

fn field(text: &'static str) -> Item {
    node(K::FIELD, vec![ident(text)])
}

fn number(text: &'static str) -> Item {
    node(K::NUMBER, vec![tok(K::NUMBER_TOKEN, text)])
}

fn build(root: Item) -> SyntaxNode {
    fn go(builder: &mut GreenNodeBuilder<'_>, item: &Item) {
        match item {
            Item::Token(kind, text) => builder.token(kind.raw(), text),
            Item::Node(kind, children) => {
                builder.start_node(kind.raw());
                for child in children {
                    go(builder, child);
                }
                builder.finish_node();
            }
        }
    }
    let mut builder = GreenNodeBuilder::new();
    go(&mut builder, &root);
    SyntaxNode::new_root(builder.finish())
}

/// `process where a == 1 and b : ("x", "y") | head 3`
fn event_query() -> SyntaxNode {
    build(node(
        K::SOURCE_FILE,
        vec![
            node(
                K::EVENT_QUERY,
                vec![
                    node(K::EVENT_CATEGORY, vec![ident("process")]),
                    ws(),
                    tok(K::WHERE_KW, "where"),
                    ws(),
                    node(
                        K::AND_EXPRESSION,
                        vec![
                            node(
                                K::COMPARISON,
                                vec![field("a"), ws(), tok(K::EQ_EQ, "=="), ws(), number("1")],
                            ),
                            ws(),
                            tok(K::AND_KW, "and"),
                            ws(),
                            node(
                                K::PREDICATE_EXPRESSION,
                                vec![
                                    field("b"),
                                    ws(),
                                    tok(K::COLON, ":"),
                                    ws(),
                                    tok(K::L_PAREN, "("),
                                    node(K::STRING, vec![tok(K::STRING_TOKEN, "\"x\"")]),
                                    tok(K::COMMA, ","),
                                    ws(),
                                    node(K::STRING, vec![tok(K::STRING_TOKEN, "\"y\"")]),
                                    tok(K::R_PAREN, ")"),
                                ],
                            ),
                        ],
                    ),
                ],
            ),
            ws(),
            node(
                K::PIPE_STAGE,
                vec![tok(K::PIPE, "|"), ws(), ident("head"), ws(), number("3")],
            ),
        ],
    ))
}

/// `sequence by k with maxspan=5m [any where true] by k2 until [file where f~(x)]`
fn sequence() -> SyntaxNode {
    let subquery = |category: Item, condition: Item| {
        node(
            K::SUBQUERY,
            vec![
                tok(K::L_BRACK, "["),
                category,
                ws(),
                tok(K::WHERE_KW, "where"),
                ws(),
                condition,
                tok(K::R_BRACK, "]"),
            ],
        )
    };
    build(node(
        K::SOURCE_FILE,
        vec![node(
            K::SEQUENCE,
            vec![
                tok(K::SEQUENCE_KW, "sequence"),
                ws(),
                node(K::JOIN_KEYS, vec![tok(K::BY_KW, "by"), ws(), field("k")]),
                ws(),
                node(
                    K::SEQUENCE_PARAMS,
                    vec![
                        tok(K::WITH_KW, "with"),
                        ws(),
                        tok(K::MAXSPAN_KW, "maxspan"),
                        tok(K::EQ, "="),
                        node(K::TIME_UNIT, vec![number("5"), ident("m")]),
                    ],
                ),
                ws(),
                node(
                    K::SEQUENCE_TERM,
                    vec![
                        subquery(
                            node(K::ANY, vec![tok(K::ANY_KW, "any")]),
                            node(K::BOOLEAN, vec![tok(K::TRUE_KW, "true")]),
                        ),
                        ws(),
                        node(K::JOIN_KEYS, vec![tok(K::BY_KW, "by"), ws(), field("k2")]),
                    ],
                ),
                ws(),
                tok(K::UNTIL_KW, "until"),
                ws(),
                node(
                    K::SEQUENCE_TERM,
                    vec![subquery(
                        node(K::EVENT_CATEGORY, vec![ident("file")]),
                        node(
                            K::FUNCTION_CALL,
                            vec![
                                node(K::CASE_INSENSITIVE_NAME, vec![tok(K::TILDE_WORD, "f~")]),
                                tok(K::L_PAREN, "("),
                                field("x"),
                                tok(K::R_PAREN, ")"),
                            ],
                        ),
                    )],
                ),
            ],
        )],
    ))
}

fn assert_conforms(root: &SyntaxNode) {
    let found = check(root, ast::RULES, GRAMMAR);
    assert!(found.is_empty(), "{found:#?}");
}

#[test]
fn every_node_kind_has_a_rule() {
    let first = K::SOURCE_FILE as u16;
    let last = K::STRING as u16;
    for raw in first..=last {
        assert!(
            ast::RULES.iter().any(|rule| rule.kind == raw),
            "{:?} has no rule in eql.ungram",
            SyntaxKind::from_raw(rowan::SyntaxKind(raw))
        );
    }
    assert_eq!(
        ast::RULES.len(),
        usize::from(last - first + 1),
        "a rule for a kind that is not a node"
    );
}

#[test]
fn an_event_query_conforms_and_reads() {
    let root = event_query();
    assert_eq!(
        root.to_string(),
        r#"process where a == 1 and b : ("x", "y") | head 3"#
    );
    assert_conforms(&root);

    let file = ast::SourceFile::cast(root).expect("a source file");
    let Some(ast::Query::EventQuery(query)) = file.query() else {
        panic!("an event query");
    };
    let Some(ast::Category::EventCategory(category)) = query.category() else {
        panic!("an event category");
    };
    assert_eq!(category.syntax().to_string(), "process");
    let Some(ast::Expr::AndExpression(and)) = query.condition() else {
        panic!("an `and`");
    };
    let operands: Vec<String> = and.exprs().map(|e| e.syntax().to_string()).collect();
    assert_eq!(operands, ["a == 1", r#"b : ("x", "y")"#]);
    let pipe = file.pipe_stages().next().expect("a pipe");
    assert_eq!(pipe.name().expect("a name").syntax().to_string(), "head");
    assert_eq!(pipe.exprs().count(), 1);
}

#[test]
fn a_sequence_conforms_and_reads() {
    let root = sequence();
    assert_eq!(
        root.to_string(),
        "sequence by k with maxspan=5m [any where true] by k2 until [file where f~(x)]"
    );
    assert_conforms(&root);

    let file = ast::SourceFile::cast(root).expect("a source file");
    let Some(ast::Query::Sequence(sequence)) = file.query() else {
        panic!("a sequence");
    };
    assert_eq!(
        sequence.by().next().expect("keys").syntax().to_string(),
        "by k"
    );
    let unit = sequence
        .params()
        .next()
        .and_then(|p| p.maxspan())
        .expect("a maxspan");
    assert_eq!(unit.value().expect("a value").syntax().to_string(), "5");
    assert_eq!(unit.unit().expect("a unit").syntax().to_string(), "m");
    assert_eq!(sequence.sequence_terms().count(), 2);
}

#[test]
fn a_tree_of_the_wrong_shape_is_reported() {
    // An event query without `where`, and a comparison with no right operand.
    let root = build(node(
        K::SOURCE_FILE,
        vec![node(
            K::EVENT_QUERY,
            vec![
                node(K::EVENT_CATEGORY, vec![ident("process")]),
                ws(),
                node(K::COMPARISON, vec![field("a"), ws(), tok(K::EQ_EQ, "==")]),
            ],
        )],
    ));
    let found = check(&root, ast::RULES, GRAMMAR);
    let kinds: Vec<&str> = found.iter().map(|m| m.kind.as_str()).collect();
    assert_eq!(kinds, ["EVENT_QUERY", "COMPARISON"], "{found:#?}");
    assert!(
        found[0].message.contains("EventQuery = "),
        "{}",
        found[0].message
    );
}
