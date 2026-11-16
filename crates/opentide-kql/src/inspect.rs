//! The parser's tokens and tree as plain data, for the crate's corpus and
//! differential tests and `opentide-analysis`'s corpus gate, which read
//! files (a library source never touches the filesystem). Not an API: hidden
//! from the docs, like `opentide_kuery::debug_parse`.

use crate::lexer::lex_kql;
use crate::parser::parse;
use crate::syntax::{ALL, SyntaxKind as K, SyntaxNode};
use rowan::NodeOrToken;
use std::collections::BTreeSet;

/// The lexemes of `source` as `(start, end, is_trivia)`: whitespace and
/// comments are trivia.
#[must_use]
pub fn lex_spans(source: &str) -> Vec<(usize, usize, bool)> {
    lex_kql(source)
        .iter()
        .map(|l| {
            let trivia = matches!(K::from_raw(l.kind), K::WHITESPACE | K::COMMENT);
            (
                usize::from(l.range.start()),
                usize::from(l.range.end()),
                trivia,
            )
        })
        .collect()
}

/// Whether the tree of `source` prints back as `source`.
#[must_use]
pub fn parse_is_lossless(source: &str) -> bool {
    SyntaxNode::new_root(parse(source).green).to_string() == source
}

/// How many syntax errors `source` has.
#[must_use]
pub fn parse_error_count(source: &str) -> usize {
    parse(source).errors.len()
}

/// The kinds of the significant tokens of `source`, by name.
#[must_use]
pub fn token_kinds(source: &str) -> Vec<String> {
    lex_kql(source)
        .iter()
        .map(|l| K::from_raw(l.kind))
        .filter(|k| !matches!(k, K::WHITESPACE | K::COMMENT))
        .map(|k| format!("{k:?}"))
        .collect()
}

/// How many times this thread has parsed a text with the new parser.
#[must_use]
pub fn parse_count() -> u64 {
    crate::parser::parse_count()
}

/// The places the tree of `source` does not conform to `kql.ungram`, one line
/// each (`opentide_parse::conformance`); empty when it conforms.
#[must_use]
pub fn conformance(source: &str) -> Vec<String> {
    let root = SyntaxNode::new_root(parse(source).green);
    opentide_parse::conformance::check(&root, crate::ast::RULES, crate::parser::GRAMMAR)
        .iter()
        .map(ToString::to_string)
        .collect()
}

/// The pipelines of `source` as text: each one's source and its operators,
/// for the differential's generated queries.
#[must_use]
pub fn pipeline_parts(source: &str) -> Vec<(String, Vec<String>)> {
    use crate::syntax_util::{is_operator, text};
    let root = SyntaxNode::new_root(parse(source).green);
    root.descendants()
        .filter(|n| n.kind() == K::TABULAR_EXPRESSION)
        .filter_map(|expr| {
            let head = expr.children().find(|c| c.kind() == K::TABULAR_SOURCE)?;
            let ops = expr
                .children()
                .filter(|op| is_operator(op.kind()))
                .map(|op| text(source, &op).to_owned())
                .collect();
            Some((text(source, &head).to_owned(), ops))
        })
        .collect()
}

/// The names of the tree's node kinds, lower-case (`where_operator`,
/// `let_statement`): the productions of `opentide-analysis`'s corpus gate.
#[must_use]
pub fn node_kinds() -> Vec<String> {
    ALL.iter()
        .filter(|k| !k.is_token())
        .map(|k| format!("{k:?}").to_ascii_lowercase())
        .collect()
}

/// What the corpus gate reads of the tree of `source`: whether the parser
/// reported a syntax error, the lower-case names of the kinds of its nodes
/// and tokens, and the tree as indented text (for a failure message).
#[must_use]
pub fn tree_kinds(source: &str) -> (bool, BTreeSet<String>, String) {
    let parsed = parse(source);
    let root = SyntaxNode::new_root(parsed.green);
    let kinds = root
        .preorder_with_tokens()
        .filter_map(|event| match event {
            rowan::WalkEvent::Enter(NodeOrToken::Node(n)) => Some(n.kind()),
            rowan::WalkEvent::Enter(NodeOrToken::Token(t)) => Some(t.kind()),
            rowan::WalkEvent::Leave(_) => None,
        })
        .map(|k| format!("{k:?}").to_ascii_lowercase())
        .collect();
    (!parsed.errors.is_empty(), kinds, format!("{root:#?}"))
}
