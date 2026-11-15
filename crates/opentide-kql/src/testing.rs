//! A window on the new parser for the crate's integration tests, which read
//! the corpus (a library source never touches the filesystem). Not an API:
//! it goes with the old engine in the last PR of the series (#1230).

use crate::lexer::lex_kql;
use crate::parser::parse;
use crate::syntax::{SyntaxKind as K, SyntaxNode};

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
