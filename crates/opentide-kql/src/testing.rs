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

/// Whether `source` holds a keyword of an operator that the parser does not
/// take yet (it reads it as an unknown operator): the verdict comparison
/// with tree-sitter leaves those files out. Goes when the operators land.
#[must_use]
pub fn names_an_unparsed_operator(source: &str) -> bool {
    crate::lexer::lex_kql(source).iter().any(|l| {
        let kind = K::from_raw(l.kind);
        (K::MATERIALIZE_KW as u16..=K::REGEX_KW as u16).contains(&(kind as u16))
            && !matches!(
                kind,
                K::WHERE_KW
                    | K::FILTER_KW
                    | K::TAKE_KW
                    | K::LIMIT_KW
                    | K::COUNT_KW
                    | K::IN_KW
                    | K::AND_KW
                    | K::OR_KW
                    | K::NOT_KW
                    | K::MATCHES_KW
                    | K::REGEX_KW
                    | K::MATERIALIZE_KW
            )
    })
}
