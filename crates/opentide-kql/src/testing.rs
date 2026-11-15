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

/// What the new parser gives of an analysis so far: the diagnostics that
/// read the tree, and the highlight tokens (the column pass and the
/// performance checks are still on tree-sitter).
pub struct NewAnalysis {
    /// The diagnostics, in the old order.
    pub diagnostics: Vec<opentide_core::Diagnostic>,
    /// The highlight tokens.
    pub tokens: Vec<opentide_highlight::HighlightToken>,
}

/// [`crate::analyze_with_catalog`] as far as the new parser goes.
#[must_use]
pub fn analyze_new(source: &str, catalog: &crate::Catalog) -> NewAnalysis {
    let analysis = crate::diagnose::analyze(source, catalog);
    NewAnalysis {
        diagnostics: analysis.diagnostics,
        tokens: analysis.tokens,
    }
}

/// The diagnostic codes `analyze_new` reports: what the old engine's other
/// diagnostics (columns, performance) are left out by.
pub const NEW_CODES: &[&str] = &[
    opentide_core::codes::KQL_PARSE_ERROR,
    opentide_core::codes::KQL_CONTROL_COMMAND_UNSUPPORTED,
    opentide_core::codes::KQL_UNKNOWN_OPERATOR,
    opentide_core::codes::KQL_RENDER_NOT_VALID,
    opentide_core::codes::KQL_UNKNOWN_FUNCTION,
    opentide_core::codes::KQL_DEPRECATED_FUNCTION,
    opentide_core::codes::KQL_DEPRECATED_OPERATOR,
    opentide_core::codes::KQL_UNKNOWN_TABLE,
    opentide_core::codes::KQL_TABLE_NOT_DECLARED,
];
