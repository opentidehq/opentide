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

/// An analysis on the new parser: what `analyze_with_catalog` gives.
pub struct NewAnalysis {
    /// The diagnostics, in the old order.
    pub diagnostics: Vec<opentide_core::Diagnostic>,
    /// The HIR.
    pub hir: crate::Hir,
    /// The highlight tokens.
    pub tokens: Vec<opentide_highlight::HighlightToken>,
}

/// [`crate::analyze_with_catalog`] on the new parser.
#[must_use]
pub fn analyze_new(source: &str, catalog: &crate::Catalog) -> NewAnalysis {
    let analysis = crate::diagnose::analyze(source, catalog);
    NewAnalysis {
        diagnostics: analysis.diagnostics,
        hir: analysis.hir,
        tokens: analysis.tokens,
    }
}

/// [`crate::columns`] on the new parser.
#[must_use]
pub fn columns_new(source: &str, profile: crate::Profile) -> crate::schema::Analysis {
    let catalog = crate::Catalog::for_workspace(profile, source);
    crate::diagnose::columns(source, &catalog)
}

/// [`crate::hover`] on the new parser (its column hover reads the new
/// column pass; the rest of hover reads no tree).
#[must_use]
pub fn hover_new(source: &str, offset: usize, profile: crate::Profile) -> Option<String> {
    crate::hover_with(source, offset, profile, |source, catalog| {
        Some(crate::diagnose::columns(source, catalog))
    })
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
