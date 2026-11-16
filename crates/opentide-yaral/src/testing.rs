//! A window on the new parser for the crate's integration tests, which read
//! the corpus (a library source never touches the filesystem). Not an API:
//! it goes with the old engine in the last PR of the series (#1227).

use crate::lexer::lex;
use crate::parser::parse;
use crate::syntax::{SyntaxKind as K, SyntaxNode};

/// The lexemes of `source` as `(start, end, is_trivia)`: whitespace and
/// comments are trivia.
#[must_use]
pub fn lex_spans(source: &str) -> Vec<(usize, usize, bool)> {
    lex(source)
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

/// The places the tree of `source` does not conform to `yaral.ungram`, one
/// line each (`opentide_parse::conformance`); empty when it conforms.
#[must_use]
pub fn conformance(source: &str) -> Vec<String> {
    let root = SyntaxNode::new_root(parse(source).green);
    opentide_parse::conformance::check(&root, crate::ast::RULES, crate::parser::GRAMMAR)
        .iter()
        .map(ToString::to_string)
        .collect()
}

/// The tree and the errors of `source` as the snapshots show them.
#[must_use]
pub fn debug_parse(source: &str) -> String {
    let parsed = parse(source);
    let tree = SyntaxNode::new_root(parsed.green);
    let mut out = opentide_parse::debug_tree(&tree, |k| format!("{k:?}"));
    let errors = opentide_parse::debug_errors(&parsed.errors, |k| K::from_raw(k).describe());
    if !errors.is_empty() {
        out.push_str("errors:\n");
        out.push_str(&errors);
    }
    out
}

/// The analysis on the pure-Rust parser: the diagnostics and the highlight
/// tokens (production still runs tree-sitter).
#[must_use]
pub fn analyze_new(source: &str, ctx: &crate::Context) -> crate::AnalyzeResult {
    let root = SyntaxNode::new_root(parse(source).green);
    crate::AnalyzeResult {
        diagnostics: crate::analysis::diagnostics(source, *ctx),
        tokens: crate::analysis::highlight(&root, source),
    }
}

/// Hover at a byte offset, read from the pure-Rust tree.
#[must_use]
pub fn hover_new(source: &str, offset: usize) -> Option<String> {
    crate::editor::hover_in_tree(source, offset)
}

/// The profile of `source` as the pure-Rust parser reads it.
#[must_use]
pub fn infer_profile_new(source: &str) -> crate::Profile {
    crate::analysis::infer_profile(source)
}
