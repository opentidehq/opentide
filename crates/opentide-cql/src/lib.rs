//! I/O-free CrowdStrike Query Language (CQL) engine: Falcon LogScale and
//! Falcon Next-Gen SIEM (`configurations.crowdstrike`).
//!
//! The tree-sitter grammar (`grammars/tree-sitter-opentide-cql`) is the parser;
//! it follows CrowdStrike's published CQL grammar. [`analyze`] reports its first
//! syntax error and then the checks of [`check`] against the catalogs of
//! [`catalog`]. See `docs/engine/CQL.md`.
//!
//! Internal to opentide, with no stability promise: depend on the
//! [`opentide`](https://docs.rs/opentide) crate, its Rust SDK, instead.

#![expect(
    missing_docs,
    reason = "imported from language-server with public items undocumented: crates/AGENTS.md, Lints"
)]

pub mod assist;
pub mod catalog;
pub mod check;

pub use assist::{completions, hover, signature_help};

use catalog::Catalog;
use opentide_core::{ByteSpan, Diagnostic, LanguageId, Range, codes, span_to_range};
use opentide_highlight::{HighlightSpec, HighlightToken, tokens_from_spans};
use opentide_syntax::{first_error, node_span, parse as ts_parse};
use tree_sitter::{Node, Tree};

/// Where the query runs.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Context {
    /// A Next-Gen SIEM correlation rule (`configurations.crowdstrike.query`),
    /// which adds CrowdStrike's correlation-rule restrictions.
    pub correlation_rule: bool,
}

impl Context {
    pub const CORRELATION_RULE: Context = Context {
        correlation_rule: true,
    };
}

#[derive(Debug, Clone, Default)]
pub struct AnalyzeResult {
    pub diagnostics: Vec<Diagnostic>,
    pub tokens: Vec<HighlightToken>,
}

/// Analyze a CQL query on its own (a raw `.cql` file or a hunt search).
pub fn analyze(source: &str) -> AnalyzeResult {
    analyze_with(source, &Context::default())
}

/// Analyze a CQL query where `ctx` says it runs.
#[expect(
    clippy::expect_used,
    reason = "loads the HighlightSpec compiled in (highlights/spec.toml): a bad spec fails the tests, never a user's document"
)]
pub fn analyze_with(source: &str, ctx: &Context) -> AnalyzeResult {
    let spec = HighlightSpec::load().expect("highlight spec");
    let Some(tree) = ts_parse(LanguageId::Cql, source) else {
        return AnalyzeResult {
            diagnostics: vec![Diagnostic::error(
                codes::CQL_PARSE_ERROR,
                "failed to initialize the CQL parser",
                Range::point(0, 0),
            )],
            tokens: Vec::new(),
        };
    };
    let root = tree.root_node();
    let mut diagnostics = Vec::new();
    if let Some(err) = first_error(root) {
        diagnostics.push(Diagnostic::error(
            codes::CQL_PARSE_ERROR,
            parse_error_message(err, source),
            span_to_range(source, node_span(err)),
        ));
    }
    diagnostics.extend(check::diagnostics(root, source, ctx));
    AnalyzeResult {
        diagnostics,
        tokens: highlight(&spec, &tree, source),
    }
}

fn parse_error_message(err: Node, source: &str) -> String {
    if err.is_missing() {
        return format!("CQL syntax error: missing `{}`", err.kind());
    }
    // Text pasted from a web page often carries U+00A0, which CQL does not
    // read as a space: blame it when it is where the parser stopped.
    let before = source[..err.start_byte()].chars().next_back();
    if before == Some('\u{a0}') || text(err, source).contains('\u{a0}') {
        return "CQL syntax error: a non-breaking space (U+00A0) is not whitespace in CQL; replace it with a space".to_string();
    }
    let first = text(err, source).split_whitespace().next().unwrap_or("");
    if first.is_empty() {
        "CQL syntax error".to_string()
    } else {
        format!("CQL syntax error near `{first}`")
    }
}

/// Highlight tokens. A call to a catalogued function is `function.builtin`;
/// any other call (a newer function) stays `function`.
fn highlight(spec: &HighlightSpec, tree: &Tree, source: &str) -> Vec<HighlightToken> {
    let Ok(mut spans) = opentide_syntax::query_captures_in(
        LanguageId::Cql,
        tree,
        source,
        opentide_highlight::CQL_HIGHLIGHTS_SCM,
    ) else {
        return Vec::new();
    };
    let catalog = Catalog::cached();
    for (span, capture) in &mut spans {
        if capture == "function" {
            let name = source.get(span.start..span.end).unwrap_or("");
            if catalog.function(name).is_some_and(|f| !f.removed) {
                *capture = "function.builtin".into();
            }
        }
    }
    let refs: Vec<(ByteSpan, &str)> = spans.iter().map(|(s, c)| (*s, c.as_str())).collect();
    tokens_from_spans(spec, source, &refs).unwrap_or_default()
}

pub(crate) fn text<'a>(node: Node, source: &'a str) -> &'a str {
    source.get(node.start_byte()..node.end_byte()).unwrap_or("")
}

pub(crate) fn range(source: &str, node: Node) -> Range {
    span_to_range(source, node_span(node))
}

#[cfg(test)]
mod tests;
