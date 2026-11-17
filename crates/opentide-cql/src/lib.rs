//! I/O-free CrowdStrike Query Language (CQL) engine: Falcon LogScale and
//! Falcon Next-Gen SIEM (`configurations.crowdstrike`).
//!
//! The parser is pure Rust: a logos lexer (`lexer`) and a hand-written
//! recursive-descent grammar (`parser`) over the `opentide-parse` toolkit, into
//! a lossless rowan tree (`syntax`). It follows CrowdStrike's published CQL
//! grammar. [`analyze`] reports its first syntax error and then the checks of
//! [`check`] against the catalogs of [`catalog`]. See `docs/engine/CQL.md`.
//!
//! Internal to opentide, with no stability promise: depend on the
//! [`opentide`](https://docs.rs/opentide) crate, its Rust SDK, instead.

#![expect(
    missing_docs,
    reason = "imported from language-server with public items undocumented: crates/AGENTS.md, Lints"
)]
#![expect(
    clippy::too_many_lines,
    reason = "engine dispatchers match every node kind in one function"
)]
pub mod assist;
pub mod catalog;
pub mod check;
mod highlight;
mod lexer;
mod parser;
mod syntax;

pub use assist::{completions, hover, signature_help};

use opentide_core::{ByteSpan, Diagnostic, Range, codes, span_to_range};
use opentide_highlight::{HighlightSpec, HighlightToken};
use opentide_parse::{ErrorKind, SyntaxError};
use rowan::TextRange;
use syntax::{SyntaxKind as K, SyntaxNode};

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

/// The node and token kinds of a parse of `source`, by their `snake_case` names, and
/// whether it has a syntax error: what the corpus gate reads
/// (`crates/opentide-analysis/tests/corpus_gate.rs`). Not part of the API.
#[doc(hidden)]
#[must_use]
pub fn debug_kinds(source: &str) -> (bool, Vec<String>) {
    let (root, parse) = parser::parse(source);
    let kinds = root
        .descendants_with_tokens()
        .map(|e| syntax::snake_case(e.kind()))
        .collect();
    (!parse.errors.is_empty(), kinds)
}

/// For each syntax error of `source`, the `snake_case` names of the nodes it was recorded in: what
/// the corpus gate of `opentide-analysis` reads to check that an invalid fixture fails in the
/// production it names. Not part of the API.
#[doc(hidden)]
#[must_use]
pub fn debug_error_kinds(source: &str) -> Vec<Vec<String>> {
    let (_, parse) = parser::parse(source);
    parse
        .errors
        .iter()
        .map(|e| {
            e.within
                .iter()
                .map(|&k| syntax::snake_case(syntax::SyntaxKind::from_raw(k)))
                .collect()
        })
        .collect()
}

/// The `snake_case` names of the tree's named productions: the nodes of `cql.ungram`
/// a parse builds (an enum of the ungram, such as `filter` or `expr`, is no node).
/// Not part of the API.
#[doc(hidden)]
#[must_use]
pub fn debug_productions() -> Vec<String> {
    syntax::PRODUCTIONS
        .iter()
        .map(|&k| syntax::snake_case(k))
        .collect()
}

/// Analyze a CQL query on its own (a raw `.cql` file or a hunt search).
pub fn analyze(source: &str) -> AnalyzeResult {
    analyze_with(source, &Context::default())
}

/// Analyze a CQL query where `ctx` says it runs.
pub fn analyze_with(source: &str, ctx: &Context) -> AnalyzeResult {
    opentide_core::with_line_index(source, || analyze_lines(source, *ctx))
}

#[expect(
    clippy::expect_used,
    reason = "loads the HighlightSpec compiled in (highlights/spec.toml): a bad spec fails the tests, never a user's document"
)]
fn analyze_lines(source: &str, ctx: Context) -> AnalyzeResult {
    let spec = HighlightSpec::load().expect("highlight spec");
    let (root, parse) = parser::parse(source);
    let mut diagnostics = Vec::new();
    if let Some(err) = parse.errors.first() {
        let (message, span) = parse_error(&root, err, source);
        diagnostics.push(Diagnostic::error(
            codes::CQL_PARSE_ERROR,
            message,
            span_to_range(source, span),
        ));
    }
    diagnostics.extend(check::diagnostics(&root, &parse.errors, source, ctx));
    AnalyzeResult {
        diagnostics,
        tokens: highlight::tokens(&spec, &root, source),
    }
}

/// The first syntax error in words, and where it is: what is missing, or the token
/// that does not fit and what would.
fn parse_error(root: &SyntaxNode, err: &SyntaxError, source: &str) -> (String, ByteSpan) {
    let at = usize::from(err.anchor(source.len()));
    // The token after the gap: the one that does not fit (inside an error node when the
    // parser skipped it).
    let next = root
        .token_at_offset(err.gap.end())
        .right_biased()
        .filter(|t| t.text_range().start() == err.gap.end() && !t.text_range().is_empty());
    // Characters no token takes are one token each (`a >= error` after an operator that wants
    // a number): the range covers the run of them, so the message quotes the whole word.
    let span = next.as_ref().map_or(ByteSpan::new(at, at), |t| {
        let mut end = t.text_range().end();
        if t.kind() == K::ERROR_TOKEN {
            let mut cur = t.next_token();
            while let Some(n) =
                cur.filter(|n| n.kind() == K::ERROR_TOKEN && n.text_range().start() == end)
            {
                end = n.text_range().end();
                cur = n.next_token();
            }
        }
        bounds(TextRange::new(t.text_range().start(), end))
    });
    // Text pasted from a web page often carries U+00A0, which CQL does not
    // read as a space: blame it when it is where the parser stopped.
    let before = source[..at].chars().next_back();
    let here = source.get(span.start..span.end).unwrap_or("");
    if before == Some('\u{a0}') || here.contains('\u{a0}') {
        return (
            "CQL syntax error: a non-breaking space (U+00A0) is not whitespace in CQL; replace it with a space".to_string(),
            span,
        );
    }
    // A `"` with no closing quote lexes as a stray character: the string is never closed.
    if here == "\"" {
        return (
            "CQL syntax error: the string is never closed".to_string(),
            span,
        );
    }
    let message = err.message.as_str();
    if let ErrorKind::TooDeep { .. } = err.kind {
        return (format!("CQL syntax error: {message}"), span);
    }
    if message.starts_with("missing ") || message.ends_with("is never closed") {
        return (
            format!("CQL syntax error: {message}"),
            ByteSpan::new(at, at),
        );
    }
    let what = if message == parser::UNEXPECTED {
        String::new()
    } else {
        format!(": {message}")
    };
    match here.split_whitespace().next() {
        Some(word) => (format!("CQL syntax error near `{word}`{what}"), span),
        None if what.is_empty() => ("CQL syntax error".to_string(), span),
        None => (
            format!("CQL syntax error at the end of the query{what}"),
            span,
        ),
    }
}

fn bounds(r: TextRange) -> ByteSpan {
    ByteSpan::new(usize::from(r.start()), usize::from(r.end()))
}

/// The text of `node`.
pub(crate) fn text<'a>(node: &SyntaxNode, source: &'a str) -> &'a str {
    source
        .get(std::ops::Range::<usize>::from(node.text_range()))
        .unwrap_or("")
}

/// The LSP range of `node`.
pub(crate) fn range(source: &str, node: &SyntaxNode) -> Range {
    span_to_range(source, bounds(node.text_range()))
}

/// The `n`th child node of `node` (ERROR nodes included).
pub(crate) fn nth(node: &SyntaxNode, n: usize) -> Option<SyntaxNode> {
    node.children().nth(n)
}

/// The first child node of `node` of `kind`.
pub(crate) fn child(node: &SyntaxNode, kind: K) -> Option<SyntaxNode> {
    node.children().find(|c| c.kind() == kind)
}

#[cfg(test)]
mod tests;
