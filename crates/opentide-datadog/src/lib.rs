//! I/O-free engine for the Datadog log search syntax: the queries of Datadog Cloud SIEM
//! detection rules (the API's `event_query`), and `.datadog` files.
//!
//! The contract is `docs/internal/rfc-datadog-cloud-siem.md`, §6. Datadog publishes no grammar,
//! so the grammar is written from its Log Search Syntax page and held to two references: the
//! queries Datadog publishes (`crates/testdata/conformance/external/datadog/`) and the grammar
//! of VRL, the library behind Observability Pipelines (`scripts/engine/oracles/datadog/`).
//!
//! The parser is pure Rust: a logos lexer (`lexer`) and a hand-written grammar (`parser`) over
//! the `opentide-parse` toolkit, into a lossless rowan tree whose shape `datadog.ungram` states.
//! AND (written or implied) binds tighter than OR, as VRL reads it. [`analyze`] reports the first
//! syntax error, else the checks of RFC §6.7, and the highlight of §6.8, from one walk of the
//! tree. See `docs/engine/DATADOG.md`.
//!
//! Internal to opentide, with no stability promise: depend on the
//! [`opentide`](https://docs.rs/opentide) crate, its Rust SDK, instead.

pub mod assist;
pub mod catalog;
mod catalog_model;
mod check;
mod lexer;
mod parser;
mod syntax;

/// The typed AST of `datadog.ungram`, written by `cargo xtask codegen`.
#[path = "generated/ast.rs"]
pub mod ast;

pub use assist::{completions, hover};
pub use check::{Finding, Profile};
pub use syntax::{Lang, SyntaxKind, SyntaxNode, SyntaxToken};

use opentide_core::{ByteSpan, Diagnostic, LineIndex, Severity, codes};
use opentide_highlight::{HighlightSpec, HighlightToken, tokens_in};
use opentide_parse::{ErrorKind, SyntaxError};

/// Where the query runs.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Context {
    /// The profile its checks run under.
    pub profile: Profile,
}

impl Context {
    /// A detection rule's query (`queries[].query` of a `configurations.datadog` block).
    pub const RULE: Context = Context {
        profile: Profile::Rule,
    };
    /// A `.datadog` file, a hunt search, `opentide query`.
    pub const SEARCH: Context = Context {
        profile: Profile::Search,
    };
}

/// The diagnostics and the highlight of a query.
#[derive(Debug, Clone, Default)]
pub struct AnalyzeResult {
    /// The first syntax error, or the checks' findings.
    pub diagnostics: Vec<Diagnostic>,
    /// The highlight tokens, in document order.
    pub tokens: Vec<HighlightToken>,
}

/// Analyzes a query on its own (a `.datadog` file): the `search` profile.
#[must_use]
pub fn analyze(source: &str) -> AnalyzeResult {
    analyze_with(source, &Context::default())
}

/// The Datadog search [`QueryEngine`](opentide_highlight::QueryEngine) (#1953):
/// [`analyze`] behind the shared interface.
#[derive(Debug, Clone, Copy, Default)]
pub struct Engine;

impl opentide_highlight::QueryEngine for Engine {
    fn language(&self) -> opentide_core::LanguageId {
        opentide_core::LanguageId::Datadog
    }

    fn analyze_for(
        &self,
        source: &str,
        setting: &opentide_highlight::Setting<'_>,
    ) -> opentide_highlight::AnalyzeResult {
        let ctx = if setting.profile == opentide_highlight::Profile::Rule {
            Context::RULE
        } else {
            Context::SEARCH
        };
        let r = analyze_with(source, &ctx);
        opentide_highlight::AnalyzeResult {
            diagnostics: r.diagnostics,
            tokens: r.tokens,
        }
    }
}

/// Analyzes a query where `ctx` says it runs.
///
/// A query that does not parse gets its first syntax error and nothing else: advice on a tree
/// that recovery rebuilt is noise, and Datadog reads nothing past the error either.
#[must_use]
#[expect(
    clippy::expect_used,
    reason = "loads the HighlightSpec compiled in (highlights/spec.toml): a bad spec fails the tests, never a user's document"
)]
pub fn analyze_with(source: &str, ctx: &Context) -> AnalyzeResult {
    let spec = HighlightSpec::shared().expect("highlight spec");
    let (root, parse) = parser::parse(source);
    let lines = LineIndex::new(source);
    let mut spans: Vec<(ByteSpan, &'static str)> = Vec::new();
    // One walk for the checks and the highlight (ADR 0014 §5a).
    let findings = check::walk(&root, source, ctx.profile, |span, capture| {
        spans.push((span, capture.name()));
    });
    let diagnostics = match parse.errors.first() {
        Some(error) => {
            let (code, message, span) = parse_error(&root, error, source);
            vec![Diagnostic::error(code, message, lines.range(span))]
        }
        None => findings
            .into_iter()
            .map(|f| {
                let start = f.span.start.min(source.len());
                let end = f.span.end.min(source.len()).max(start);
                Diagnostic::error(f.code, f.message, lines.range(ByteSpan::new(start, end)))
                    .with_severity(f.severity)
            })
            .collect(),
    };
    AnalyzeResult {
        diagnostics,
        tokens: tokens_in(spec, &lines, &spans).unwrap_or_default(),
    }
}

/// The findings of the checks of `source` under `profile`, without the highlight or the line
/// table: what the published-corpus tests count. Empty when the query does not parse.
#[must_use]
pub fn findings(source: &str, profile: Profile) -> Vec<Finding> {
    let (root, parse) = parser::parse(source);
    if let Some(error) = parse.errors.first() {
        let (code, message, span) = parse_error(&root, error, source);
        return vec![Finding {
            code,
            severity: Severity::Error,
            message,
            span,
        }];
    }
    check::walk(&root, source, profile, |_, _| {})
}

/// The highlight tokens of `source`.
#[must_use]
pub fn highlight(spec: &HighlightSpec, source: &str) -> Vec<HighlightToken> {
    let (root, _) = parser::parse(source);
    let mut spans: Vec<(ByteSpan, &'static str)> = Vec::new();
    check::walk(&root, source, Profile::Search, |span, capture| {
        spans.push((span, capture.name()));
    });
    tokens_in(spec, &LineIndex::new(source), &spans).unwrap_or_default()
}

/// The code, message and span of the first syntax error. A fault inside a range is
/// `datadog_range` (RFC §6.7: a malformed range); every other one is `datadog_parse_error`.
fn parse_error(
    root: &SyntaxNode,
    error: &SyntaxError,
    source: &str,
) -> (&'static str, String, ByteSpan) {
    let in_range = !matches!(error.kind, ErrorKind::TooDeep { .. })
        && error
            .within
            .last()
            .is_some_and(|&k| SyntaxKind::from_raw(k) == SyntaxKind::RANGE);
    let code = if in_range {
        codes::DATADOG_RANGE
    } else {
        codes::DATADOG_PARSE_ERROR
    };
    let at = usize::from(error.anchor(source.len()));
    // The token where the parser stopped, if it is not the end.
    let next = root
        .token_at_offset(error.gap.end())
        .right_biased()
        .filter(|t| t.text_range().start() == error.gap.end() && !t.text_range().is_empty());
    let span = next
        .as_ref()
        .map_or(ByteSpan::new(at, at), |t| check::span(t.text_range()));
    let message = error.message.as_str();
    let here = source.get(span.start..span.end).unwrap_or("");
    let text = if message == parser::UNEXPECTED {
        if here.is_empty() {
            "Datadog search syntax error at the end of the query".to_owned()
        } else {
            format!("Datadog search syntax error near `{here}`")
        }
    } else if matches!(error.kind, ErrorKind::Syntax) && !here.is_empty() {
        format!("Datadog search syntax error near `{here}`: {message}")
    } else {
        format!("Datadog search syntax error: {message}")
    };
    (code, text, span)
}

/// Whether `source` parses without an error: the parse alone, with no analysis, for the
/// throughput benchmark (`cargo bench --bench throughput`, ADR 0014). Not part of the API.
#[doc(hidden)]
#[must_use]
pub fn parses(source: &str) -> bool {
    parser::parse(source).1.errors.is_empty()
}

/// Whether the grammar reports an error in `source`, and the `snake_case` names of the kinds of
/// its tree, nodes and tokens in preorder: what the corpus gate of `opentide-analysis` reads.
/// Not part of the API.
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

/// For each syntax error of `source`, the `snake_case` names of the nodes it was recorded in,
/// root first: what the corpus gate reads to check that an invalid fixture fails in the
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
                .map(|&k| syntax::snake_case(SyntaxKind::from_raw(k)))
                .collect()
        })
        .collect()
}

/// The `snake_case` names of the node kinds the grammar declares, the error node left out: the
/// productions the corpus gate asks a fixture of. Not part of the API.
#[doc(hidden)]
#[must_use]
pub fn debug_node_kinds() -> Vec<String> {
    syntax::node_kinds()
}

/// The tree of `source` and how many syntax errors it has: what the `.ungram` conformance test
/// reads. Not part of the API.
#[doc(hidden)]
#[must_use]
pub fn debug_syntax(source: &str) -> (SyntaxNode, usize) {
    let (root, parse) = parser::parse(source);
    (root, parse.errors.len())
}

/// The toolkit's kinds for the language: what `opentide_parse::conformance::check` takes. Not
/// part of the API.
#[doc(hidden)]
#[must_use]
pub fn debug_grammar() -> opentide_parse::Grammar {
    parser::GRAMMAR
}

/// The text of the tree of `source` and how many syntax errors it has: a lossless tree's text
/// is the source. Not part of the API.
#[doc(hidden)]
#[must_use]
pub fn debug_roundtrip(source: &str) -> (String, usize) {
    let (root, parse) = parser::parse(source);
    (root.to_string(), parse.errors.len())
}

/// The tree of `source` and its errors, as text, for snapshots. Not part of the API.
#[doc(hidden)]
#[must_use]
pub fn debug_tree(source: &str) -> String {
    let (root, parse) = parser::parse(source);
    let mut out = opentide_parse::debug_tree(&root, |k: SyntaxKind| format!("{k:?}"));
    out.push_str(&opentide_parse::debug_errors(&parse.errors, |k| {
        format!("{:?}", SyntaxKind::from_raw(k))
    }));
    out
}

#[cfg(test)]
mod tests;
