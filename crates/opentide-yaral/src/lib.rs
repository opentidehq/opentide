//! I/O-free YARA-L 2.0 engine (yara-l-1.0, RFC 0019 section 7).
//!
//! YARA-L is the detection and search language of Google Security
//! Operations. Google publishes no grammar and no offline compiler, so the
//! engine is an approximation of the tenant's compiler (`verifyRuleText`): it
//! reports what Google's pages say the compiler refuses, and never claims a
//! compile. A text goes through:
//!
//! 1. the pure-Rust parser (`lexer`, `parser`: a lossless rowan tree, ADR
//!    0012), whose first error is `yaral_parse_error`;
//! 2. `analysis::checker::Checker`, on the typed tree: sections and their
//!    order for the profile, scope (event variables, placeholders, outcomes),
//!    `match` windows, outcome aggregation, condition shape, options, the UDM
//!    and function catalogues, literals and limits.
//!
//! Two profiles: a rule (`YaraLRule`, or a Tide block's sections assembled
//! into one) and a search (`YaraLSearch`, a hunt). Reference lists, data
//! tables, composite producer names and curated rules live in the tenant and
//! are never reported unknown. `docs/engine/YARAL.md` maps each code to Google's page
//! and the test that proves it.
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
mod analysis;
pub mod catalog;
mod catalog_model;
pub mod editor;
// The lexer: public but hidden, as the kinds, for the crate's corpus test (`tests/`). Not an
// API.
#[doc(hidden)]
pub mod lexer;
mod parser;
#[doc(hidden)]
pub mod syntax;
// The typed AST names the kinds from the crate root.
#[doc(hidden)]
pub use syntax::{Lang, SyntaxKind, SyntaxNode, SyntaxToken};
// Generated from yaral.ungram by `cargo xtask codegen`: an accessor for every
// child of every node, named by the grammar. Public but hidden, as SPL's and
// KQL's: `tests/ast_accessors.rs` calls every accessor on the corpus's
// trees, which keeps them right and measured.
#[doc(hidden)]
#[path = "generated/ast.rs"]
pub mod ast;

use opentide_core::{Diagnostic, Severity};
use opentide_highlight::HighlightToken;

/// Which sections, functions and limits a text may use (yara-l-1.0
/// "Profiles").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    /// A detection rule: a `.yaral` file, or a Google SecOps block's sections.
    Rule,
    /// A search (a hunt): `opentide query`, `response.procedure.searches[]`.
    Search,
}

impl Profile {
    /// The function catalogue's availability tag.
    pub fn availability(self) -> &'static str {
        match self {
            Profile::Rule => "rules",
            Profile::Search => "search",
        }
    }
}

/// Where the text runs.
#[derive(Debug, Clone, Copy, Default)]
pub struct Context {
    /// `None`: a text with a `rule` header is a rule, any other a search.
    pub profile: Option<Profile>,
    /// A `YaraLRule` file needs its `meta`; deploy writes it for a block.
    pub meta_required: bool,
}

impl Context {
    /// A `.yaral` file: a rule (with its `meta`) or a search, by its text.
    pub const FILE: Context = Context {
        profile: None,
        meta_required: true,
    };
    /// A Google SecOps block's sections, assembled into the rule deploy
    /// sends (google-secops-1.0 "Assembled rule").
    pub const SECTIONS: Context = Context {
        profile: Some(Profile::Rule),
        meta_required: false,
    };
    /// A hunt (`response.procedure.searches[].query` with `system:
    /// google_secops`).
    pub const SEARCH: Context = Context {
        profile: Some(Profile::Search),
        meta_required: false,
    };
}

/// A finding in byte offsets, before ranges.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Finding {
    pub code: &'static str,
    pub severity: Severity,
    pub message: String,
    pub start: usize,
    pub end: usize,
}

impl Finding {
    pub fn new(
        code: &'static str,
        severity: Severity,
        message: String,
        start: usize,
        end: usize,
    ) -> Self {
        Self {
            code,
            severity,
            message,
            start,
            end,
        }
    }
}

pub struct AnalyzeResult {
    pub diagnostics: Vec<Diagnostic>,
    pub tokens: Vec<HighlightToken>,
}

/// The profile of `source`: a rule when it holds a `rule` declaration.
pub fn infer_profile(source: &str) -> Profile {
    analysis::infer_profile(source)
}

/// Analyze a YARA-L file (`.yaral`, `.yl2`).
pub fn analyze(source: &str) -> AnalyzeResult {
    analyze_with(source, &Context::FILE)
}

/// The YARA-L 2.0 [`QueryEngine`](opentide_highlight::QueryEngine) (#1953):
/// [`analyze`] behind the shared interface.
#[derive(Debug, Clone, Copy, Default)]
pub struct Engine;

impl opentide_highlight::QueryEngine for Engine {
    fn language(&self) -> opentide_core::LanguageId {
        opentide_core::LanguageId::Yaral
    }

    fn analyze(&self, source: &str) -> opentide_highlight::AnalyzeResult {
        let r = analyze(source);
        opentide_highlight::AnalyzeResult {
            diagnostics: r.diagnostics,
            tokens: r.tokens,
        }
    }
}

/// Analyze YARA-L text where `ctx` says it runs: one parse for the
/// diagnostics and the highlight tokens.
pub fn analyze_with(source: &str, ctx: &Context) -> AnalyzeResult {
    let parsed = parser::parse(source);
    let root = SyntaxNode::new_root(parsed.green.clone());
    let (diagnostics, tokens) = analysis::analysis_of(source, *ctx, &parsed, &root);
    AnalyzeResult {
        diagnostics,
        tokens,
    }
}

/// Every diagnostic of a text, in source order.
pub fn diagnostics(source: &str, ctx: &Context) -> Vec<Diagnostic> {
    analysis::diagnostics(source, *ctx)
}

/// Semantic tokens from the tree.
pub fn highlight(source: &str) -> Vec<HighlightToken> {
    analysis::highlight(&SyntaxNode::new_root(parser::parse(source).green), source)
}

/// The tree of `source` and its errors as indented text, for the snapshot
/// tests of the parser (`tests/trees.rs`). Not part of the API.
#[doc(hidden)]
pub fn debug_parse(source: &str) -> String {
    let parsed = parser::parse(source);
    let tree = SyntaxNode::new_root(parsed.green);
    let mut out = opentide_parse::debug_tree(&tree, |k| format!("{k:?}"));
    let errors =
        opentide_parse::debug_errors(&parsed.errors, |k| SyntaxKind::from_raw(k).describe());
    if !errors.is_empty() {
        out.push_str("errors:\n");
        out.push_str(&errors);
    }
    out
}

/// What the parser tests read of `source` (a library source never touches
/// the corpus files they walk). Not part of the API.
#[doc(hidden)]
pub mod parse_facts {
    use crate::syntax::{SyntaxKind as K, SyntaxNode};

    /// The lexemes as `(start, end, is_trivia)`: whitespace and comments
    /// are trivia.
    #[must_use]
    pub fn lex_spans(source: &str) -> Vec<(usize, usize, bool)> {
        crate::lexer::lex(source)
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

    /// The tree of `source`, for the tests of the typed AST
    /// (`tests/ast_accessors.rs`).
    #[must_use]
    pub fn tree(source: &str) -> SyntaxNode {
        SyntaxNode::new_root(crate::parser::parse(source).green)
    }

    /// Whether the tree prints back as `source`.
    #[must_use]
    pub fn parse_is_lossless(source: &str) -> bool {
        SyntaxNode::new_root(crate::parser::parse(source).green).to_string() == source
    }

    /// How many syntax errors `source` has.
    #[must_use]
    pub fn parse_error_count(source: &str) -> usize {
        crate::parser::parse(source).errors.len()
    }

    /// The places the tree does not conform to `yaral.ungram`, one line each
    /// (`opentide_parse::conformance`); empty when it conforms.
    #[must_use]
    pub fn conformance(source: &str) -> Vec<String> {
        let root = SyntaxNode::new_root(crate::parser::parse(source).green);
        opentide_parse::conformance::check(&root, crate::ast::RULES, crate::parser::GRAMMAR)
            .iter()
            .map(ToString::to_string)
            .collect()
    }
}

/// Whether `source` parses without an error: the parse alone, with no
/// analysis, for the throughput benchmark (`cargo bench --bench throughput`, ADR
/// 0014). Not part of the API.
#[doc(hidden)]
#[must_use]
pub fn parses(source: &str) -> bool {
    parser::parse(source).errors.is_empty()
}

/// Whether the grammar reports an error in `source`, and the `Debug` names of
/// the kinds of its tree, nodes and tokens in preorder: what the corpus gate of
/// `opentide-analysis` reads. Not part of the API.
#[doc(hidden)]
#[must_use]
pub fn debug_kinds(source: &str) -> (bool, Vec<String>) {
    opentide_parse::debug_kinds::<syntax::Lang>(&parser::parse(source))
}

/// For each syntax error of `source`, the `Debug` names of the nodes it was recorded in: what
/// the corpus gate of `opentide-analysis` reads to check that an invalid fixture fails in
/// the production it names. Not part of the API.
#[doc(hidden)]
#[must_use]
pub fn debug_error_kinds(source: &str) -> Vec<Vec<String>> {
    opentide_parse::debug_error_kinds::<syntax::Lang>(&parser::parse(source))
}

/// The `Debug` names of the node kinds the grammar declares, the error node
/// left out: the productions the corpus gate of `opentide-analysis` asks a
/// fixture of. Not part of the API.
#[doc(hidden)]
#[must_use]
pub fn debug_node_kinds() -> Vec<String> {
    syntax::node_kinds()
}

#[cfg(test)]
mod tests {
    use super::*;
    use opentide_core::codes;

    fn codes_of(source: &str) -> Vec<String> {
        analyze(source)
            .diagnostics
            .into_iter()
            .map(|d| d.code)
            .collect()
    }

    const SPRAY: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../testdata/conformance/specifications-google-secops/rule-google-secops-spray-1.0.yaral"
    ));

    #[test]
    fn a_clean_rule_has_no_finding() {
        assert!(
            codes_of(SPRAY).is_empty(),
            "{:?}",
            analyze(SPRAY).diagnostics
        );
    }

    #[test]
    fn a_syntax_error_is_placed() {
        let d = analyze("rule r {\n  meta:\n    a = \"b\"\n  events:\n    $e.metadata.event_type = \n  condition:\n    $e\n}\n").diagnostics;
        assert_eq!(d[0].code, codes::YARAL_PARSE_ERROR, "{d:?}");
    }

    #[test]
    fn highlight_colours_the_rule() {
        let source = "rule r {\n  meta:\n    author = \"a\"\n  events:\n    $e.metadata.event_type = \"USER_LOGIN\"\n  outcome:\n    $risk_score = max(strings.length($e.principal.hostname))\n  condition:\n    #e > 2\n}\n";
        let tokens = analyze(source).tokens;
        let at = |text: &str| {
            let start = source.find(text).unwrap();
            tokens
                .iter()
                .find(|t| t.span.start == start)
                .map(|t| t.capture.clone())
        };
        assert_eq!(at("rule").as_deref(), Some("keyword"));
        assert_eq!(at("r {").as_deref(), Some("type"));
        assert_eq!(at("author").as_deref(), Some("property"));
        assert_eq!(at("$e.").as_deref(), Some("variable"));
        assert_eq!(at("metadata").as_deref(), Some("property"));
        assert_eq!(at("\"USER_LOGIN\"").as_deref(), Some("string"));
        assert_eq!(at("$risk_score").as_deref(), Some("constant"));
        assert_eq!(at("max(").as_deref(), Some("function.builtin"));
        assert_eq!(at("strings.").as_deref(), Some("type"));
        assert_eq!(at("length").as_deref(), Some("function.builtin"));
        assert_eq!(at("#e").as_deref(), Some("variable"));
        assert_eq!(at("2\n").as_deref(), Some("number"));
        assert_eq!(at("events").as_deref(), Some("keyword"));
    }
}
