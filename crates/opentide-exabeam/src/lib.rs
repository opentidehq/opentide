//! I/O-free engine for the Exabeam Query Language: the search language of
//! Exabeam's New-Scale SIEM (`configurations.exabeam` correlation-rule
//! sequences, `system: exabeam` hunts, `.exabeam` files). Exabeam's guides
//! call it "EQL"; opentide never does, because `eql` is Elastic's.
//!
//! The contract is specifications `specs/languages/exabeam-1.0.md`. Exabeam
//! publishes no grammar and no parser, so the verdicts come from [`check`](mod@check), a
//! port of the specification's reference checker
//! (`scripts/exabeam_language.py`), and the field catalogue from Exabeam's
//! Common Information Model ([`catalog`]). A parser on `opentide-parse`
//! (`cst`), which accepts what `grammars/tree-sitter-opentide-exabeam` accepts,
//! drives highlighting. See `docs/engine/EXABEAM.md`.
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
// Slicing a `str` by byte index panics off a char boundary, and this crate
// reads user queries: every slice is checked or says why it is safe (#1946;
// the lint moves to `[workspace.lints]` once every crate is clean).
#![warn(clippy::string_slice)]

pub mod assist;
pub mod catalog;
mod catalog_model;
pub mod check;
mod cst;
mod syntax;

pub use assist::{completions, hover};
pub use check::{Profile, check};
#[doc(hidden)]
pub use cst::{debug_parse, highlight_captures, tree_has_error};

pub(crate) use opentide_core::codes;
use opentide_core::{ByteSpan, Diagnostic, LineIndex};
use opentide_highlight::{HighlightSpec, HighlightToken, tokens_from_spans, tokens_in};

/// Where the query runs.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Context {
    pub profile: Profile,
}

impl Context {
    /// A correlation-rule sequence query (`configurations.exabeam.sequences[].query`).
    pub const RULE: Context = Context {
        profile: Profile::Rule,
    };
    /// A hunt search or a `.exabeam` file.
    pub const SEARCH: Context = Context {
        profile: Profile::Search,
    };
}

#[derive(Debug, Clone, Default)]
pub struct AnalyzeResult {
    pub diagnostics: Vec<Diagnostic>,
    pub tokens: Vec<HighlightToken>,
}

/// The codes exabeam-1.0 lists as warnings; every other `exabeam_*` code of
/// the language is an error.
pub const WARNINGS: [&str; 10] = [
    codes::EXABEAM_MIXED_BOOLEAN,
    codes::EXABEAM_IMPLICIT_AND,
    codes::EXABEAM_SINGLE_GROUP,
    codes::EXABEAM_PIPE_MISUSE,
    codes::EXABEAM_WILDCARD_IN_PHRASE,
    codes::EXABEAM_UNQUOTED_VALUE,
    codes::EXABEAM_LEGACY_REGEX,
    codes::EXABEAM_UNKNOWN_FIELD,
    codes::EXABEAM_STRING_FIELD_NUMBER,
    codes::EXABEAM_UNKNOWN_VALUE,
];

pub fn is_warning(code: &str) -> bool {
    WARNINGS.contains(&code)
}

/// Analyze a query on its own (a `.exabeam` file): the `search` profile.
pub fn analyze(source: &str) -> AnalyzeResult {
    analyze_with(source, &Context::default())
}

/// The Exabeam Query Language [`QueryEngine`](opentide_highlight::QueryEngine) (#1953):
/// [`analyze`] behind the shared interface.
#[derive(Debug, Clone, Copy, Default)]
pub struct Engine;

impl opentide_highlight::QueryEngine for Engine {
    fn language(&self) -> opentide_core::LanguageId {
        opentide_core::LanguageId::Exabeam
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

    fn highlight(&self, source: &str) -> Vec<HighlightToken> {
        let Ok(spec) = HighlightSpec::shared() else {
            return Vec::new();
        };
        highlight(spec, source)
    }

    fn hover(
        &self,
        source: &str,
        offset: usize,
        _setting: &opentide_highlight::Setting<'_>,
    ) -> Option<String> {
        hover(source, offset)
    }

    fn completions(
        &self,
        source: &str,
        offset: usize,
        _setting: &opentide_highlight::Setting<'_>,
    ) -> Vec<opentide_core::CompletionItem> {
        completions(source, offset)
    }
}

/// Analyze a query where `ctx` says it runs.
#[expect(
    clippy::expect_used,
    reason = "loads the HighlightSpec compiled in (highlights/spec.toml): a bad spec fails the tests, never a user's document"
)]
pub fn analyze_with(source: &str, ctx: &Context) -> AnalyzeResult {
    let spec = HighlightSpec::shared().expect("highlight spec");
    let checked = check(source, ctx.profile);
    let lines = LineIndex::new(source);
    let diagnostics = checked
        .findings
        .into_iter()
        .map(|f| {
            let start = f.start.min(source.len());
            let end = f.end.min(source.len()).max(start);
            let range = lines.range(ByteSpan::new(start, end));
            if is_warning(f.code) {
                Diagnostic::warning(f.code, f.message, range)
            } else {
                Diagnostic::error(f.code, f.message, range)
            }
        })
        .collect();
    AnalyzeResult {
        diagnostics,
        tokens: tokens_in(spec, &lines, &highlight_captures(source)).unwrap_or_default(),
    }
}

/// Highlight tokens from the parser's tree.
pub fn highlight(spec: &HighlightSpec, source: &str) -> Vec<HighlightToken> {
    tokens_from_spans(spec, source, &highlight_captures(source)).unwrap_or_default()
}

/// Whether `source` parses without an error: the parse alone, with no
/// analysis, for the throughput benchmark (`cargo bench --bench throughput`, ADR
/// 0014). Not part of the API.
#[doc(hidden)]
#[must_use]
pub fn parses(source: &str) -> bool {
    cst::parse(source).1.errors.is_empty()
}

/// Whether the grammar reports an error in `source`, and the `Debug` names of
/// the kinds of its tree, nodes and tokens in preorder: what the corpus gate of
/// `opentide-analysis` reads. Not part of the API.
#[doc(hidden)]
#[must_use]
pub fn debug_kinds(source: &str) -> (bool, Vec<String>) {
    opentide_parse::debug_kinds::<syntax::Exabeam>(&cst::parse(source).1)
}

/// For each syntax error of `source`, the `Debug` names of the nodes it was recorded in: what
/// the corpus gate of `opentide-analysis` reads to check that an invalid fixture fails in
/// the production it names. Not part of the API.
#[doc(hidden)]
#[must_use]
pub fn debug_error_kinds(source: &str) -> Vec<Vec<String>> {
    opentide_parse::debug_error_kinds::<syntax::Exabeam>(&cst::parse(source).1)
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
mod tests;
