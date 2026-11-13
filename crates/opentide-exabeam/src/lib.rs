//! I/O-free engine for the Exabeam Query Language: the search language of
//! Exabeam's New-Scale SIEM (`configurations.exabeam` correlation-rule
//! sequences, `system: exabeam` hunts, `.exabeam` files). Exabeam's guides
//! call it "EQL"; opentide never does, because `eql` is Elastic's.
//!
//! The contract is specifications `specs/languages/exabeam-1.0.md`. Exabeam
//! publishes no grammar and no parser, so the verdicts come from [`check`](mod@check), a
//! port of the specification's reference checker
//! (`scripts/exabeam_language.py`), and the field catalogue from Exabeam's
//! Common Information Model ([`catalog`]). The tree-sitter grammar
//! (`grammars/tree-sitter-opentide-exabeam`) drives highlighting and editor
//! structure. See `docs/engine/EXABEAM.md`.
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

pub use assist::{completions, hover};
pub use check::{Profile, check};

pub(crate) use opentide_core::codes;
use opentide_core::{ByteSpan, Diagnostic, LanguageId, LineIndex};
use opentide_highlight::{HighlightSpec, HighlightToken, tokens_from_spans};

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
pub const WARNINGS: [&str; 9] = [
    codes::EXABEAM_MIXED_BOOLEAN,
    codes::EXABEAM_IMPLICIT_AND,
    codes::EXABEAM_SINGLE_GROUP,
    codes::EXABEAM_PIPE_MISUSE,
    codes::EXABEAM_WILDCARD_IN_PHRASE,
    codes::EXABEAM_UNQUOTED_VALUE,
    codes::EXABEAM_LEGACY_REGEX,
    codes::EXABEAM_UNKNOWN_FIELD,
    codes::EXABEAM_STRING_FIELD_NUMBER,
];

pub fn is_warning(code: &str) -> bool {
    WARNINGS.contains(&code)
}

/// Analyze a query on its own (a `.exabeam` file): the `search` profile.
pub fn analyze(source: &str) -> AnalyzeResult {
    analyze_with(source, &Context::default())
}

/// Analyze a query where `ctx` says it runs.
#[expect(
    clippy::expect_used,
    reason = "loads the HighlightSpec compiled in (highlights/spec.toml): a bad spec fails the tests, never a user's document"
)]
pub fn analyze_with(source: &str, ctx: &Context) -> AnalyzeResult {
    let spec = HighlightSpec::load().expect("highlight spec");
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
        tokens: highlight(&spec, source),
    }
}

/// Highlight tokens from the tree-sitter grammar and the highlight query.
pub fn highlight(spec: &HighlightSpec, source: &str) -> Vec<HighlightToken> {
    let Ok(spans) = opentide_syntax::query_captures(
        LanguageId::Exabeam,
        source,
        opentide_highlight::EXABEAM_HIGHLIGHTS_SCM,
    ) else {
        return Vec::new();
    };
    let refs: Vec<(ByteSpan, &str)> = spans.iter().map(|(s, c)| (*s, c.as_str())).collect();
    tokens_from_spans(spec, source, &refs).unwrap_or_default()
}

#[cfg(test)]
mod tests;
