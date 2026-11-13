//! The analysis engine (`analysis` feature): check one query on its own and
//! highlight a text in any of the query languages, without opening a
//! workspace.
//!
//! [`Workspace::validate`](crate::Workspace::validate) runs these checks across
//! a workspace's objects; this module is the engine underneath, for a host that
//! has a single query or text in hand and no workspace: the Python package's
//! `opentide.analysis` and the browser build both call it.
//!
//! Positions in a [`Diagnostic`] and a [`HighlightToken`] are the engine's: LSP
//! coordinates, 0-based, columns in UTF-16 code units. A [`LineStarts`] over
//! the same text converts them to whatever a host reports.

pub use opentide_analysis::{
    Diagnostic, HighlightResult, HighlightToken, LanguageId, LineStarts, QueryRequest, Range,
    Severity, codes,
};

/// The analysis engine's version: the lockstep version every `opentide-*` crate
/// shares, which a host reports as the engine behind its diagnostics.
pub const VERSION: &str = opentide_analysis::VERSION;

/// Checks one query, read as `request.language`, on its own: the diagnostics
/// the queries check would report for it, in the engine's coordinates. The
/// `request`'s `platform` selects a schema or dialect and its `stack` an
/// Elastic stack for ES|QL (see [`QueryRequest`]).
///
/// ```
/// use opentide::analysis::{LanguageId, QueryRequest};
///
/// let request = QueryRequest {
///     language: LanguageId::Esql,
///     platform: None,
///     stack: None,
///     text: "FROM logs-* | WEHRE x == 1".to_owned(),
/// };
/// let diagnostics = opentide::analysis::analyze_query(&request);
/// assert!(diagnostics.iter().any(|d| d.code == "esql_unknown_command"));
/// ```
#[must_use]
pub fn analyze_query(request: &QueryRequest) -> Vec<Diagnostic> {
    opentide_analysis::analyze_query(request)
}

/// Highlights `text` read as `language`, as an editor colours it: the tokens
/// and the capture legend (see [`legend`]). A Tide object's injected queries
/// are highlighted in their own language.
#[must_use]
pub fn highlight(language: LanguageId, text: &str) -> HighlightResult {
    opentide_analysis::highlight(language, text)
}

/// The highlight legend: the HighlightSpec capture names, in the order a
/// semantic token's type index refers to.
#[must_use]
pub fn legend() -> Vec<String> {
    opentide_analysis::legend()
}
