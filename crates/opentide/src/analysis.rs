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
/// Elastic stack for ES|QL (see [`QueryRequest`]). The query is checked as
/// a file of its language is, whatever the platform: an Exabeam, CQL or
/// Datadog query is a search, not a rule's query: a rule block's query is
/// checked as a rule by [`Workspace::validate`](crate::Workspace::validate)
/// and [`Workspace::lint`](crate::Workspace::lint), by its place in the
/// object.
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
///
/// The query is checked without a workspace: no workspace's declared
/// datasets apply, not even ones a host installed for the process (a
/// [`Workspace::validate`](crate::Workspace::validate) or
/// [`Workspace::lint`](crate::Workspace::lint) run uses its own and installs
/// nothing). It takes no lock.
#[must_use]
pub fn analyze_query(request: &QueryRequest) -> Vec<Diagnostic> {
    let _standalone = opentide_analysis::standalone_datasets();
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

#[cfg(all(test, feature = "queries"))]
mod tests {
    use super::*;

    /// A query checked on its own on a thread where a host installed a
    /// workspace's datasets, while another thread holds the engines' lock:
    /// it neither waits for the lock nor sees those datasets.
    #[test]
    fn a_query_on_its_own_never_waits_for_or_sees_a_workspace_run() {
        let _engine = opentide_analysis::queries::ENGINE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (done, finished) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _restore = opentide_analysis::save_visibility();
            opentide_analysis::install_visibility(Some(
                "[[logsources]]\nname = \"SecurityEvent\"\ndescription = \"x\"\nsystem = \"sentinel\"\n",
            ))
            .unwrap();
            let codes: Vec<String> = analyze_query(&QueryRequest {
                language: LanguageId::Kql,
                platform: None,
                stack: None,
                text: "DeviceProcessEvents | take 1".to_owned(),
            })
            .into_iter()
            .map(|diagnostic| diagnostic.code)
            .collect();
            let _ = done.send(codes);
        });
        let codes = finished
            .recv_timeout(std::time::Duration::from_secs(30))
            .expect("analyze_query waited for the engines' lock");
        assert!(
            !codes.iter().any(|code| code == "kql_table_not_declared"),
            "{codes:?}"
        );
    }
}
