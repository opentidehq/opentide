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
    Diagnostic, HighlightResult, HighlightToken, LanguageId, LineStarts, QueryPosition,
    QueryRequest, QueryRequestError, Range, Severity, codes, validate_position,
};

/// The analysis engine's version: the lockstep version every `opentide-*` crate
/// shares, which a host reports as the engine behind its diagnostics.
pub const VERSION: &str = opentide_analysis::VERSION;

/// Checks one query, read as `request.language`, on its own: the diagnostics
/// the queries check would report for it, in the engine's coordinates. The
/// `request`'s `platform` selects a schema or dialect and its `stack` an
/// Elastic stack for ES|QL (see [`QueryRequest`]). The query is checked as a
/// file of its language is: an Exabeam, CQL or Datadog query is a search.
/// [`analyze_query_at`] checks it where it will sit, a rule block's query
/// included.
///
/// ```
/// use opentide::analysis::{LanguageId, QueryRequest};
///
/// let request = QueryRequest::new(LanguageId::Esql, "FROM logs-* | WEHRE x == 1");
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
    analyze_query_at(request, QueryPosition::Search)
}

/// [`analyze_query`] at `position`, where the query will sit. At
/// [`QueryPosition::Search`] it is checked as a file of its language is. At
/// [`QueryPosition::Rule`] it is checked as the platform's rule block checks
/// its query, as [`Workspace::validate`](crate::Workspace::validate) and
/// [`Workspace::lint`](crate::Workspace::lint) check a rule's: an Exabeam
/// sequence filter refuses Search's advanced operators, and a CrowdStrike
/// query is a Next-Gen SIEM correlation rule.
///
/// ```
/// use opentide::analysis::{LanguageId, QueryPosition, QueryRequest};
///
/// // The query of a CrowdStrike rule block: a correlation rule.
/// let rule = QueryRequest::new(
///     LanguageId::Cql,
///     "correlate(A: { #event_simpleName=UserLogon }, B: { #event_simpleName=ProcessRollup2 \
///      | aid <=> A.aid }, within=10m) | groupBy(aid)",
/// )
/// .with_platform(Some("crowdstrike"));
/// let diagnostics = opentide::analysis::analyze_query_at(&rule, QueryPosition::Rule);
/// assert!(diagnostics.iter().any(|d| d.code == "cql_correlate_aggregate"));
/// // As a search, a `.cql` file, it is plain LogScale.
/// let diagnostics = opentide::analysis::analyze_query_at(&rule, QueryPosition::Search);
/// assert!(!diagnostics.iter().any(|d| d.code == "cql_correlate_aggregate"));
/// ```
///
/// A [`QueryPosition::Rule`] without a platform is not checked: the answer
/// is one error, `query_position_needs_platform` ([`validate_position`]
/// says so before the call). It takes no workspace and no lock, as
/// [`analyze_query`].
#[must_use]
pub fn analyze_query_at(request: &QueryRequest, position: QueryPosition) -> Vec<Diagnostic> {
    let _standalone = opentide_analysis::standalone_datasets();
    opentide_analysis::analyze_query_at(request, position)
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
            let codes: Vec<String> = analyze_query(&QueryRequest::new(
                LanguageId::Kql,
                "DeviceProcessEvents | take 1",
            ))
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

#[cfg(test)]
mod position_tests {
    use super::*;

    /// A rule block is a platform's: [`QueryPosition::Rule`] without one is
    /// one error and no check, never a search (#1993).
    #[test]
    fn a_rule_without_a_platform_is_one_error() {
        let rule = QueryRequest::new(LanguageId::Exabeam, "SELECT user WHERE x:\"y\"");
        assert!(validate_position(&rule, QueryPosition::Rule).is_err());
        let found = analyze_query_at(&rule, QueryPosition::Rule);
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].code, codes::QUERY_POSITION_NEEDS_PLATFORM);
        assert_eq!(found[0].severity, Severity::Error);
        let rule = rule.with_platform(Some("exabeam"));
        let found = analyze_query_at(&rule, QueryPosition::Rule);
        assert!(
            found.iter().any(|d| d.code == "exabeam_advanced_in_rule"),
            "{found:?}"
        );
        assert!(analyze_query(&rule).is_empty());
    }
}
