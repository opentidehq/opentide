//! The query engines behind validate's and lint's queries checks: the
//! engines themselves with the `queries` feature, otherwise a stand-in that
//! reports `engine_unavailable`, as the Python package does when its compiled
//! engine does not load. A queries check never skips.

use std::path::Path;

use opentide_workspace::Workspace;
use opentide_workspace::lint::{LintFinding, LintQueryCheck};
use opentide_workspace::validate::{QueryCheck, QueryFindings, QueryObject};

/// The code of the finding a queries check reports without its engines.
pub const ENGINE_UNAVAILABLE: &str = "engine_unavailable";

/// The message of that finding.
pub const ENGINE_UNAVAILABLE_MESSAGE: &str = "The opentide analysis engine does not load: this \
     build of the opentide crate has no query engines (its `queries` feature is off)";

/// What to do about it.
pub const ENGINE_UNAVAILABLE_ADVICE: &str = "Build the opentide crate with its `queries` (or \
     `cli`) feature, or turn the queries check off (QueriesMode::Off)";

/// Whether this build carries the query engines (the `queries` feature).
pub const AVAILABLE: bool = cfg!(feature = "queries");

/// The queries check of `validate`.
pub(crate) fn validate_check() -> &'static dyn QueryCheck {
    #[cfg(feature = "queries")]
    {
        &opentide_cli::queries::EngineQueries
    }
    #[cfg(not(feature = "queries"))]
    {
        &Unavailable
    }
}

/// Runs `run` with lint's queries check for the workspace at `root`, holding
/// the engines' lock while it runs, as the command line does.
pub(crate) fn with_lint_check<T>(ws: &Workspace, run: impl FnOnce(&dyn LintQueryCheck) -> T) -> T {
    #[cfg(feature = "queries")]
    {
        let _engine = opentide_cli::queries::ENGINE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let check = opentide_cli::queries::EngineLintQueries::install(ws.fs().as_ref(), ws.root());
        run(&check)
    }
    #[cfg(not(feature = "queries"))]
    {
        let _ = ws;
        run(&Unavailable)
    }
}

/// The queries checks of a build without the engines.
#[cfg_attr(
    all(feature = "queries", not(test)),
    expect(dead_code, reason = "the engines replace it; the tests still check it")
)]
pub(crate) struct Unavailable;

impl QueryCheck for Unavailable {
    fn check(&self, _: &Workspace, _: &[QueryObject<'_>], _: bool) -> QueryFindings {
        let error =
            opentide_workspace::Diagnostic::error(ENGINE_UNAVAILABLE, ENGINE_UNAVAILABLE_MESSAGE)
                .suggest(Some(ENGINE_UNAVAILABLE_ADVICE.to_owned()))
                .with("source", "engine");
        QueryFindings {
            errors: vec![error],
            warnings: Vec::new(),
            queries: 0,
        }
    }
}

impl LintQueryCheck for Unavailable {
    fn check(
        &self,
        _: &Path,
        _: &str,
        _: Option<&str>,
        _: &str,
    ) -> Result<Vec<LintFinding>, String> {
        Err(format!(
            "{ENGINE_UNAVAILABLE_MESSAGE}. {ENGINE_UNAVAILABLE_ADVICE}."
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn workspace() -> crate::Workspace {
        crate::Workspace::from_files("/ws", [("objects/rules/.keep", "")]).unwrap()
    }

    #[test]
    fn without_the_engines_validate_reports_engine_unavailable_whatever_the_mode() {
        let ws = workspace();
        for as_warnings in [false, true] {
            let found = QueryCheck::check(&Unavailable, ws.inner(), &[], as_warnings);
            assert!(found.warnings.is_empty());
            assert_eq!(found.queries, 0);
            let [error] = found.errors.as_slice() else {
                panic!("{found:?}");
            };
            assert_eq!(error.code, ENGINE_UNAVAILABLE);
            assert!(error.is_error());
            assert_eq!(error.suggestion.as_deref(), Some(ENGINE_UNAVAILABLE_ADVICE));
        }
    }

    #[test]
    fn without_the_engines_lint_stops_and_says_why() {
        let refused = LintQueryCheck::check(&Unavailable, Path::new("a.yaml"), "a.yaml", None, "");
        let message = refused.unwrap_err();
        assert!(message.starts_with(ENGINE_UNAVAILABLE_MESSAGE), "{message}");
        assert!(message.contains(ENGINE_UNAVAILABLE_ADVICE), "{message}");
    }

    #[test]
    fn the_build_says_whether_it_has_the_engines() {
        assert_eq!(AVAILABLE, cfg!(feature = "queries"));
    }
}
