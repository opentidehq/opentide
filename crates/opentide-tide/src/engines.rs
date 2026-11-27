//! The query-engine registry (#1953): one [`QueryEngine`] per query
//! language, keyed by its [`LanguageId`].
//!
//! It lives here because opentide-tide is the lowest crate that depends on
//! every query crate (`xtask/layers.toml`); opentide-analysis and the crates
//! above it read it from here. A new query language adds its engine to
//! [`ENGINES`], and a dispatcher that looks the language up here needs no
//! new arm.

use opentide_core::LanguageId;
use opentide_highlight::QueryEngine;

/// Every query language's engine, one per [`LanguageId`]. Tide YAML and the
/// configuration files are documents, not queries: they have none.
pub static ENGINES: &[&dyn QueryEngine] = &[
    &opentide_kql::Engine,
    &opentide_spl::Engine,
    &opentide_esql::Engine,
    &opentide_eql::Engine,
    &opentide_kuery::Engine {
        lucene_parses: opentide_lucene::parses,
    },
    &opentide_lucene::Engine,
    &opentide_falco::Engine,
    &opentide_cql::Engine,
    &opentide_yara::Engine,
    &opentide_exabeam::Engine,
    &opentide_yaral::Engine,
    &opentide_datadog::Engine,
];

/// The engine of `language`, or `None` for a language that is not a query
/// language (Tide YAML, a configuration file).
#[must_use]
pub fn engine(language: LanguageId) -> Option<&'static dyn QueryEngine> {
    ENGINES
        .iter()
        .copied()
        .find(|engine| engine.language() == language)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_language_has_one_engine_that_reads_it() {
        let mut seen = Vec::new();
        for registered in ENGINES {
            let language = registered.language();
            assert!(!seen.contains(&language), "{language:?} registered twice");
            seen.push(language);
            let found = engine(language).map(QueryEngine::language);
            assert_eq!(found, Some(language));
        }
        assert_eq!(seen.len(), 12);
        assert!(engine(LanguageId::TideYaml).is_none());
        assert!(engine(LanguageId::Config).is_none());
    }

    #[test]
    fn an_engine_analyses_as_its_crate_does() {
        let kql = engine(LanguageId::Kql).map(|e| e.analyze("NoSuchTable | take 1"));
        let direct = opentide_kql::analyze("NoSuchTable | take 1", opentide_kql::Dialect::Sentinel);
        assert_eq!(
            kql.map(|r| (r.diagnostics, r.tokens)),
            Some((direct.diagnostics, direct.tokens))
        );
        let kuery = engine(LanguageId::Kuery).map(|e| e.analyze("process.name: (a OR"));
        let direct = opentide_kuery::analyze("process.name: (a OR", opentide_lucene::parses);
        assert_eq!(
            kuery.map(|r| (r.diagnostics, r.tokens)),
            Some((direct.diagnostics, direct.tokens))
        );
    }
}
