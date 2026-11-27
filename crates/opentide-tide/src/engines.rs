//! The query-engine registry (#1953): one [`QueryEngine`] per query
//! language, keyed by its [`LanguageId`].
//!
//! It lives here because opentide-tide is the lowest crate that depends on
//! every query crate (`xtask/layers.toml`). Crates above opentide-analysis
//! read it as `opentide_analysis::engines`, never from here: it moves into
//! opentide-analysis when ADR 0016 folds opentide-tide into it (#1965). A
//! new query language adds its engine to [`ENGINES`], and a dispatcher that
//! looks the language up here needs no new arm.

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
            assert!(
                LanguageId::QUERY_LANGUAGES.contains(&language),
                "{language:?} has an engine but is not a query language"
            );
            seen.push(language);
            let found = engine(language).map(QueryEngine::language);
            assert_eq!(found, Some(language));
        }
        for &language in LanguageId::QUERY_LANGUAGES {
            assert!(
                seen.contains(&language),
                "{language:?} has no engine in ENGINES"
            );
        }
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

    use opentide_highlight::{Profile, Setting};

    /// `language`'s engine on `source` under `setting`, as diagnostics and
    /// tokens.
    fn through(
        language: LanguageId,
        source: &str,
        setting: Setting<'_>,
    ) -> (
        Vec<opentide_core::Diagnostic>,
        Vec<opentide_highlight::HighlightToken>,
    ) {
        let r = engine(language).map(|e| e.analyze_for(source, &setting));
        let r = r.unwrap_or_default();
        (r.diagnostics, r.tokens)
    }

    fn setting(platform: &str, profile: Profile) -> Setting<'_> {
        Setting {
            platform,
            profile,
            stack: None,
        }
    }

    /// Each engine maps a setting onto the dialect, profile and stack its
    /// crate takes, as `analyze_query` and Tide's injections chose them
    /// before they went through the trait (#1953).
    #[test]
    fn a_setting_selects_what_the_crate_takes() {
        use opentide_kql::{Dialect, Profile as Kql};
        let kql = "search * | where x == 'é😀' | take 1";
        let direct = |dialect: Dialect, profile: Option<Kql>| {
            let mut r = opentide_kql::analyze(kql, dialect);
            if let Some(profile) = profile {
                opentide_kql::apply_profile(kql, dialect, profile, &mut r.diagnostics);
            }
            (r.diagnostics, r.tokens)
        };
        for (platform, dialect) in [
            ("", Dialect::Sentinel),
            ("microsoft_defender", Dialect::Defender),
        ] {
            for (profile, kql_profile) in [
                (Profile::File, None),
                (Profile::Search, Some(Kql::Search)),
                (Profile::Rule, Some(Kql::Rule)),
            ] {
                assert_eq!(
                    through(LanguageId::Kql, kql, setting(platform, profile)),
                    direct(dialect, kql_profile),
                    "{platform} {profile:?}"
                );
            }
        }
        // The rule profile reaches the engine: Sentinel's rule refuses `search *`.
        let (rule, _) = through(LanguageId::Kql, kql, setting("", Profile::Rule));
        let (search, _) = through(LanguageId::Kql, kql, setting("", Profile::Search));
        assert_ne!(rule, search);

        let lucene = "process.name:a* and 'é😀' AND cb_field:x";
        let mut seen = Vec::new();
        for (platform, dialect) in [
            ("", opentide_lucene::Dialect::Elastic),
            ("carbon_black_cloud", opentide_lucene::Dialect::CarbonBlack),
            ("graylog", opentide_lucene::Dialect::Graylog),
        ] {
            let r = opentide_lucene::analyze_dialect(lucene, dialect);
            let direct = (r.diagnostics, r.tokens);
            let found = through(LanguageId::Lucene, lucene, setting(platform, Profile::Rule));
            assert_eq!(found, direct, "{platform}");
            seen.push(direct);
        }
        assert_distinct("lucene", &seen);

        let yara = "rule é { strings: $a = \"😀\" condition: $a and pe.is_dll() }";
        let mut seen = Vec::new();
        for platform in ["", "harfanglab", "bitdefender", "sentinel"] {
            let ctx = opentide_yara::Dialect::for_platform(platform)
                .map(opentide_yara::Context::for_profile)
                .unwrap_or_default();
            let r = opentide_yara::analyze_with(yara, &ctx);
            let direct = (r.diagnostics, r.tokens);
            let found = through(LanguageId::Yara, yara, setting(platform, Profile::Search));
            assert_eq!(found, direct, "{platform}");
            seen.push(direct);
        }
        assert_distinct("yara", &seen);

        let esql = "FROM logs-* | WHERE a == \"é😀\" | LOOKUP JOIN x ON a";
        let mut seen = Vec::new();
        for stack in [
            None,
            Some("8.19"),
            Some("9.5"),
            Some("serverless"),
            Some("nine"),
        ] {
            let target = stack.and_then(opentide_esql::StackTarget::parse);
            let r = opentide_esql::analyze_for(esql, target);
            let direct = (r.diagnostics, r.tokens);
            let found = through(
                LanguageId::Esql,
                esql,
                Setting {
                    stack,
                    ..Setting::default()
                },
            );
            assert_eq!(found, direct, "{stack:?}");
            seen.push(direct);
        }
        assert_distinct("esql", &seen);

        let cql = "correlate(A: { #event_simpleName=UserLogon }, B: { #event_simpleName=ProcessRollup2 | aid <=> A.aid }, within=10m) | groupBy(aid) // é😀";
        let mut seen = Vec::new();
        for (profile, ctx) in [
            (Profile::File, opentide_cql::Profile::default()),
            (Profile::Search, opentide_cql::Profile::default()),
            (Profile::Rule, opentide_cql::Profile::CORRELATION_RULE),
        ] {
            let r = opentide_cql::analyze_with(cql, &ctx);
            let direct = (r.diagnostics, r.tokens);
            assert_eq!(through(LanguageId::Cql, cql, setting("", profile)), direct);
            seen.push(direct);
        }
        assert_distinct("cql", &seen);

        let exabeam = "activity_type:\"process-create\" | select user // é😀";
        let mut seen = Vec::new();
        for (profile, ctx) in [
            (Profile::File, opentide_exabeam::Context::SEARCH),
            (Profile::Search, opentide_exabeam::Context::SEARCH),
            (Profile::Rule, opentide_exabeam::Context::RULE),
        ] {
            let r = opentide_exabeam::analyze_with(exabeam, &ctx);
            let direct = (r.diagnostics, r.tokens);
            let found = through(LanguageId::Exabeam, exabeam, setting("", profile));
            assert_eq!(found, direct);
            seen.push(direct);
        }
        assert_distinct("exabeam", &seen);

        let datadog = "*:é😀 #name source:windows";
        let mut seen = Vec::new();
        for (profile, ctx) in [
            (Profile::File, opentide_datadog::Context::SEARCH),
            (Profile::Search, opentide_datadog::Context::SEARCH),
            (Profile::Rule, opentide_datadog::Context::RULE),
        ] {
            let r = opentide_datadog::analyze_with(datadog, &ctx);
            let direct = (r.diagnostics, r.tokens);
            let found = through(LanguageId::Datadog, datadog, setting("", profile));
            assert_eq!(found, direct);
            seen.push(direct);
        }
        assert_distinct("datadog", &seen);

        let yaral =
            "$e.metadata.event_type = \"PROCESS_LAUNCH\" and $e.principal.hostname = \"é😀\"";
        let mut seen = Vec::new();
        for (profile, ctx) in [
            (Profile::File, opentide_yaral::Context::FILE),
            (Profile::Search, opentide_yaral::Context::SEARCH),
            (Profile::Rule, opentide_yaral::Context::SECTIONS),
        ] {
            let r = opentide_yaral::analyze_with(yaral, &ctx);
            let direct = (r.diagnostics, r.tokens);
            let found = through(LanguageId::Yaral, yaral, setting("", profile));
            assert_eq!(found, direct);
            seen.push(direct);
        }
        assert_distinct("yaral", &seen);
    }

    /// The input of `language` tells its settings apart: a mapping onto the
    /// wrong dialect, profile or stack would fail the comparison above.
    fn assert_distinct<T: PartialEq>(language: &str, seen: &[T]) {
        assert!(
            seen.iter().skip(1).any(|other| *other != seen[0]),
            "{language}: every setting gives the same findings"
        );
    }
}
