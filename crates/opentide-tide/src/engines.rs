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

    /// What `language`'s engine finds on each of `sources` under `setting`,
    /// as diagnostics and tokens.
    fn through(
        language: LanguageId,
        sources: &[&str],
        setting: Setting<'_>,
    ) -> Vec<(
        Vec<opentide_core::Diagnostic>,
        Vec<opentide_highlight::HighlightToken>,
    )> {
        sources
            .iter()
            .map(|source| {
                let r = engine(language).map(|e| e.analyze_for(source, &setting));
                let r = r.unwrap_or_default();
                (r.diagnostics, r.tokens)
            })
            .collect()
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
    /// before they went through the trait (#1953). Each row names the
    /// behaviour its setting should get; [`assert_classes`] holds two rows
    /// with the same name to the same findings and two with different names
    /// to different ones, so the inputs tell every mapping apart.
    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "one table per language, side by side"
    )]
    fn a_setting_selects_what_the_crate_takes() {
        use opentide_kql::{Dialect, Profile as Kql};
        let kql = [
            // Sentinel's rule refuses `search *`.
            "search * | where x == 'é😀' | take 1",
            // A Sentinel table Defender's catalog does not have.
            "SecurityEvent | where Account == 'é😀' | take 1",
            // A Defender table.
            "DeviceProcessEvents | where FileName == 'é😀' | take 1",
        ];
        let direct = |dialect: Dialect, profile: Option<Kql>| {
            kql.iter()
                .map(|source| {
                    let mut r = opentide_kql::analyze(source, dialect);
                    if let Some(profile) = profile {
                        opentide_kql::apply_profile(source, dialect, profile, &mut r.diagnostics);
                    }
                    (r.diagnostics, r.tokens)
                })
                .collect::<Vec<_>>()
        };
        let mut seen = Vec::new();
        // KQL's search profile adds nothing to `analyze` in any dialect, and
        // Defender's rule takes none of Sentinel's limits (`rule_findings`):
        // File, Search and Defender's Rule are the same checks, so they share
        // a class. File applies no profile, as `analyze_query` did.
        for (platform, dialect, classes) in [
            (
                "",
                Dialect::Sentinel,
                ["sentinel", "sentinel", "sentinel rule"],
            ),
            (
                "sentinel",
                Dialect::Sentinel,
                ["sentinel", "sentinel", "sentinel rule"],
            ),
            ("microsoft_defender", Dialect::Defender, ["defender"; 3]),
        ] {
            for ((profile, kql_profile), class) in [
                (Profile::File, None),
                (Profile::Search, Some(Kql::Search)),
                (Profile::Rule, Some(Kql::Rule)),
            ]
            .into_iter()
            .zip(classes)
            {
                let direct = direct(dialect, kql_profile);
                assert_eq!(
                    through(LanguageId::Kql, &kql, setting(platform, profile)),
                    direct,
                    "{platform} {profile:?}"
                );
                seen.push((class, direct));
            }
        }
        assert_classes("kql", &seen);

        let lucene = [
            "process.name:a* and 'é😀' AND cb_field:x",
            // Graylog refuses a leading wildcard.
            "message:*é😀",
        ];
        let mut seen = Vec::new();
        for (platform, dialect, class) in [
            ("", opentide_lucene::Dialect::Elastic, "elastic"),
            // Every platform but Carbon Black and Graylog is Elastic's.
            ("elastic", opentide_lucene::Dialect::Elastic, "elastic"),
            (
                "carbon_black_cloud",
                opentide_lucene::Dialect::CarbonBlack,
                "carbon black",
            ),
            ("graylog", opentide_lucene::Dialect::Graylog, "graylog"),
        ] {
            let direct: Vec<_> = lucene
                .iter()
                .map(|source| {
                    let r = opentide_lucene::analyze_dialect(source, dialect);
                    (r.diagnostics, r.tokens)
                })
                .collect();
            let found = through(
                LanguageId::Lucene,
                &lucene,
                setting(platform, Profile::Rule),
            );
            assert_eq!(found, direct, "{platform}");
            seen.push((class, direct));
        }
        assert_classes("lucene", &seen);

        let yara = [
            "rule é { strings: $a = \"😀\" condition: $a and pe.is_dll() }",
            // HarfangLab knows a fixed set of contexts.
            "rule a { meta: context = \"nowhere\" condition: true }",
        ];
        let mut seen = Vec::new();
        // A platform with no YARA dialect checks as a raw `.yar` file does.
        for (platform, class) in [
            ("", "no dialect"),
            ("sentinel", "no dialect"),
            ("harfanglab", "harfanglab"),
            ("bitdefender", "bitdefender"),
        ] {
            let ctx = opentide_yara::Dialect::for_platform(platform)
                .map(opentide_yara::Context::for_profile)
                .unwrap_or_default();
            let direct: Vec<_> = yara
                .iter()
                .map(|source| {
                    let r = opentide_yara::analyze_with(source, &ctx);
                    (r.diagnostics, r.tokens)
                })
                .collect();
            let found = through(LanguageId::Yara, &yara, setting(platform, Profile::Search));
            assert_eq!(found, direct, "{platform}");
            seen.push((class, direct));
        }
        assert_classes("yara", &seen);

        let esql = [
            "FROM logs-* | WHERE a == \"é😀\" | LOOKUP JOIN x ON a",
            // FORK is new in 9.1.
            "FROM logs-* | FORK (WHERE a == \"é😀\") (WHERE b > 1)",
            // DAY is new in 9.6, the newest line: serverless has it.
            "ROW d = DAY(NOW()) // é😀",
        ];
        let mut seen = Vec::new();
        // A stack that does not parse is no stack.
        for (stack, class) in [
            (None, "every stack"),
            (Some("nine"), "every stack"),
            (Some("8.19"), "8.19"),
            (Some("9.5"), "9.5"),
            (Some("serverless"), "serverless"),
        ] {
            let target = stack.and_then(opentide_esql::StackTarget::parse);
            let direct: Vec<_> = esql
                .iter()
                .map(|source| {
                    let r = opentide_esql::analyze_for(source, target);
                    (r.diagnostics, r.tokens)
                })
                .collect();
            let found = through(
                LanguageId::Esql,
                &esql,
                Setting {
                    stack,
                    ..Setting::default()
                },
            );
            assert_eq!(found, direct, "{stack:?}");
            seen.push((class, direct));
        }
        assert_classes("esql", &seen);

        // CQL, Exabeam and Datadog have no file profile: a file is checked
        // as a search, the crate's default.
        let cql = [
            "correlate(A: { #event_simpleName=UserLogon }, B: { #event_simpleName=ProcessRollup2 | aid <=> A.aid }, within=10m) | groupBy(aid) // é😀",
        ];
        let mut seen = Vec::new();
        for (profile, ctx, class) in [
            (Profile::File, opentide_cql::Profile::default(), "search"),
            (Profile::Search, opentide_cql::Profile::default(), "search"),
            (
                Profile::Rule,
                opentide_cql::Profile::CORRELATION_RULE,
                "rule",
            ),
        ] {
            let r = opentide_cql::analyze_with(cql[0], &ctx);
            let direct = vec![(r.diagnostics, r.tokens)];
            assert_eq!(through(LanguageId::Cql, &cql, setting("", profile)), direct);
            seen.push((class, direct));
        }
        assert_classes("cql", &seen);

        let exabeam = ["activity_type:\"process-create\" | select user // é😀"];
        let mut seen = Vec::new();
        for (profile, ctx, class) in [
            (Profile::File, opentide_exabeam::Context::SEARCH, "search"),
            (Profile::Search, opentide_exabeam::Context::SEARCH, "search"),
            (Profile::Rule, opentide_exabeam::Context::RULE, "rule"),
        ] {
            let r = opentide_exabeam::analyze_with(exabeam[0], &ctx);
            let direct = vec![(r.diagnostics, r.tokens)];
            let found = through(LanguageId::Exabeam, &exabeam, setting("", profile));
            assert_eq!(found, direct);
            seen.push((class, direct));
        }
        assert_classes("exabeam", &seen);

        let datadog = ["*:é😀 #name source:windows"];
        let mut seen = Vec::new();
        for (profile, ctx, class) in [
            (Profile::File, opentide_datadog::Context::SEARCH, "search"),
            (Profile::Search, opentide_datadog::Context::SEARCH, "search"),
            (Profile::Rule, opentide_datadog::Context::RULE, "rule"),
        ] {
            let r = opentide_datadog::analyze_with(datadog[0], &ctx);
            let direct = vec![(r.diagnostics, r.tokens)];
            let found = through(LanguageId::Datadog, &datadog, setting("", profile));
            assert_eq!(found, direct);
            seen.push((class, direct));
        }
        assert_classes("datadog", &seen);

        let yaral = [
            "$e.metadata.event_type = \"PROCESS_LAUNCH\" and $e.principal.hostname = \"é😀\"",
            // A file reads a `rule` header as a rule, which needs `meta`; a
            // search does not.
            "rule r { events: $e.principal.hostname = \"é😀\" condition: $e }",
        ];
        let mut seen = Vec::new();
        for (profile, ctx, class) in [
            (Profile::File, opentide_yaral::Context::FILE, "file"),
            (Profile::Search, opentide_yaral::Context::SEARCH, "search"),
            (Profile::Rule, opentide_yaral::Context::SECTIONS, "sections"),
        ] {
            let direct: Vec<_> = yaral
                .iter()
                .map(|source| {
                    let r = opentide_yaral::analyze_with(source, &ctx);
                    (r.diagnostics, r.tokens)
                })
                .collect();
            let found = through(LanguageId::Yaral, &yaral, setting("", profile));
            assert_eq!(found, direct);
            seen.push((class, direct));
        }
        assert_classes("yaral", &seen);
    }

    /// Two settings of `language` in the same class give the same findings,
    /// and two in different classes give different ones: a mapping onto the
    /// wrong dialect, profile or stack fails the comparisons above.
    fn assert_classes<T: PartialEq + std::fmt::Debug>(language: &str, seen: &[(&str, T)]) {
        for (i, (class, found)) in seen.iter().enumerate() {
            for (other_class, other) in &seen[i + 1..] {
                if class == other_class {
                    assert_eq!(found, other, "{language}: {class} gives two results");
                } else {
                    assert_ne!(
                        found, other,
                        "{language}: {class} and {other_class} give the same findings"
                    );
                }
            }
        }
    }
}
