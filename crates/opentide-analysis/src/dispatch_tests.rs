//! The editor hooks answer as they did before they went through
//! `QueryEngine` (#1953): `old_*` are the matches `opentide_analysis` had,
//! calling each crate's functions exactly as they did, and every query
//! language's hover, completion and signature help through the public entry
//! points is compared with them at every char boundary of multi-byte
//! samples, in raw query files and in Tide blocks that pick a dialect.

use super::*;

/// Queries that parse and that do not, in every query language, with
/// multi-byte text and ECS fields (`process.name`, `user.name`) that only
/// the ECS fallback knows.
const SAMPLES: &[&str] = &[
    "",
    "é 😀",
    "SecurityEvent | where Account == 'é😀' | summarize count() by bin(",
    "index=main user=\"é😀\" | stats count by (",
    "FROM logs-* | WHERE process.name == \"é😀\" | EVAL x = CONCAT(",
    "process where process.name : \"é😀\" and (user.",
    "process.name: \"é😀\" and (a OR user.na",
    "process.name:\"é😀\" AND user.name:",
    "#event_simpleName=ProcessRollup2 user=\"é😀\" | count(",
    "spawned_process and proc.name = \"é😀\" and (",
    "rule r { strings: $a = \"é😀\" condition: uint16(0) == 0x5a4d and $a }",
    "rule r { events: $e.principal.user.userid = \"é😀\" condition: $e }",
    "activity_type:\"é😀\" AND (",
    "@usr.name:\"é😀\" AND (service:web OR",
];

/// Every platform whose name changes a dialect or the ECS fallback, and
/// some that do not.
const PLATFORMS: &[&str] = &[
    "",
    "sentinel",
    "microsoft_defender",
    "elastic",
    "carbon_black_cloud",
    "graylog",
    "splunk",
];

fn boundaries(source: &str) -> impl Iterator<Item = usize> + use<'_> {
    (0..=source.len()).filter(move |&i| source.is_char_boundary(i))
}

fn old_query_hover(
    language: LanguageId,
    text: &str,
    offset: usize,
    platform: &str,
) -> Option<String> {
    match language {
        LanguageId::Kql => {
            opentide_kql::hover(text, offset, opentide_kql::Dialect::for_platform(platform))
        }
        LanguageId::Spl => opentide_spl::hover(text, offset),
        LanguageId::Esql => opentide_esql::hover(text, offset).or_else(|| ecs::hover(text, offset)),
        LanguageId::Eql => opentide_eql::hover(text, offset).or_else(|| ecs::hover(text, offset)),
        LanguageId::Kuery => {
            opentide_kuery::hover(text, offset).or_else(|| ecs::hover(text, offset))
        }
        LanguageId::Lucene
            if opentide_lucene::Dialect::for_platform(platform)
                != opentide_lucene::Dialect::Elastic =>
        {
            opentide_lucene::hover_dialect(
                text,
                offset,
                opentide_lucene::Dialect::for_platform(platform),
            )
        }
        LanguageId::Lucene => {
            opentide_lucene::hover(text, offset).or_else(|| ecs::hover(text, offset))
        }
        LanguageId::Falco => {
            opentide_falco::hover(text, offset, &opentide_falco::Context::default())
        }
        LanguageId::Cql => opentide_cql::hover(text, offset),
        LanguageId::Yara => opentide_yara::editor::hover(text, offset),
        LanguageId::Exabeam => opentide_exabeam::hover(text, offset),
        LanguageId::Datadog => opentide_datadog::hover(text, offset),
        LanguageId::Yaral => opentide_yaral::editor::hover(text, offset),
        _ => None,
    }
}

fn old_query_completions(
    language: LanguageId,
    text: &str,
    offset: usize,
    platform: &str,
) -> Vec<CompletionItem> {
    match language {
        LanguageId::Kql => {
            opentide_kql::completions(text, offset, opentide_kql::Dialect::for_platform(platform))
        }
        LanguageId::Spl => opentide_spl::completions(text, offset),
        LanguageId::Lucene
            if opentide_lucene::Dialect::for_platform(platform)
                != opentide_lucene::Dialect::Elastic =>
        {
            opentide_lucene::completions_dialect(
                text,
                offset,
                opentide_lucene::Dialect::for_platform(platform),
            )
        }
        LanguageId::Esql | LanguageId::Eql | LanguageId::Kuery | LanguageId::Lucene => {
            let mut items = match language {
                LanguageId::Esql => opentide_esql::completions(text, offset),
                LanguageId::Eql => opentide_eql::completions(text, offset),
                LanguageId::Kuery => opentide_kuery::completions(text, offset),
                _ => opentide_lucene::completions(text, offset),
            };
            ecs::complete(language, text, offset, &mut items);
            items
        }
        LanguageId::Falco => {
            opentide_falco::completions(text, offset, &opentide_falco::Context::default())
        }
        LanguageId::Cql => opentide_cql::completions(text, offset),
        LanguageId::Yara => opentide_yara::editor::completions(text, offset),
        LanguageId::Exabeam => opentide_exabeam::completions(text, offset),
        LanguageId::Datadog => opentide_datadog::completions(text, offset),
        LanguageId::Yaral => opentide_yaral::editor::completions(text, offset),
        _ => Vec::new(),
    }
}

fn old_query_signature_help(
    language: LanguageId,
    text: &str,
    offset: usize,
    platform: &str,
) -> Option<SignatureHelp> {
    match language {
        LanguageId::Kql => opentide_kql::signature_help(
            text,
            offset,
            opentide_kql::Dialect::for_platform(platform),
        ),
        LanguageId::Spl => opentide_spl::signature_help(text, offset),
        LanguageId::Esql => opentide_esql::signature_help(text, offset),
        LanguageId::Eql => opentide_eql::signature_help(text, offset),
        LanguageId::Cql => opentide_cql::signature_help(text, offset),
        LanguageId::Yara => opentide_yara::editor::signature_help(text, offset),
        LanguageId::Yaral => opentide_yaral::editor::signature_help(text, offset),
        _ => None,
    }
}

/// A raw query file in each of the 12 languages, through `hover`,
/// `completions` and `signature_help`.
#[test]
fn raw_query_files_answer_as_before() {
    let host = MemoryWorkspace::default();
    assert_eq!(LanguageId::QUERY_LANGUAGES.len(), 12);
    for &language in LanguageId::QUERY_LANGUAGES {
        for source in SAMPLES {
            for offset in boundaries(source) {
                let at = format!("{language:?}: {source:?} at {offset}");
                assert_eq!(
                    hover(&host, language, source, offset),
                    old_query_hover(language, source, offset, ""),
                    "hover {at}"
                );
                assert_eq!(
                    completions(&host, language, source, offset),
                    old_query_completions(language, source, offset, ""),
                    "completions {at}"
                );
                assert_eq!(
                    signature_help(&host, language, source, offset),
                    old_query_signature_help(language, source, offset, ""),
                    "signature help {at}"
                );
            }
        }
    }
}

/// Every language under every platform: the dialect and the ECS fallback
/// the platform picks, as the old matches picked them.
#[test]
fn each_platform_answers_as_before() {
    for &language in LanguageId::QUERY_LANGUAGES {
        for &platform in PLATFORMS {
            for source in SAMPLES {
                for offset in boundaries(source) {
                    let at = format!("{language:?} on {platform:?}: {source:?} at {offset}");
                    assert_eq!(
                        query_hover(language, source, offset, platform),
                        old_query_hover(language, source, offset, platform),
                        "hover {at}"
                    );
                    assert_eq!(
                        query_completions(language, source, offset, platform),
                        old_query_completions(language, source, offset, platform),
                        "completions {at}"
                    );
                    assert_eq!(
                        query_signature_help(language, source, offset, platform),
                        old_query_signature_help(language, source, offset, platform),
                        "signature help {at}"
                    );
                }
            }
        }
    }
}

/// Tide blocks whose platform picks the KQL or Lucene dialect, or the ECS
/// fallback, through the public entry points at every char boundary of the
/// object file.
#[test]
fn tide_blocks_answer_as_before() {
    let header = "name: é😀\nmetadata:\n  uuid: 00000000-0000-4000-8003-000000000001\n  schema: rule::1.1\nconfigurations:\n";
    let blocks = [
        (
            LanguageId::Kql,
            "  sentinel:\n    query: |\n      SecurityEvent | where Account == 'é😀' | summarize count() by bin(\n",
        ),
        (
            LanguageId::Kql,
            "  microsoft_defender:\n    query: |\n      DeviceProcessEvents | where AccountName == 'é😀' | summarize count() by bin(\n",
        ),
        (
            LanguageId::Lucene,
            "  elastic:\n    type: query\n    language: lucene\n    query: process.name:\"é😀\" AND user.name:\n",
        ),
        (
            LanguageId::Kuery,
            "  elastic:\n    type: query\n    language: kuery\n    query: process.name:\"é😀\" and user.na\n",
        ),
        (
            LanguageId::Eql,
            "  elastic:\n    type: eql\n    language: eql\n    query: process where process.name : \"é😀\" and (user.\n",
        ),
        (
            LanguageId::Esql,
            "  elastic:\n    type: esql\n    language: esql\n    query: FROM logs-* | WHERE process.name == \"é😀\" | EVAL x = CONCAT(\n",
        ),
        (
            LanguageId::Lucene,
            "  carbon_black_cloud:\n    query: process_name:\"é😀\" AND process.name:\n",
        ),
    ];
    let host = MemoryWorkspace::default();
    for (language, block) in blocks {
        let doc = format!("{header}{block}");
        // The block's own `é😀`, past the header's.
        let probe = doc.rfind("é😀");
        let (injection, _) = probe
            .and_then(|i| opentide_tide::injection_at_offset(&doc, i))
            .unwrap_or_else(|| panic!("no injection in {doc:?}"));
        assert_eq!(injection.language, language, "{doc:?}");
        for offset in boundaries(&doc) {
            let at = format!("{doc:?} at {offset}");
            let old_hover = opentide_tide::injection_at_offset(&doc, offset).map_or_else(
                || opentide_tide::hover_tide(&doc, offset, &workspace_index(&host)),
                |(inj, inner)| old_query_hover(inj.language, &inj.inner, inner, &inj.platform),
            );
            assert_eq!(
                hover(&host, LanguageId::TideYaml, &doc, offset),
                old_hover,
                "hover {at}"
            );
            let old_completions = opentide_tide::injection_typed_at(&doc, offset).map_or_else(
                || opentide_tide::completions_tide(&doc, offset, &workspace_index(&host)),
                |(inj, inner, typed)| {
                    let mut query = inj.inner.clone();
                    query.insert_str(inner, &typed);
                    old_query_completions(inj.language, &query, inner + typed.len(), &inj.platform)
                },
            );
            assert_eq!(
                completions(&host, LanguageId::TideYaml, &doc, offset),
                old_completions,
                "completions {at}"
            );
            let old_signature =
                opentide_tide::injection_at_offset(&doc, offset).and_then(|(inj, inner)| {
                    old_query_signature_help(inj.language, &inj.inner, inner, &inj.platform)
                });
            assert_eq!(
                signature_help(&host, LanguageId::TideYaml, &doc, offset),
                old_signature,
                "signature help {at}"
            );
        }
    }
}

/// Which language and platform read ECS fields, written out: ES|QL, EQL and
/// Kibana KQL everywhere, Lucene except in its Carbon Black and Graylog
/// dialects, nothing else.
#[test]
fn ecs_applies_to_the_elastic_languages_only() {
    let languages = LanguageId::QUERY_LANGUAGES
        .iter()
        .copied()
        .chain([LanguageId::TideYaml, LanguageId::Config]);
    for language in languages {
        for &platform in PLATFORMS {
            let expected = match language {
                LanguageId::Esql | LanguageId::Eql | LanguageId::Kuery => true,
                LanguageId::Lucene => !matches!(platform, "carbon_black_cloud" | "graylog"),
                _ => false,
            };
            assert_eq!(
                ecs_applies(language, platform),
                expected,
                "{language:?} on {platform:?}"
            );
        }
    }
}

/// An ECS-only field gets the ECS docs and completions in an Elastic
/// Lucene query (a raw file, an `elastic` block) and not in Carbon Black's
/// or Graylog's.
#[test]
fn ecs_fields_reach_elastic_lucene_only() {
    let source = "process.name:\"é😀\" AND user.na";
    let field = source.find("name").unwrap_or_default();
    let end = source.len();
    let ecs_docs = ecs::hover(source, field).unwrap_or_default();
    assert!(!ecs_docs.is_empty(), "process.name is an ECS field");
    let user_name = |items: &[CompletionItem]| items.iter().any(|i| i.label == "user.name");
    for (platform, ecs) in [
        ("", true),
        ("elastic", true),
        ("carbon_black_cloud", false),
        ("graylog", false),
    ] {
        let hovered = query_hover(LanguageId::Lucene, source, field, platform);
        assert_eq!(
            hovered.as_deref() == Some(ecs_docs.as_str()),
            ecs,
            "hover on {platform:?}: {hovered:?}"
        );
        let items = query_completions(LanguageId::Lucene, source, end, platform);
        assert_eq!(user_name(&items), ecs, "completions on {platform:?}");
    }
    let host = MemoryWorkspace::default();
    assert_eq!(
        hover(&host, LanguageId::Lucene, source, field).as_deref(),
        Some(ecs_docs.as_str())
    );
    assert!(user_name(&completions(
        &host,
        LanguageId::Lucene,
        source,
        end
    )));
    // The same query in a Tide block: the platform decides.
    for (block, ecs) in [
        ("  elastic:\n    type: query\n    language: lucene\n", true),
        ("  carbon_black_cloud:\n", false),
    ] {
        let doc = format!(
            "name: ECS\nmetadata:\n  uuid: 00000000-0000-4000-8003-000000000001\n  schema: rule::1.1\nconfigurations:\n{block}    query: {source}\n"
        );
        let start = doc.find(source).unwrap_or_default();
        let hovered = hover(&host, LanguageId::TideYaml, &doc, start + field);
        assert_eq!(
            hovered.as_deref() == Some(ecs_docs.as_str()),
            ecs,
            "hover in {block:?}: {hovered:?}"
        );
        let items = completions(&host, LanguageId::TideYaml, &doc, start + end);
        assert_eq!(user_name(&items), ecs, "completions in {block:?}");
    }
}
