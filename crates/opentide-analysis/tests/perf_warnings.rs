//! Slow-query warnings on raw KQL/SPL files and the same text inside Tide blocks.

use opentide_analysis::{AnalyzeRequest, MemoryWorkspace, analyze};
use opentide_core::{LanguageId, Severity};
use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(name: &str) -> String {
    std::fs::read_to_string(repo_root().join("testdata/conformance/perf").join(name)).unwrap()
}

fn codes_for(language: LanguageId, text: &str) -> Vec<String> {
    let host = MemoryWorkspace::default();
    analyze(
        &host,
        AnalyzeRequest {
            uri: format!("memory.{}", language.as_str()),
            language,
            text: text.to_string(),
        },
    )
    .diagnostics
    .into_iter()
    .filter(|d| d.severity == Severity::Warning)
    .map(|d| d.code)
    .collect()
}

#[test]
fn kql_where_not_first_fixture_raw_and_tide() {
    let raw = read("where-not-first.kql");
    let raw_codes = codes_for(LanguageId::Kql, &raw);
    assert!(
        raw_codes.iter().any(|c| c == "kql_where_not_first"),
        "{raw_codes:?}"
    );

    let yaml = read("where-not-first.rule.yaml");
    let host = MemoryWorkspace {
        files: vec![("where-not-first.rule.yaml".into(), yaml.clone())],
    };
    let response = analyze(
        &host,
        AnalyzeRequest {
            uri: "where-not-first.rule.yaml".into(),
            language: LanguageId::TideYaml,
            text: yaml,
        },
    );
    let diag = response
        .diagnostics
        .iter()
        .find(|d| d.code == "kql_where_not_first")
        .expect("tide where warning");
    assert_eq!(diag.severity, Severity::Warning);
    assert!(
        diag.message
            .contains("https://learn.microsoft.com/en-us/kusto/query/best-practices")
    );
    assert_eq!(
        diag.field_path.as_deref(),
        Some(
            [
                "configurations".to_string(),
                "sentinel".into(),
                "query".into()
            ]
            .as_slice()
        )
    );
    assert!(
        diag.range.end.line > diag.range.start.line
            || diag.range.end.character > diag.range.start.character
    );
}

#[test]
fn spl_leading_wildcard_fixture_raw_and_tide() {
    let raw = read("leading-wildcard.spl");
    let raw_codes = codes_for(LanguageId::Spl, &raw);
    assert!(
        raw_codes.iter().any(|c| c == "spl_wildcard"),
        "{raw_codes:?}"
    );

    let yaml = read("leading-wildcard.rule.yaml");
    let host = MemoryWorkspace {
        files: vec![("leading-wildcard.rule.yaml".into(), yaml.clone())],
    };
    let response = analyze(
        &host,
        AnalyzeRequest {
            uri: "leading-wildcard.rule.yaml".into(),
            language: LanguageId::TideYaml,
            text: yaml,
        },
    );
    let diag = response
        .diagnostics
        .iter()
        .find(|d| d.code == "spl_wildcard")
        .expect("tide wildcard warning");
    assert_eq!(diag.severity, Severity::Warning);
    assert!(
        diag.message
            .contains("https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Search")
    );
    assert_eq!(
        diag.field_path.as_deref(),
        Some(
            [
                "configurations".to_string(),
                "splunk".into(),
                "search".into()
            ]
            .as_slice()
        )
    );
}

#[test]
fn project_after_summarize_is_a_warning_and_summarize_alone_is_not() {
    let reversed = "SecurityEvent\n| where EventID == 4688\n| summarize count() by Computer\n| project Computer, count_\n";
    let codes = codes_for(LanguageId::Kql, reversed);
    assert!(
        codes
            .iter()
            .any(|c| c == "kql_join_summarize_before_project"),
        "{codes:?}"
    );
    let no_project = "SecurityEvent\n| where EventID == 4688\n| summarize count() by Computer\n";
    let codes = codes_for(LanguageId::Kql, no_project);
    assert!(
        !codes
            .iter()
            .any(|c| c == "kql_join_summarize_before_project"),
        "{codes:?}"
    );
    let already = "SecurityEvent\n| where EventID == 4688\n| project Computer, EventID\n| summarize count() by Computer\n| project Computer, count_\n";
    let codes = codes_for(LanguageId::Kql, already);
    assert!(
        !codes
            .iter()
            .any(|c| c == "kql_join_summarize_before_project"),
        "{codes:?}"
    );
}

#[test]
fn clean_hunt_and_trailing_wildcard_stay_clean() {
    let kql = codes_for(LanguageId::Kql, &read("sentinel-hunt.kql"));
    assert!(
        kql.iter().all(|c| {
            !matches!(
                c.as_str(),
                "kql_where_not_first"
                    | "kql_unscoped_search"
                    | "kql_unscoped_union"
                    | "kql_wildcard_table"
                    | "kql_join_summarize_before_project"
            )
        }),
        "{kql:?}"
    );
    let spl = codes_for(LanguageId::Spl, &read("trailing-wildcard.spl"));
    assert!(
        spl.iter().all(|c| {
            !matches!(
                c.as_str(),
                "spl_wildcard" | "spl_leading_not" | "spl_subsearch_truncation"
            )
        }),
        "{spl:?}"
    );
}
