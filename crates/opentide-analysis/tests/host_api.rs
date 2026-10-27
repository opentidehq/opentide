//! The API the `opentide` Python package binds: per-query reports, single
//! queries, code descriptions, and the version.

use opentide_analysis::{
    LanguageId, MemoryWorkspace, QueryRequest, VERSION, analyze_queries, analyze_query, codes,
};

const RULE: &str = r#"name: Two Platforms
metadata:
  uuid: 00000000-0000-4000-8003-000000000001
  schema: rule::1.0
configurations:
  sentinel:
    query: |
      SecurityEvent
      | where EventID == 4688
  splunk:
    query: |
      index=main sourcetype=foo | statz count
  crowdstrike:
    query: |
      anything at all
"#;

#[test]
fn every_injected_query_is_reported_with_its_language_and_place() {
    let reports = analyze_queries(&MemoryWorkspace::default(), RULE);
    let paths: Vec<Vec<&str>> = reports
        .iter()
        .map(|r| r.field_path.iter().map(String::as_str).collect())
        .collect();
    assert_eq!(
        paths,
        vec![
            vec!["configurations", "sentinel", "query"],
            vec!["configurations", "splunk", "query"],
        ],
        "CrowdStrike is never validated, so it is not a query here"
    );
    assert_eq!(reports[0].language, LanguageId::Kql);
    assert!(
        reports[0].diagnostics.is_empty(),
        "{:?}",
        reports[0].diagnostics
    );
    assert_eq!(reports[0].range.start.line, 7);
    assert_eq!(reports[1].language, LanguageId::Spl);
    let unknown = reports[1]
        .diagnostics
        .iter()
        .find(|d| d.code == codes::SPL_UNKNOWN_COMMAND)
        .expect("statz");
    // Object-file coordinates: line 11 of RULE, under `query: |`.
    assert_eq!(unknown.range.start.line, 11);
    assert_eq!(
        unknown.field_path.as_deref(),
        Some(
            [
                "configurations".to_string(),
                "splunk".into(),
                "query".into()
            ]
            .as_slice()
        )
    );
}

#[test]
fn a_file_that_is_not_yaml_has_no_queries() {
    assert!(analyze_queries(&MemoryWorkspace::default(), "{ not: [yaml").is_empty());
}

#[test]
fn a_single_query_takes_the_platform_profile() {
    let defender = QueryRequest {
        language: LanguageId::Kql,
        platform: Some("defender_for_endpoint".into()),
        stack: None,
        text: "DeviceProcessEvents | take 1".into(),
    };
    let sentinel = QueryRequest {
        platform: Some("sentinel".into()),
        ..defender.clone()
    };
    let unknown_table = |request: &QueryRequest| {
        analyze_query(request)
            .iter()
            .any(|d| d.code == codes::KQL_UNKNOWN_TABLE)
    };
    assert!(!unknown_table(&defender));
    assert!(unknown_table(&sentinel));

    let broken = QueryRequest {
        language: LanguageId::Esql,
        platform: Some("elastic".into()),
        stack: Some("9.5".into()),
        text: "FROM logs-* | WHER x == 1".into(),
    };
    assert!(
        analyze_query(&broken)
            .iter()
            .any(|d| d.severity == opentide_analysis::Severity::Error)
    );
}

#[test]
fn every_code_has_a_description_and_the_version_is_the_crate_version() {
    for code in codes::ALL {
        assert!(codes::describe(code).is_some(), "{code}");
    }
    assert_eq!(VERSION, env!("CARGO_PKG_VERSION"));
}

#[test]
fn analysis_with_a_prebuilt_index_matches_analyze() {
    use opentide_analysis::{AnalyzeRequest, analyze, analyze_with_index, index_workspace};
    let objective = "name: Parent\nmetadata:\n  uuid: 00000000-0000-4000-8002-000000000001\n  schema: objective::1.0\n";
    let rule = "name: Child\nmetadata:\n  uuid: 00000000-0000-4000-8003-000000000002\n  schema: rule::1.0\ndetection_model: 00000000-0000-4000-8002-000000000009\n";
    let host = MemoryWorkspace {
        files: vec![
            ("objects/objectives/parent.yaml".into(), objective.into()),
            ("objects/rules/child.yaml".into(), rule.into()),
        ],
    };
    let request = AnalyzeRequest {
        uri: "objects/rules/child.yaml".into(),
        language: LanguageId::TideYaml,
        text: rule.into(),
    };
    let index = index_workspace(&host);
    let codes = |diagnostics: Vec<opentide_analysis::Diagnostic>| {
        diagnostics.into_iter().map(|d| d.code).collect::<Vec<_>>()
    };
    let indexed = codes(analyze_with_index(&host, &index, request.clone()).diagnostics);
    assert_eq!(indexed, codes(analyze(&host, request).diagnostics));
    assert!(
        indexed.contains(&codes::INVALID_REF.to_string()),
        "{indexed:?}"
    );
}
