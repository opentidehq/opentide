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
      #event_simpleName=ProcessRollup2 | groupBi(aid)
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
            vec!["configurations", "crowdstrike", "query"],
        ]
    );
    assert_eq!(reports[0].language, LanguageId::Kql);
    assert_eq!(reports[0].platform, "sentinel");
    assert_eq!(reports[1].platform, "splunk");
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
    // CrowdStrike is CQL, checked as a Next-Gen SIEM correlation rule.
    assert_eq!(reports[2].language, LanguageId::Cql);
    assert_eq!(reports[2].platform, "crowdstrike");
    let unknown = reports[2]
        .diagnostics
        .iter()
        .find(|d| d.code == codes::CQL_UNKNOWN_FUNCTION)
        .expect("groupBi");
    assert_eq!(unknown.range.start.line, 14);
    assert_eq!(unknown.suggestion.as_deref(), Some("groupBy"));
}

#[test]
fn a_hunt_is_reported_at_its_path_with_its_platform_and_profile() {
    // A hunt's path does not name its platform: `platform` does, and it picks
    // the KQL profile (`NTANetAnalytics` is a Log Analytics table, not an
    // advanced hunting one).
    let rule = r#"name: Hunts
metadata:
  uuid: 00000000-0000-4000-8003-000000000001
  schema: rule::1.0
response:
  procedure:
    searches:
      - query: NTANetAnalytics | take 1
        system: defender_for_endpoint
      - system: sentinel
        query: NTANetAnalytics | take 1
"#;
    let reports = analyze_queries(&MemoryWorkspace::default(), rule);
    let found: Vec<(String, &str, bool)> = reports
        .iter()
        .map(|r| {
            (
                r.field_path.join("."),
                r.platform.as_str(),
                r.diagnostics
                    .iter()
                    .any(|d| d.code == codes::KQL_UNKNOWN_TABLE),
            )
        })
        .collect();
    assert_eq!(
        found,
        vec![
            (
                "response.procedure.searches.0.query".into(),
                "defender_for_endpoint",
                true
            ),
            (
                "response.procedure.searches.1.query".into(),
                "sentinel",
                false
            ),
        ]
    );
    assert!(reports.iter().all(|r| r.language == LanguageId::Kql));
    assert_eq!(reports[0].range.start.line, 7);
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
    // Sentinel ingests the Defender XDR tables (#113).
    assert!(!unknown_table(&defender));
    assert!(!unknown_table(&sentinel));
    // A Log Analytics table is not an advanced hunting table.
    let log_analytics = |platform: &str| QueryRequest {
        platform: Some(platform.into()),
        text: "NTANetAnalytics | take 1".into(),
        ..defender.clone()
    };
    assert!(unknown_table(&log_analytics("defender_for_endpoint")));
    assert!(!unknown_table(&log_analytics("sentinel")));

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

/// UC-2.6 (#821): the analysis of a Tide object reads no other object of
/// the workspace — its own checks are `validate`'s — so an unresolved
/// reference is not a finding here, with or without an index of the
/// workspace.
#[test]
fn the_analysis_reads_no_other_object() {
    use opentide_analysis::{AnalyzeRequest, analyze, index_workspace};
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
    assert_eq!(index_workspace(&host).len(), 2);
    let found: Vec<String> = analyze(&host, request)
        .diagnostics
        .into_iter()
        .map(|d| d.code)
        .collect();
    assert!(found.is_empty(), "{found:?}");
}

#[test]
fn the_bundled_catalogs_are_the_files_compiled_in() {
    let bundled = opentide_analysis::bundled_catalog();
    let root =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../data/catalogs/tide/generated");
    let read = |name: &str| std::fs::read_to_string(root.join(name)).expect(name);
    assert_eq!(
        bundled.fields.as_deref(),
        Some(read("fields.json").as_str())
    );
    assert_eq!(
        bundled.deprecations.as_deref(),
        Some(read("deprecations.json").as_str())
    );
    let fields: serde_json::Value =
        serde_json::from_str(bundled.fields.as_deref().unwrap_or_default()).expect("fields.json");
    assert_eq!(
        fields["opentide"].as_str(),
        Some(opentide_analysis::catalog_version())
    );
}

const CORRELATE_THEN_AGGREGATE: &str = "correlate(A: { #event_simpleName=UserLogon }, B: { #event_simpleName=ProcessRollup2 | aid <=> A.aid }, within=10m) | groupBy(aid)";

fn has_correlate_aggregate(diagnostics: &[opentide_analysis::Diagnostic]) -> bool {
    diagnostics
        .iter()
        .any(|d| d.code == codes::CQL_CORRELATE_AGGREGATE)
}

#[test]
fn a_single_cql_query_is_a_correlation_rule_only_for_the_crowdstrike_platform() {
    let request = |platform: Option<&str>| QueryRequest {
        language: LanguageId::Cql,
        platform: platform.map(str::to_string),
        stack: None,
        text: CORRELATE_THEN_AGGREGATE.into(),
    };
    let rule = analyze_query(&request(Some("crowdstrike")));
    assert!(has_correlate_aggregate(&rule), "{rule:?}");
    // No platform: plain LogScale, which allows an aggregate after correlate().
    let plain = analyze_query(&request(None));
    assert!(!has_correlate_aggregate(&plain), "{plain:?}");
}

#[test]
fn a_crowdstrike_hunt_search_is_not_a_correlation_rule() {
    let query = "correlate(A: { #event_simpleName=UserLogon }, B: { #event_simpleName=ProcessRollup2 | aid <=> A.aid }, within=10m) | count()";
    let text = format!(
        "name: Hunt\nmetadata:\n  uuid: 00000000-0000-4000-8003-000000000001\n  schema: rule::1.0\nconfigurations:\n  crowdstrike:\n    query: '{query}'\nresponse:\n  procedure:\n    searches:\n      - system: crowdstrike\n        query: '{query}'\n"
    );
    let reports = analyze_queries(&MemoryWorkspace::default(), &text);
    let found: Vec<(String, bool)> = reports
        .iter()
        .map(|r| {
            (
                r.field_path.join("."),
                has_correlate_aggregate(&r.diagnostics),
            )
        })
        .collect();
    assert_eq!(
        found,
        vec![
            ("configurations.crowdstrike.query".into(), true),
            ("response.procedure.searches.0.query".into(), false),
        ]
    );
}
