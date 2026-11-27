//! The API the `opentide` Python package binds: per-query reports, single
//! queries, code descriptions, and the version.

use opentide_analysis::{
    LanguageId, MemoryWorkspace, QueryPosition, QueryRequest, VERSION, analyze_queries,
    analyze_query, analyze_query_at, codes, validate_position,
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
        system: microsoft_defender
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
                "microsoft_defender",
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
    let defender = QueryRequest::new(LanguageId::Kql, "DeviceProcessEvents | take 1")
        .with_platform(Some("microsoft_defender"));
    let sentinel = defender.clone().with_platform(Some("sentinel"));
    let unknown_table = |request: &QueryRequest| {
        analyze_query(request)
            .iter()
            .any(|d| d.code == codes::KQL_UNKNOWN_TABLE)
    };
    // Sentinel ingests the Defender XDR tables (#113).
    assert!(!unknown_table(&defender));
    assert!(!unknown_table(&sentinel));
    // A Log Analytics table is not an advanced hunting table.
    let log_analytics = |platform: &str| {
        QueryRequest::new(LanguageId::Kql, "NTANetAnalytics | take 1").with_platform(Some(platform))
    };
    assert!(unknown_table(&log_analytics("microsoft_defender")));
    assert!(!unknown_table(&log_analytics("sentinel")));

    let broken = QueryRequest::new(LanguageId::Esql, "FROM logs-* | WHER x == 1")
        .with_platform(Some("elastic"))
        .with_stack(Some("9.5"));
    assert!(
        analyze_query(&broken)
            .iter()
            .any(|d| d.severity == opentide_analysis::Severity::Error)
    );
}

#[test]
fn every_code_has_a_description_and_the_version_is_the_one_every_build_reports() {
    for code in codes::ALL {
        assert!(codes::describe(code).is_some(), "{code}");
    }
    assert_eq!(VERSION, opentide_core::VERSION);
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

/// A query on its own is checked as a file of its language is: the platform
/// names a dialect, never a profile (ADR 0015 §4, #1912). A `.cql` file is
/// plain LogScale, which allows an aggregate after `correlate()`, even under
/// `--platform crowdstrike`; the CrowdStrike block's query is the
/// correlation rule ([`a_crowdstrike_hunt_search_is_not_a_correlation_rule`]).
#[test]
fn a_single_cql_query_is_a_search_whatever_the_platform() {
    let request = |platform: Option<&str>| {
        QueryRequest::new(LanguageId::Cql, CORRELATE_THEN_AGGREGATE).with_platform(platform)
    };
    let plain = analyze_query(&request(None));
    assert!(!has_correlate_aggregate(&plain), "{plain:?}");
    let crowdstrike = analyze_query(&request(Some("crowdstrike")));
    assert!(!has_correlate_aggregate(&crowdstrike), "{crowdstrike:?}");
}

/// A `.exabeam` search with Search's advanced operators passed without a
/// platform and failed with `exabeam_advanced_in_rule` under `exabeam`,
/// whose `rule` profile is a correlation-rule sequence's (#1912). A
/// `.datadog` search under a `datadog` platform is a search too.
#[test]
fn an_exabeam_or_datadog_search_is_a_search_under_its_platform() {
    let request = |language: LanguageId, platform: Option<&str>, text: &str| {
        QueryRequest::new(language, text).with_platform(platform)
    };
    let exabeam = "SELECT DISTINCT user, src_ip WHERE vendor:\"Microsoft\"";
    for platform in [None, Some("exabeam")] {
        let found = analyze_query(&request(LanguageId::Exabeam, platform, exabeam));
        assert!(found.is_empty(), "{platform:?}: {found:?}");
    }
    // The same text in a sequence filter is refused, by its position.
    let rule = opentide_exabeam::analyze_with(exabeam, &opentide_exabeam::Context::RULE);
    assert!(
        rule.diagnostics
            .iter()
            .any(|d| d.code == "exabeam_advanced_in_rule"),
        "{:?}",
        rule.diagnostics
    );
    // `*:term` is a warning only in a detection rule's query.
    let datadog = "*:mimikatz";
    for platform in [None, Some("datadog")] {
        let found = analyze_query(&request(LanguageId::Datadog, platform, datadog));
        assert!(
            !found.iter().any(|d| d.code == "datadog_full_text_in_rule"),
            "{platform:?}: {found:?}"
        );
    }
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

/// An explicit position is a position (#1993, ADR 0015 §4): at `rule`, a
/// query on its own is checked as the platform's rule block checks its own,
/// so the rule-only codes come back; at `search` (the default) they do not.
#[test]
fn a_query_at_the_rule_position_is_checked_as_its_rule_block() {
    let exabeam = "SELECT DISTINCT user, src_ip WHERE vendor:\"Microsoft\"";
    let cases = [
        (
            LanguageId::Cql,
            "crowdstrike",
            CORRELATE_THEN_AGGREGATE,
            codes::CQL_CORRELATE_AGGREGATE,
        ),
        (
            LanguageId::Exabeam,
            "exabeam",
            exabeam,
            "exabeam_advanced_in_rule",
        ),
        (
            LanguageId::Datadog,
            "datadog",
            "*:mimikatz",
            "datadog_full_text_in_rule",
        ),
    ];
    for (language, platform, text, code) in cases {
        let request = QueryRequest::new(language, text).with_platform(Some(platform));
        assert!(
            validate_position(&request, QueryPosition::Rule).is_ok(),
            "{platform}"
        );
        let found = |position| {
            analyze_query_at(&request, position)
                .iter()
                .any(|d| d.code == code)
        };
        assert!(found(QueryPosition::Rule), "{platform}: {code} at rule");
        assert!(
            !found(QueryPosition::Search),
            "{platform}: {code} at search"
        );
        // `analyze_query` is the search.
        assert_eq!(
            analyze_query(&request),
            analyze_query_at(&request, QueryPosition::Search)
        );
    }
}

/// A YARA-L text at `rule` is the rule a Google SecOps block assembles: the
/// rule profile, whose `meta` deploy writes. As a `.yaral` file (`search`) a
/// rule needs its own `meta` (#1993).
#[test]
fn a_yaral_rule_at_the_rule_position_needs_no_meta() {
    let text = "rule r {\n  events:\n    $e.metadata.event_type = \"USER_LOGIN\"\n  condition:\n    $e\n}\n";
    let missing_section = |position: QueryPosition| {
        analyze_query_at(
            &QueryRequest::new(LanguageId::Yaral, text).with_platform(Some("google_secops")),
            position,
        )
        .into_iter()
        .any(|d| d.code == codes::YARAL_SECTION_MISSING)
    };
    assert!(missing_section(QueryPosition::Search));
    assert!(!missing_section(QueryPosition::Rule));
}

/// A rule block is a platform's: a rule without one is one error and no
/// check, not a search.
#[test]
fn a_rule_position_needs_a_platform() {
    let rule = QueryPosition::Rule;
    let request = QueryRequest::new(LanguageId::Cql, CORRELATE_THEN_AGGREGATE);
    assert_eq!(
        validate_position(&request, rule),
        Err(opentide_analysis::QueryRequestError::RuleWithoutPlatform)
    );
    let found = analyze_query_at(&request, rule);
    assert_eq!(
        found.iter().map(|d| d.code.as_str()).collect::<Vec<_>>(),
        [codes::QUERY_POSITION_NEEDS_PLATFORM]
    );
    assert!(validate_position(&request.clone().with_platform(Some("")), rule).is_err());
    assert!(validate_position(&request.clone().with_platform(Some("crowdstrike")), rule).is_ok());
    assert!(validate_position(&request, QueryPosition::Search).is_ok());
}

#[test]
fn a_position_has_a_name() {
    for position in [QueryPosition::Search, QueryPosition::Rule] {
        assert_eq!(QueryPosition::parse(position.as_str()), Some(position));
    }
    assert_eq!(QueryPosition::parse("RULE"), None);
    assert_eq!(QueryPosition::parse("hunt"), None);
    assert_eq!(QueryPosition::default(), QueryPosition::Search);
}
