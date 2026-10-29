//! Declared Elastic index patterns and data views (#116, tiers 2 and 3) and
//! `ecs_indices`, through `install_catalog`. One test: the declared datasets
//! are process-wide.

use opentide_analysis::{
    AnalyzeRequest, Catalog, Diagnostic, LanguageId, MemoryWorkspace, QueryRequest, Severity,
    analyze, analyze_queries, analyze_query, codes, install_catalog,
};

const DATASETS: &str = r#"{"opentide": "0.20.0", "platforms": {
    "elastic": {
        "indices": ["logs-*", "winlogbeat-x", "custom-ecs-*"],
        "data_views": ["security-solution-default"],
        "ecs_indices": ["custom-ecs-*"]
    }
}}"#;

fn esql(text: &str) -> Vec<Diagnostic> {
    analyze_query(&QueryRequest {
        language: LanguageId::Esql,
        platform: None,
        stack: None,
        text: text.into(),
    })
}

fn tide(block: &str) -> (String, Vec<Diagnostic>) {
    let source = format!(
        "name: Dataset rule\nmetadata:\n  uuid: 00000000-0000-4000-8003-000000000001\n  schema: rule::1.0\nconfigurations:\n  elastic:\n{block}"
    );
    let found = analyze(
        &MemoryWorkspace::default(),
        AnalyzeRequest {
            uri: "objects/rules/dataset-rule.yaml".into(),
            language: LanguageId::TideYaml,
            text: source.clone(),
        },
    )
    .diagnostics;
    (source, found)
}

fn codes_of<'a>(found: &'a [Diagnostic], code: &str) -> Vec<&'a Diagnostic> {
    found.iter().filter(|d| d.code == code).collect()
}

fn install(datasets: Option<&str>) {
    install_catalog(&Catalog {
        datasets: datasets.map(str::to_string),
        ..Catalog::default()
    })
    .unwrap();
}

#[test]
fn declared_index_patterns_and_data_views() {
    let undeclared = codes::ELASTIC_DATASET_NOT_DECLARED;
    let rule = "    type: query\n    index:\n      - logs-azure.signinlogs-*\n      - filebeat-*\n    query: event.action:x\n";

    // Nothing declared: today's behaviour, no warning.
    install(None);
    assert!(codes_of(&tide(rule).1, undeclared).is_empty());
    assert!(codes_of(&esql("FROM filebeat-* | LIMIT 1"), undeclared).is_empty());
    // Declaring another platform's datasets is no opt-in for Elastic.
    install(Some(
        r#"{"platforms": {"sentinel": {"tables": ["SigninLogs"]}}}"#,
    ));
    assert!(codes_of(&tide(rule).1, undeclared).is_empty());

    install(Some(DATASETS));

    // `logs-*` covers `logs-azure.signinlogs-*`; `filebeat-*` warns, on its
    // own list item.
    let (source, found) = tide(rule);
    let warned = codes_of(&found, undeclared);
    assert_eq!(warned.len(), 1, "{found:?}");
    assert_eq!(warned[0].severity, Severity::Warning);
    assert!(warned[0].message.contains("filebeat-*"));
    let line = source
        .lines()
        .position(|l| l.contains("- filebeat-*"))
        .unwrap() as u32;
    assert_eq!(warned[0].range.start.line, line);
    assert_eq!(
        warned[0].field_path.as_deref(),
        Some(
            &[
                "configurations".to_string(),
                "elastic".into(),
                "index".into()
            ][..]
        )
    );

    // Data views: declared or not.
    let (_, found) = tide(
        "    type: query\n    data_view_id: security-solution-default\n    query: event.action:x\n",
    );
    assert!(codes_of(&found, undeclared).is_empty(), "{found:?}");
    let (_, found) =
        tide("    type: query\n    data_view_id: my-view\n    query: event.action:x\n");
    assert_eq!(codes_of(&found, undeclared).len(), 1, "{found:?}");

    // The indicator index of a threat-match rule.
    let (_, found) = tide(
        "    type: threat_match\n    index: [logs-*]\n    query: x:y\n    threat:\n      index: [filebeat-ti-*]\n      query: x:y\n",
    );
    assert_eq!(codes_of(&found, undeclared).len(), 1, "{found:?}");

    // ES|QL `FROM`: a used pattern reaching a declared name is declared.
    assert!(codes_of(&esql("FROM logs-*, win* | LIMIT 1"), undeclared).is_empty());
    let found = esql("FROM logs-*, filebeat-* | LIMIT 1");
    let warned = codes_of(&found, undeclared);
    assert_eq!(warned.len(), 1, "{found:?}");
    assert_eq!(warned[0].range.start.character, 13);

    // `ecs_indices`: a declared ECS index gets the field checks; a pattern
    // that only reaches it does not.
    let mismatch = |found: &[Diagnostic]| !codes_of(found, codes::ECS_TYPE_MISMATCH).is_empty();
    assert!(mismatch(&esql(
        "FROM custom-ecs-prod | WHERE source.ip LIKE \"10.*\""
    )));
    assert!(!mismatch(&esql(
        "FROM custom-* | WHERE source.ip LIKE \"10.*\""
    )));
    let (_, found) =
        tide("    type: query\n    index: [custom-ecs-*]\n    query: source.ip:10.*\n");
    assert!(mismatch(&found), "{found:?}");

    // The query report opentide validate reads has the block's warnings too.
    let (source, _) = tide(rule);
    let reports = analyze_queries(&MemoryWorkspace::default(), &source);
    let elastic = reports
        .iter()
        .find(|r| r.field_path == ["configurations", "elastic", "query"])
        .expect("elastic query");
    assert_eq!(
        codes_of(&elastic.diagnostics, undeclared).len(),
        1,
        "{reports:?}"
    );

    install(None);
}
