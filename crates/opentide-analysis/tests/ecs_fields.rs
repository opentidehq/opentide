//! ECS field checks (#116) through the public entry points: a raw ES|QL file
//! reads its indices from `FROM`; a raw kuery, Lucene, or EQL file has none,
//! so it gets no ECS check; inside a Tide rule the elastic block's `index`
//! (or `threat.index`) decides. No datasets are installed here: `logs-*`
//! data streams are ECS without a declaration.

use opentide_analysis::{
    AnalyzeRequest, Diagnostic, LanguageId, MemoryWorkspace, QueryRequest, Severity, analyze,
    analyze_queries, analyze_query, codes,
};

fn raw(language: LanguageId, text: &str) -> Vec<Diagnostic> {
    analyze_query(&QueryRequest {
        language,
        platform: None,
        stack: None,
        text: text.into(),
    })
}

fn rule(block: &str) -> String {
    format!(
        "name: ECS rule\nmetadata:\n  uuid: 00000000-0000-4000-8003-000000000001\n  schema: rule::1.0\nconfigurations:\n  elastic:\n{block}"
    )
}

fn tide(source: &str) -> Vec<Diagnostic> {
    let host = MemoryWorkspace::default();
    analyze(
        &host,
        AnalyzeRequest {
            uri: "objects/rules/ecs-rule.yaml".into(),
            language: LanguageId::TideYaml,
            text: source.into(),
        },
    )
    .diagnostics
}

fn ecs(found: &[Diagnostic]) -> Vec<(&str, Severity)> {
    found
        .iter()
        .filter(|d| d.code.starts_with("ecs_"))
        .map(|d| (d.code.as_str(), d.severity))
        .collect()
}

#[test]
fn raw_esql_reads_its_indices_from_from() {
    let found = raw(
        LanguageId::Esql,
        "FROM logs-* | WHERE source.ip LIKE \"10.*\"",
    );
    assert_eq!(
        ecs(&found),
        vec![(codes::ECS_TYPE_MISMATCH, Severity::Error)],
        "{found:?}"
    );
    let found = raw(
        LanguageId::Esql,
        "FROM winlogbeat-* | WHERE source.ip LIKE \"10.*\"",
    );
    assert!(ecs(&found).is_empty(), "{found:?}");
}

#[test]
fn raw_queries_without_indices_are_not_checked() {
    for (language, text) in [
        (LanguageId::Kuery, "source.ip: 10.* and process.nmae: x"),
        (LanguageId::Lucene, "source.ip:10.* AND process.nmae:x"),
        (LanguageId::Eql, "process where process.pid like \"4*\""),
    ] {
        let found = raw(language, text);
        assert!(ecs(&found).is_empty(), "{text}: {found:?}");
    }
}

#[test]
fn a_kuery_rule_on_logs_indices() {
    let source = rule(
        "    type: query\n    language: kuery\n    index: [logs-endpoint.events.*]\n    query: source.ip:10.* and process.nmae:cmd.exe\n",
    );
    let found = tide(&source);
    let mismatch = found
        .iter()
        .find(|d| d.code == codes::ECS_TYPE_MISMATCH)
        .expect("ecs_type_mismatch");
    assert_eq!(mismatch.severity, Severity::Error);
    // The range is in the object file: the `10.*` on the query line.
    let line = source.lines().position(|l| l.contains("query: ")).unwrap() as u32;
    let column = source
        .lines()
        .nth(line as usize)
        .unwrap()
        .find("10.*")
        .unwrap() as u32;
    assert_eq!(
        (mismatch.range.start.line, mismatch.range.start.character),
        (line, column)
    );
    assert_eq!(
        mismatch.field_path.as_deref(),
        Some(
            &[
                "configurations".to_string(),
                "elastic".into(),
                "query".into()
            ][..]
        )
    );
    let unknown = found
        .iter()
        .find(|d| d.code == codes::ECS_UNKNOWN_FIELD)
        .expect("ecs_unknown_field");
    assert_eq!(unknown.severity, Severity::Warning);
    assert_eq!(unknown.suggestion.as_deref(), Some("process.name"));
}

#[test]
fn only_when_every_index_is_ecs() {
    for block in [
        // A non-ECS pattern mixed in.
        "    type: query\n    index: [logs-*, winlogbeat-*]\n    query: source.ip:10.*\n",
        // A data view: its fields are Kibana's.
        "    type: query\n    index: [logs-*]\n    data_view_id: security-solution-default\n    query: source.ip:10.*\n",
        // No index: the tenant's `setup.index`, unknown here.
        "    type: query\n    query: source.ip:10.*\n",
    ] {
        let found = tide(&rule(block));
        assert!(ecs(&found).is_empty(), "{block}: {found:?}");
    }
}

#[test]
fn lucene_eql_and_indicator_queries() {
    let lucene = rule(
        "    type: query\n    language: lucene\n    index:\n      - logs-*\n    query: process.pid:12*\n",
    );
    assert_eq!(
        ecs(&tide(&lucene)),
        vec![(codes::ECS_TYPE_MISMATCH, Severity::Error)]
    );

    let eql = rule(
        "    type: eql\n    index: [logs-*]\n    query: |\n      network where cidrMatch(source.address, \"10.0.0.0/8\")\n",
    );
    let found = tide(&eql);
    assert_eq!(
        ecs(&found),
        vec![(codes::ECS_TYPE_MISMATCH, Severity::Error)],
        "{found:?}"
    );
    // The engine's own hint gives way to the error.
    assert!(
        !found
            .iter()
            .any(|d| d.code == codes::EQL_ARGUMENT_TYPE && d.severity == Severity::Hint),
        "{found:?}"
    );

    // `threat.query` reads `threat.index`; `query` reads `index`.
    let threat = rule(
        "    type: threat_match\n    index: [winlogbeat-*]\n    query: source.ip:10.*\n    threat:\n      index: [logs-ti_*]\n      query: threat.indicator.ip:10.*\n",
    );
    let found = tide(&threat);
    let mismatches: Vec<&Diagnostic> = found
        .iter()
        .filter(|d| d.code == codes::ECS_TYPE_MISMATCH)
        .collect();
    assert_eq!(mismatches.len(), 1, "{found:?}");
    assert!(
        mismatches[0]
            .field_path
            .as_ref()
            .is_some_and(|p| p.iter().any(|s| s == "threat")),
        "{mismatches:?}"
    );
}

#[test]
fn analyze_queries_reports_them_too() {
    let source =
        rule("    type: esql\n    query: |\n      FROM logs-* | WHERE source.ip LIKE \"10.*\"\n");
    let host = MemoryWorkspace::default();
    let reports = analyze_queries(&host, &source);
    assert_eq!(reports.len(), 1);
    assert_eq!(
        ecs(&reports[0].diagnostics),
        vec![(codes::ECS_TYPE_MISMATCH, Severity::Error)]
    );
    let source = rule("    type: query\n    index: [logs-*]\n    query: process.nmae:x\n");
    let reports = analyze_queries(&host, &source);
    assert_eq!(
        ecs(&reports[0].diagnostics),
        vec![(codes::ECS_UNKNOWN_FIELD, Severity::Warning)]
    );
}
