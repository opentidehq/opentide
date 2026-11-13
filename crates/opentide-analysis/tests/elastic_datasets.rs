//! Declared Elastic index patterns (#116, tiers 2 and 3) and their columns
//! (#146), through `install_catalog`. One test: the declared datasets are
//! process-wide.

#![expect(
    clippy::unwrap_used,
    reason = "test helpers outside #[test] functions: a panic fails the test"
)]

use opentide_analysis::{
    AnalyzeRequest, Catalog, Diagnostic, LanguageId, MemoryWorkspace, QueryRequest, Severity,
    analyze, analyze_blocks, analyze_queries, analyze_query, codes, install_catalog,
};

const DATASETS: &str = r#"[[logsources]]
name = "logs-*"
description = "Integration data streams."
system = "elastic"

[[logsources]]
name = "winlogbeat-x"
description = "Winlogbeat."
system = "elastic"

[[logsources]]
name = "logs-custom.app-*"
description = "Custom app."
system = "elastic"

[logsources.columns]
"process.nmae" = { type = "keyword" }
"process.pid" = { type = "keyword" }
"app.score" = { type = "long" }

[[logsources]]
name = "logs-custom.app-prod"
description = "Production custom app."
system = "elastic"

[logsources.columns]
"app.score" = { type = "keyword" }
"#;

fn esql(text: &str) -> Vec<Diagnostic> {
    analyze_query(&QueryRequest {
        language: LanguageId::Esql,
        platform: None,
        stack: None,
        text: text.into(),
    })
}

/// The rule's queries and its platform blocks: the declared datasets are
/// the Elastic block's, which `lint` reports and the editor leaves to it
/// (UC-2.6, #821).
fn tide(block: &str) -> (String, Vec<Diagnostic>) {
    let source = format!(
        "name: Dataset rule\nmetadata:\n  uuid: 00000000-0000-4000-8003-000000000001\n  schema: rule::1.0\nconfigurations:\n  elastic:\n{block}"
    );
    let host = MemoryWorkspace::default();
    let found = analyze(
        &host,
        AnalyzeRequest {
            uri: "objects/rules/dataset-rule.yaml".into(),
            language: LanguageId::TideYaml,
            text: source.clone(),
        },
    )
    .diagnostics
    .into_iter()
    .chain(analyze_blocks(&host, &source))
    .collect();
    (source, found)
}

fn codes_of<'a>(found: &'a [Diagnostic], code: &str) -> Vec<&'a Diagnostic> {
    found.iter().filter(|d| d.code == code).collect()
}

fn install(datasets: Option<&str>) {
    install_catalog(&Catalog {
        visibility: datasets.map(str::to_string),
        ..Catalog::default()
    })
    .unwrap();
}

#[test]
#[expect(
    clippy::cast_possible_truncation,
    reason = "positions in a test document of a few lines"
)]
fn declared_index_patterns_and_their_columns() {
    let undeclared = codes::ELASTIC_DATASET_NOT_DECLARED;
    let rule = "    type: query\n    index:\n      - logs-azure.signinlogs-*\n      - filebeat-*\n    query: event.action:x\n";

    // Nothing declared: today's behaviour, no warning.
    install(None);
    assert!(codes_of(&tide(rule).1, undeclared).is_empty());
    assert!(codes_of(&esql("FROM filebeat-* | LIMIT 1"), undeclared).is_empty());
    // Declaring another platform's datasets is no opt-in for Elastic.
    install(Some(
        r#"[[logsources]]
name = "SigninLogs"
description = "Test log source."
system = "sentinel"
"#,
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

    // Data views are not declarable: a `data_view_id` is never checked.
    let (_, found) =
        tide("    type: query\n    data_view_id: my-view\n    query: event.action:x\n");
    assert!(codes_of(&found, undeclared).is_empty(), "{found:?}");

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

    // ECS checks run on `logs-*` data streams only: declaring an index
    // pattern does not make it ECS.
    let mismatch = |found: &[Diagnostic]| !codes_of(found, codes::ECS_TYPE_MISMATCH).is_empty();
    assert!(mismatch(&esql(
        "FROM logs-endpoint.events.process-default | WHERE source.ip LIKE \"10.*\""
    )));
    assert!(!mismatch(&esql(
        "FROM winlogbeat-x | WHERE source.ip LIKE \"10.*\""
    )));

    // Declared columns are mapped fields of their index pattern: no
    // `ecs_unknown_field`, and their declared type for `ecs_type_mismatch`.
    let unknown = |found: &[Diagnostic]| !codes_of(found, codes::ECS_UNKNOWN_FIELD).is_empty();
    assert!(unknown(&esql(
        "FROM logs-other-default | WHERE process.nmae == \"x\""
    )));
    assert!(!unknown(&esql(
        "FROM logs-custom.app-default | WHERE process.nmae == \"x\""
    )));
    // `process.pid` is a long in ECS, a keyword here.
    assert!(mismatch(&esql(
        "FROM logs-other-default | WHERE process.pid LIKE \"12*\""
    )));
    assert!(!mismatch(&esql(
        "FROM logs-custom.app-default | WHERE process.pid LIKE \"12*\""
    )));
    let found = esql("FROM logs-custom.app-default | WHERE app.score LIKE \"1*\"");
    let mismatched = codes_of(&found, codes::ECS_TYPE_MISMATCH);
    assert_eq!(mismatched.len(), 1, "{found:?}");
    assert!(
        mismatched[0].message.contains("visibility.toml"),
        "{found:?}"
    );
    // An index both an exact log source and a pattern declare gets both's
    // fields; the exact one's type wins.
    assert!(!unknown(&esql(
        "FROM logs-custom.app-prod | WHERE process.nmae == \"x\""
    )));
    assert!(!mismatch(&esql(
        "FROM logs-custom.app-prod | WHERE app.score LIKE \"1*\""
    )));
    let (_, found) =
        tide("    type: query\n    index: [logs-custom.app-*]\n    query: process.nmae:x\n");
    assert!(!unknown(&found), "{found:?}");
    let (_, found) =
        tide("    type: query\n    index: [logs-other-*]\n    query: process.nmae:x\n");
    assert!(unknown(&found), "{found:?}");

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
