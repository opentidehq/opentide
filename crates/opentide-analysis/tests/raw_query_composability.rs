//! Raw `.kql` and `.spl` documents are first-class: `analyze` uses an empty Tide
//! workspace and the same engines as Tide `query:` / `search:` injections.

use opentide_analysis::{AnalyzeRequest, AnalyzeResponse, MemoryWorkspace, analyze};
use opentide_core::{Diagnostic, LanguageId, codes};

fn analyze_doc(
    uri: &str,
    language: LanguageId,
    text: &str,
    host: &MemoryWorkspace,
) -> AnalyzeResponse {
    analyze(
        host,
        AnalyzeRequest {
            uri: uri.to_string(),
            language,
            text: text.to_string(),
        },
    )
}

/// Raw query files must ignore Tide objects that happen to sit in the host.
fn analyze_raw(uri: &str, language: LanguageId, text: &str) -> AnalyzeResponse {
    let alone = MemoryWorkspace {
        files: vec![(uri.to_string(), text.to_string())],
    };
    let with_tide = MemoryWorkspace {
        files: vec![
            (uri.to_string(), text.to_string()),
            (
                "objects/rules/unrelated.yaml".into(),
                tide_rule("sentinel", "query", "SecurityEvent | take 1"),
            ),
        ],
    };
    let raw = analyze_doc(uri, language, text, &alone);
    let beside_tide = analyze_doc(uri, language, text, &with_tide);
    assert_eq!(
        raw.diagnostics, beside_tide.diagnostics,
        "{uri} must be analyzed with an empty Tide workspace"
    );
    raw
}

fn tide_rule(platform: &str, key: &str, query: &str) -> String {
    let body = query
        .lines()
        .map(|line| format!("      {line}"))
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "\
name: Composability
metadata:
  uuid: 00000000-0000-4000-8003-000000000099
  schema: rule::1.0
configurations:
  {platform}:
    {key}: |
{body}
"
    )
}

fn operator<'a>(diagnostics: &'a [Diagnostic], code: &str) -> &'a Diagnostic {
    let matches: Vec<_> = diagnostics.iter().filter(|d| d.code == code).collect();
    assert_eq!(
        matches.len(),
        1,
        "expected one {code}, got {:?}",
        diagnostics
            .iter()
            .map(|d| d.code.as_str())
            .collect::<Vec<_>>()
    );
    matches[0]
}

fn assert_same_operator(raw: &Diagnostic, embedded: &Diagnostic) {
    assert_eq!(raw.code, embedded.code);
    assert_eq!(raw.severity, embedded.severity);
    assert_eq!(raw.message, embedded.message);
    assert_eq!(raw.suggestion, embedded.suggestion);
}

#[test]
fn standalone_kql_matches_tide_query_unknown_operator() {
    let query = "SecurityEvent\n| frobnicate x";
    let raw = analyze_raw("queries/broken.kql", LanguageId::Kql, query);
    let raw_op = operator(&raw.diagnostics, codes::KQL_UNKNOWN_OPERATOR);
    assert!(raw_op.message.contains("frobnicate"), "{}", raw_op.message);
    assert!(raw.diagnostics.iter().all(|d| d.code.starts_with("kql_")));

    let yaml = tide_rule("sentinel", "query", query);
    let host = MemoryWorkspace {
        files: vec![("objects/rules/composability-kql.yaml".into(), yaml.clone())],
    };
    let embedded = analyze_doc(
        "objects/rules/composability-kql.yaml",
        LanguageId::TideYaml,
        &yaml,
        &host,
    );
    let embedded_op = operator(&embedded.diagnostics, codes::KQL_UNKNOWN_OPERATOR);
    assert_same_operator(raw_op, embedded_op);
    assert_eq!(
        embedded_op.field_path.as_deref(),
        Some(
            [
                "configurations".to_string(),
                "sentinel".to_string(),
                "query".to_string(),
            ]
            .as_slice()
        )
    );
}

#[test]
fn standalone_spl_matches_tide_query_unknown_command() {
    let query = "index=main\n| notacommand foo=1";
    let raw = analyze_raw("queries/broken.spl", LanguageId::Spl, query);
    let raw_op = operator(&raw.diagnostics, codes::SPL_UNKNOWN_COMMAND);
    assert!(raw_op.message.contains("notacommand"), "{}", raw_op.message);
    // An app on the search head may provide it (#123).
    assert_eq!(raw_op.severity, opentide_core::Severity::Warning);
    assert!(raw.diagnostics.iter().all(|d| d.code.starts_with("spl_")));

    let yaml = tide_rule("splunk", "query", query);
    let host = MemoryWorkspace {
        files: vec![("objects/rules/composability-spl.yaml".into(), yaml.clone())],
    };
    let embedded = analyze_doc(
        "objects/rules/composability-spl.yaml",
        LanguageId::TideYaml,
        &yaml,
        &host,
    );
    let embedded_op = operator(&embedded.diagnostics, codes::SPL_UNKNOWN_COMMAND);
    assert_same_operator(raw_op, embedded_op);
    assert_eq!(
        embedded_op.field_path.as_deref(),
        Some(
            [
                "configurations".to_string(),
                "splunk".to_string(),
                "query".to_string(),
            ]
            .as_slice()
        )
    );
}

#[test]
fn standalone_falco_matches_tide_condition_unknown_field() {
    let query = "spawned_process and proc.nmae = bash";
    let raw = analyze_raw("queries/broken.falco", LanguageId::Falco, query);
    let raw_op = operator(&raw.diagnostics, codes::FALCO_UNKNOWN_FIELD);
    assert!(raw_op.message.contains("proc.nmae"), "{}", raw_op.message);
    assert!(raw.diagnostics.iter().all(|d| d.code.starts_with("falco_")));

    let yaml = tide_rule("sysdig", "condition", query);
    let host = MemoryWorkspace {
        files: vec![(
            "objects/rules/composability-falco.yaml".into(),
            yaml.clone(),
        )],
    };
    let embedded = analyze_doc(
        "objects/rules/composability-falco.yaml",
        LanguageId::TideYaml,
        &yaml,
        &host,
    );
    let embedded_op = operator(&embedded.diagnostics, codes::FALCO_UNKNOWN_FIELD);
    assert_same_operator(raw_op, embedded_op);
    assert_eq!(
        embedded_op.field_path.as_deref(),
        Some(
            [
                "configurations".to_string(),
                "sysdig".to_string(),
                "condition".to_string(),
            ]
            .as_slice()
        )
    );
}

#[test]
fn standalone_cql_matches_tide_crowdstrike_query_unknown_function() {
    let query = "#event_simpleName=ProcessRollup2\n| groupBi([aid, ComputerName])";
    let raw = analyze_raw("queries/broken.cql", LanguageId::Cql, query);
    let raw_op = operator(&raw.diagnostics, codes::CQL_UNKNOWN_FUNCTION);
    assert!(raw_op.message.contains("groupBi"), "{}", raw_op.message);
    assert!(raw.diagnostics.iter().all(|d| d.code.starts_with("cql_")));

    let yaml = tide_rule("crowdstrike", "query", query);
    let host = MemoryWorkspace {
        files: vec![("objects/rules/composability-cql.yaml".into(), yaml.clone())],
    };
    let embedded = analyze_doc(
        "objects/rules/composability-cql.yaml",
        LanguageId::TideYaml,
        &yaml,
        &host,
    );
    let embedded_op = operator(&embedded.diagnostics, codes::CQL_UNKNOWN_FUNCTION);
    assert_same_operator(raw_op, embedded_op);
    assert_eq!(
        embedded_op.field_path.as_deref(),
        Some(
            [
                "configurations".to_string(),
                "crowdstrike".to_string(),
                "query".to_string(),
            ]
            .as_slice()
        )
    );
}

#[test]
fn a_yaral_hunt_is_checked_as_a_search() {
    let query = "metadata.event_type = \"USER_LOGIN\"\n$user = target.user.userid\nmatch:\n  $user\noutcome:\n  $n = avg(metadata.id)\n";
    let raw = opentide_analysis::analyze_query(&opentide_analysis::QueryRequest {
        language: LanguageId::Yaral,
        platform: Some("google_secops".into()),
        stack: None,
        text: query.into(),
    });
    assert!(
        !raw.iter()
            .any(|d| d.code == codes::YARAL_FUNCTION_UNAVAILABLE),
        "avg is a search aggregation: {raw:?}"
    );
}
