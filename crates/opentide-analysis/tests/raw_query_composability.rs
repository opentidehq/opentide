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
