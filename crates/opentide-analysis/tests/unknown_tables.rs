//! A table the Sentinel catalog does not list is a warning, never an error: the
//! engine cannot see the workspace's tables (#111). The Azure Monitor and
//! Defender XDR tables are known (#113).

use opentide_analysis::{AnalyzeRequest, MemoryWorkspace, analyze};
use opentide_core::{Diagnostic, LanguageId, Severity, codes};
use std::path::PathBuf;

fn read(name: &str) -> String {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    std::fs::read_to_string(root.join("testdata/conformance/tables").join(name)).unwrap()
}

fn diagnostics(language: LanguageId, uri: &str, text: String) -> Vec<Diagnostic> {
    let host = MemoryWorkspace {
        files: vec![(uri.into(), text.clone())],
    };
    analyze(
        &host,
        AnalyzeRequest {
            uri: uri.into(),
            language,
            text,
        },
    )
    .diagnostics
}

fn unknown_tables(diagnostics: &[Diagnostic], source: &str) -> Vec<(String, Severity)> {
    diagnostics
        .iter()
        .filter(|d| d.code == codes::KQL_UNKNOWN_TABLE)
        .map(|d| {
            let line = source.lines().nth(d.range.start.line as usize).unwrap();
            let start = d.range.start.character as usize;
            let name: String = line[start..]
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            (name, d.severity)
        })
        .collect()
}

#[test]
fn raw_kql_file_warns_on_tables_the_catalog_does_not_list() {
    let source = read("unknown-tables.kql");
    let found = diagnostics(LanguageId::Kql, "unknown-tables.kql", source.clone());
    assert!(
        found.iter().all(|d| d.severity != Severity::Error),
        "{found:?}"
    );
    assert_eq!(
        unknown_tables(&found, &source),
        vec![
            ("MyCustomLog_CL".into(), Severity::Warning),
            ("VendorFirewallEvents".into(), Severity::Warning),
        ]
    );
}

#[test]
fn tide_query_block_warns_and_still_suggests_a_known_table() {
    let source = read("unknown-tables.rule.yaml");
    let found = diagnostics(
        LanguageId::TideYaml,
        "unknown-tables.rule.yaml",
        source.clone(),
    );
    // The fixture's detection model is not in the workspace; only the query matters here.
    assert!(
        found
            .iter()
            .filter(|d| d.code.starts_with("kql_"))
            .all(|d| d.severity != Severity::Error),
        "{found:?}"
    );
    assert_eq!(
        unknown_tables(&found, &source),
        vec![
            ("MyCustomLog_CL".into(), Severity::Warning),
            ("VendorFirewallEvents".into(), Severity::Warning),
            ("SigninLog".into(), Severity::Warning),
        ]
    );
    let misspelt = found
        .iter()
        .find(|d| d.code == codes::KQL_UNKNOWN_TABLE && d.message.contains("'SigninLog'"))
        .expect("SigninLog");
    assert_eq!(misspelt.suggestion.as_deref(), Some("SigninLogs"));
    assert_eq!(
        misspelt.message,
        "'SigninLog' is not a table opentide knows; if the workspace holds it, declare it in visibility.toml"
    );
}
