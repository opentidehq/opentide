//! `spl_search_operator` on the fixtures in `testdata/conformance/lint/`,
//! as raw `.spl` files and inside a Tide rule's splunk block (#136).
//!
//! Splunk 10.6.1's parser accepts every fixture but `search-operator-tstats.spl`
//! (`WHERE clause is not an exact query`). The fixtures are not in the oracle
//! corpus yet: the SPL grammar still reports `spl_parse_error` on these
//! operators.

use opentide_analysis::{AnalyzeRequest, MemoryWorkspace, analyze};
use opentide_core::{Diagnostic, LanguageId, Severity, codes};
use std::path::PathBuf;

fn lint_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/conformance/lint")
}

fn search_operators(
    uri: &str,
    language: LanguageId,
    text: &str,
    files: Vec<(String, String)>,
) -> Vec<Diagnostic> {
    let host = MemoryWorkspace { files };
    analyze(
        &host,
        AnalyzeRequest {
            uri: uri.into(),
            language,
            text: text.into(),
        },
    )
    .diagnostics
    .into_iter()
    .filter(|d| d.code == codes::SPL_SEARCH_OPERATOR)
    .collect()
}

#[test]
fn every_lint_fixture_reports_its_operator_once() {
    let mut fixtures: Vec<PathBuf> = std::fs::read_dir(lint_dir())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "spl"))
        .collect();
    fixtures.sort();
    assert!(fixtures.len() >= 12, "{fixtures:?}");
    for path in fixtures {
        let text = std::fs::read_to_string(&path).unwrap();
        let found = search_operators("memory.spl", LanguageId::Spl, &text, Vec::new());
        assert_eq!(found.len(), 1, "{}: {found:?}", path.display());
        assert_eq!(found[0].severity, Severity::Error, "{}", path.display());
    }
}

#[test]
fn a_splunk_block_reports_the_operator_on_its_field_path() {
    let yaml = "\
name: Search Operator

metadata:
  uuid: 00000000-0000-4000-8003-000000000136
  schema: rule::1.0
  version: 1
  created: \"2026-01-01\"
  modified: \"2026-01-02\"
  tlp: clear
  author: analyst
  organisation: opentide

description: |
  A comparison search does not have.
status: STAGING
severity: High
techniques:
  - T1059
detection_model: 00000000-0000-4000-8002-000000000001

response:
  alert_severity: High

configurations:
  splunk:
    enabled: true
    name: Search Operator
    status: STAGING
    search: |
      index=main | search status==200 | where code==1
    cron_schedule: \"0 * * * *\"
";
    let uri = "search-operator.rule.yaml";
    let found = search_operators(
        uri,
        LanguageId::TideYaml,
        yaml,
        vec![(uri.into(), yaml.into())],
    );
    assert_eq!(found.len(), 1, "{found:?}");
    let d = &found[0];
    assert_eq!(d.severity, Severity::Error);
    assert_eq!(d.suggestion.as_deref(), Some("="));
    assert_eq!(
        d.field_path.as_deref(),
        Some(
            [
                "configurations".to_string(),
                "splunk".into(),
                "search".into()
            ]
            .as_slice()
        )
    );
    // The range is the operator itself, on the query's line.
    let line = yaml.lines().nth(d.range.start.line as usize).unwrap();
    let start = d.range.start.character as usize;
    let end = d.range.end.character as usize;
    assert_eq!(&line[start..end], "==", "{line}");
}
