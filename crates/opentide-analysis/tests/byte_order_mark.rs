//! A Tide document that starts with a UTF-8 byte-order mark (`EF BB BF`) is
//! analysed as the same document without it, at the same lines and columns:
//! an editor neither shows the mark nor counts it as a column
//! (opentidehq/language-server#150).

use opentide_analysis::{
    AnalyzeRequest, MemoryWorkspace, analyze, analyze_queries, completions, hover, index_workspace,
};
use opentide_core::{LanguageId, Position, codes};

const BOM: &str = "\u{feff}";

/// The first line carries a finding of its own (`unknown_key` is not a rule
/// field) and non-ASCII text, so a column the mark shifted would show.
const RULE: &str = r#"unknown_key: é😀 x
name: BOM Rule
metadata:
  uuid: 00000000-0000-4000-8003-000000000150
  schema: rule::1.0
  version: 1
  created: "2026-01-01"
  modified: "2026-01-02"
  tlp: clear
description: |
  A rule saved with a byte-order mark.
status: STAGING
severity: High
techniques:
  - T1059
detection_model: 00000000-0000-4000-8002-000000000001
response:
  alert_severity: High
configurations:
  sentinel:
    enabled: true
    name: BOM Rule
    status: STAGING
    query: |
      SecurityEvent
      | frobnicate EventID
      | where EventID == 4688
"#;

fn with_bom() -> String {
    format!("{BOM}{RULE}")
}

fn tide_diagnostics(text: &str) -> Vec<(String, u32, u32, u32, u32)> {
    let host = MemoryWorkspace {
        files: vec![("objects/rules/bom.yaml".into(), text.to_string())],
    };
    let mut out: Vec<_> = analyze(
        &host,
        AnalyzeRequest {
            uri: "objects/rules/bom.yaml".into(),
            language: LanguageId::TideYaml,
            text: text.to_string(),
        },
    )
    .diagnostics
    .into_iter()
    .map(|d| {
        (
            d.code,
            d.range.start.line,
            d.range.start.character,
            d.range.end.line,
            d.range.end.character,
        )
    })
    .collect();
    out.sort();
    out
}

#[test]
fn a_bom_rule_reports_the_same_findings_at_the_same_places() {
    let plain = tide_diagnostics(RULE);
    assert!(
        plain
            .iter()
            .any(|(code, line, ..)| code == codes::KQL_UNKNOWN_OPERATOR && *line == 25),
        "{plain:?}"
    );
    assert!(plain.iter().any(|(_, line, ..)| *line == 0), "{plain:?}");
    assert_eq!(tide_diagnostics(&with_bom()), plain);
}

#[test]
fn a_bom_rule_still_has_its_queries() {
    let host = MemoryWorkspace::default();
    let plain = analyze_queries(&host, RULE);
    let bom = analyze_queries(&host, &with_bom());
    assert_eq!(plain.len(), 1);
    assert_eq!(bom.len(), 1);
    assert_eq!(bom[0].field_path, plain[0].field_path);
    assert_eq!(bom[0].range, plain[0].range);
    let ranges = |reports: &[opentide_analysis::QueryReport]| {
        reports[0]
            .diagnostics
            .iter()
            .map(|d| (d.code.clone(), d.range))
            .collect::<Vec<_>>()
    };
    assert!(
        ranges(&plain)
            .iter()
            .any(|(code, _)| code == codes::KQL_UNKNOWN_OPERATOR)
    );
    assert_eq!(ranges(&bom), ranges(&plain));
}

#[test]
fn a_bom_rule_is_indexed() {
    let host = MemoryWorkspace {
        files: vec![("objects/rules/bom.yaml".into(), with_bom())],
    };
    let index = index_workspace(&host);
    assert_eq!(index.len(), 1);
    assert_eq!(index[0].uuid, "00000000-0000-4000-8003-000000000150");
}

#[test]
fn hover_and_completion_work_in_a_bom_rule() {
    let host = MemoryWorkspace::default();
    // `SecurityEvent` on line 24, as the editor counts it (no column for the mark).
    let at = Position::new(24, 8);
    let plain = hover(&host, LanguageId::TideYaml, RULE, at);
    assert!(
        plain
            .as_deref()
            .is_some_and(|h| h.contains("SecurityEvent")),
        "{plain:?}"
    );
    assert_eq!(hover(&host, LanguageId::TideYaml, &with_bom(), at), plain);

    // Completion after `| where ` on line 26, by byte offset into each text.
    let cursor = RULE.find("| where ").unwrap() + "| where ".len();
    let labels = |text: &str, offset: usize| {
        completions(&host, LanguageId::TideYaml, text, offset)
            .into_iter()
            .map(|item| item.label)
            .collect::<Vec<_>>()
    };
    let plain = labels(RULE, cursor);
    assert!(plain.iter().any(|l| l == "EventID"), "{plain:?}");
    assert_eq!(labels(&with_bom(), cursor + BOM.len()), plain);
}

/// The mark sits right before the first key: `configurations` must still be
/// `configurations`, not a key whose name starts with U+FEFF.
#[test]
fn a_bom_before_the_query_block_keeps_the_query() {
    let rule = "configurations:\n  sentinel:\n    query: |\n      SecurityEvent | frobnicate\n";
    let host = MemoryWorkspace::default();
    let plain = analyze_queries(&host, rule);
    assert_eq!(plain.len(), 1);
    let bom = analyze_queries(&host, &format!("{BOM}{rule}"));
    assert_eq!(bom.len(), 1);
    assert_eq!(bom[0].range, plain[0].range);
    let ranges = |r: &opentide_analysis::QueryReport| {
        r.diagnostics
            .iter()
            .map(|d| (d.code.clone(), d.range))
            .collect::<Vec<_>>()
    };
    assert_eq!(ranges(&bom[0]), ranges(&plain[0]));
}
