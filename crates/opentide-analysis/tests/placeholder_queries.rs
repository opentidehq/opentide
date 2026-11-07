//! A query `opentide new` left as a placeholder (`...` under a key marked
//! `# opentide:placeholder`) is not checked, in any query language, as
//! `opentide validate` skips it (opentidehq/language-server#207). The same
//! `...` without the marker, or a query written under a forgotten marker, is
//! checked.

use opentide_analysis::{AnalyzeRequest, MemoryWorkspace, analyze, analyze_queries};
use opentide_core::{Diagnostic, LanguageId};

const MARKER: &str = "  # opentide:placeholder";

const HEAD: &str = r#"name: First Fresh Rule
metadata:
  uuid: 00000000-0000-4000-8003-000000000207
  schema: rule::1.0
  version: 1
  created: "2026-11-04"
  modified: "2026-11-04"
  tlp: clear
description: |  # opentide:placeholder
  ...
detection_model: 00000000-0000-4000-8002-000000000001
"#;

/// `(name, YAML after the head with `{marker}` where opentide new puts the
/// marker, path of the placeholder query)`.
const CASES: &[(&str, &str, &str)] = &[
    (
        "sentinel",
        "configurations:\n  sentinel:\n    query: |{marker}\n      ...\n",
        "configurations.sentinel.query",
    ),
    (
        "defender",
        "configurations:\n  defender_for_endpoint:\n    query: |{marker}\n      ...\n",
        "configurations.defender_for_endpoint.query",
    ),
    (
        "splunk",
        "configurations:\n  splunk:\n    query: |{marker}\n      ...\n",
        "configurations.splunk.query",
    ),
    (
        "carbon black",
        "configurations:\n  carbon_black_cloud:\n    query: |{marker}\n      ...\n",
        "configurations.carbon_black_cloud.query",
    ),
    (
        "elastic kuery",
        "configurations:\n  elastic:\n    type: query\n    language: kuery\n    query: |{marker}\n      ...\n",
        "configurations.elastic.query",
    ),
    (
        "elastic lucene",
        "configurations:\n  elastic:\n    type: query\n    language: lucene\n    query: |{marker}\n      ...\n",
        "configurations.elastic.query",
    ),
    (
        "elastic eql",
        "configurations:\n  elastic:\n    type: eql\n    query: |{marker}\n      ...\n",
        "configurations.elastic.query",
    ),
    (
        "elastic esql",
        "configurations:\n  elastic:\n    type: esql\n    query: |{marker}\n      ...\n",
        "configurations.elastic.query",
    ),
    (
        "sysdig",
        "configurations:\n  sysdig:\n    source: syscall\n    condition: |{marker}\n      ...\n",
        "configurations.sysdig.condition",
    ),
    (
        "elastic threat",
        "configurations:\n  elastic:\n    type: threat_match\n    language: kuery\n    query: 'host.name: *'\n    threat:\n      language: kuery\n      query: |{marker}\n        ...\n",
        "configurations.elastic.threat.query",
    ),
    (
        "sysdig output",
        "configurations:\n  sysdig:\n    source: syscall\n    condition: spawned_process\n    output: |{marker}\n      ...\n",
        "configurations.sysdig.output",
    ),
    (
        "hunt",
        "response:\n  procedure:\n    searches:\n      - system: sentinel\n        query: |{marker}\n          ...\n",
        "response.procedure.searches.0.query",
    ),
    (
        "inline",
        "configurations:\n  sentinel:\n    query: ...{marker}\n",
        "configurations.sentinel.query",
    ),
];

fn rule(body: &str, marker: &str) -> String {
    format!("{HEAD}{}", body.replace("{marker}", marker))
}

fn diagnostics(text: &str) -> Vec<Diagnostic> {
    let uri = "objects/rules/first-fresh-rule.yaml";
    let host = MemoryWorkspace {
        files: vec![(uri.into(), text.to_string())],
    };
    analyze(
        &host,
        AnalyzeRequest {
            uri: uri.into(),
            language: LanguageId::TideYaml,
            text: text.to_string(),
        },
    )
    .diagnostics
}

/// The diagnostics of the query at `path`.
fn in_query(text: &str, path: &str) -> Vec<String> {
    diagnostics(text)
        .into_iter()
        .filter(|d| d.field_path.as_ref().is_some_and(|p| p.join(".") == path))
        .map(|d| format!("{:?} {} at {:?}", d.severity, d.code, d.range))
        .collect()
}

#[test]
fn a_placeholder_query_is_not_checked_in_any_language() {
    for (name, body, path) in CASES {
        let text = rule(body, MARKER);
        assert_eq!(
            in_query(&text, path),
            Vec::<String>::new(),
            "{name}:\n{text}"
        );
        let host = MemoryWorkspace { files: Vec::new() };
        let reports = analyze_queries(&host, &text);
        let report = reports
            .iter()
            .find(|r| r.field_path.join(".") == *path)
            .unwrap_or_else(|| panic!("{name}: the placeholder query is still a query"));
        assert!(
            report.diagnostics.is_empty(),
            "{name}: {:?}",
            report.diagnostics
        );
    }
}

#[test]
fn the_same_stand_in_without_the_marker_is_checked() {
    for (name, body, path) in CASES {
        let text = rule(body, "");
        let found = in_query(&text, path);
        // SPL, Carbon Black and Elastic Lucene take `...` as a search term,
        // and a Falco output as text.
        let accepted = matches!(
            *name,
            "splunk" | "carbon black" | "elastic lucene" | "sysdig output"
        );
        assert_eq!(found.is_empty(), accepted, "{name}: {found:?}\n{text}");
    }
}

#[test]
fn a_query_written_under_a_forgotten_marker_is_checked() {
    let text = rule(
        "configurations:\n  sentinel:\n    query: |{marker}\n      SecurityEvent\n      | frobnicate EventID\n",
        MARKER,
    );
    let found = in_query(&text, "configurations.sentinel.query");
    assert!(
        found.iter().any(|d| d.contains("kql_unknown_operator")),
        "{found:?}"
    );
}

#[test]
fn a_marker_two_lines_above_the_stand_in_does_not_count() {
    // opentide reads the marker on the query's first line or the line above
    // it: a blank line between the key and `...` leaves the query checked.
    let text = rule(
        "configurations:\n  sentinel:\n    query: |{marker}\n\n      ...\n",
        MARKER,
    );
    let found = in_query(&text, "configurations.sentinel.query");
    assert!(
        found.iter().any(|d| d.contains("kql_parse_error")),
        "{found:?}"
    );
}
