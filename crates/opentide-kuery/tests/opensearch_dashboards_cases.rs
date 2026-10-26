//! KQL query strings from OpenSearch Dashboards' kuery tests (Apache-2.0,
//! forked from Kibana 7.10.2), with the verdict each test expects. Kibana's
//! current grammar agrees on every one. Source, pin, and licence:
//! `testdata/conformance/external/SOURCES.md`.
//!
//! An accepted query must produce no engine error and a rejected one must
//! produce one. Each accepted query with a `:` outside quotes also gets a
//! fault twin, its first such `:` turned into `:)`, which must error.

use opentide_core::Severity;
use std::path::PathBuf;

/// Disagreements with the reason; empty while the engine agrees.
const EXCEPTIONS: &[(&str, &str)] = &[];

fn json_string(s: &str) -> String {
    let inner = &s[1..s.len() - 1];
    let mut out = String::new();
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('r') => out.push('\r'),
            Some(other) => out.push(other),
            None => {}
        }
    }
    out
}

fn has_error(query: &str) -> bool {
    opentide_kuery::analyze(query)
        .diagnostics
        .iter()
        .any(|d| d.severity == Severity::Error)
}

/// The first `:` outside a quoted string and not escaped, turned into `:)`.
fn fault_twin(query: &str) -> Option<String> {
    let mut in_quotes = false;
    let mut escaped = false;
    for (i, c) in query.char_indices() {
        match c {
            _ if escaped => escaped = false,
            '\\' => escaped = true,
            '"' => in_quotes = !in_quotes,
            ':' if !in_quotes => return Some(format!("{}:){}", &query[..i], &query[i + 1..])),
            _ => {}
        }
    }
    None
}

#[test]
fn opensearch_dashboards_kuery_tests() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/conformance/external/kuery-opensearch-dashboards/cases.tsv");
    let text = std::fs::read_to_string(path).expect("cases.tsv");
    let (mut checked, mut twins) = (0, 0);
    let mut wrong = Vec::new();
    for line in text.lines().filter(|l| !l.starts_with('#')) {
        let mut cols = line.split('\t');
        let (Some(verdict), Some(query), Some(source)) = (cols.next(), cols.next(), cols.next())
        else {
            continue;
        };
        let query = json_string(query);
        if EXCEPTIONS.iter().any(|(q, _)| *q == query) {
            continue;
        }
        checked += 1;
        let errored = has_error(&query);
        match verdict {
            "accept" if errored => wrong.push(format!("accept {query:?} ({source}) errors")),
            "reject" if !errored => wrong.push(format!("reject {query:?} ({source}) passes")),
            "accept" | "reject" => {}
            other => panic!("unknown verdict {other}"),
        }
        if verdict == "accept" {
            if let Some(twin) = fault_twin(&query) {
                twins += 1;
                if !has_error(&twin) {
                    wrong.push(format!("fault twin {twin:?} ({source}) passes"));
                }
            }
        }
    }
    assert!(
        checked >= 60,
        "expected the OpenSearch Dashboards cases, found {checked}"
    );
    assert!(twins >= 10, "expected fault twins, found {twins}");
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}
