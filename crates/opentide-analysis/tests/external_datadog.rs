//! Datadog's published queries (`crates/testdata/conformance/external/datadog/published.jsonl`,
//! sources and licences in `SOURCES.md`) and twins of a sample of them with one injected fault
//! each (`broken.jsonl`: the line of the query it was made from, the fault and the code it must
//! raise). Through `analyze_query` at position `rule` (#1993), as a detection rule's
//! `queries[].query` is checked: the position, never the platform, picks the profile
//! (ADR 0015 §4).
//!
//! Every published query is free of errors but the reasoned exceptions of `EXCEPTIONS.toml`
//! (counted per code by `crates/opentide-datadog/tests/published.rs`); every twin's query is
//! clean before its fault and reports the fault's code after it.

#![expect(
    clippy::expect_used,
    reason = "test helpers outside #[test] functions: a panic fails the test"
)]

use opentide_analysis::{LanguageId, QueryPosition, QueryRequest, Severity, analyze_query_at};

const DIR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../testdata/conformance/external/datadog"
);

fn rule(text: &str) -> Vec<opentide_core::Diagnostic> {
    analyze_query_at(
        &QueryRequest::new(LanguageId::Datadog, text).with_platform(Some("datadog")),
        QueryPosition::Rule,
    )
}

fn errors(text: &str) -> Vec<String> {
    rule(text)
        .into_iter()
        .filter(|d| d.severity == Severity::Error)
        .map(|d| d.code)
        .collect()
}

fn lines(name: &str) -> Vec<serde_json::Value> {
    std::fs::read_to_string(format!("{DIR}/{name}"))
        .expect(name)
        .lines()
        .map(|line| serde_json::from_str(line).expect("a JSON line"))
        .collect()
}

#[test]
fn published_queries_raise_only_the_listed_errors() {
    let published = lines("published.jsonl");
    assert_eq!(published.len(), 2_895);
    let text = std::fs::read_to_string(format!("{DIR}/EXCEPTIONS.toml")).expect("EXCEPTIONS");
    let exceptions: toml::Value = toml::from_str(&text).expect("EXCEPTIONS.toml is TOML");
    let listed: Vec<(&str, &str)> = exceptions["rejected"]
        .as_array()
        .expect("[[rejected]]")
        .iter()
        .map(|e| {
            (
                e["query"].as_str().expect("query"),
                e["code"].as_str().expect("code"),
            )
        })
        .collect();
    let mut rejected = 0;
    for row in &published {
        let query = row["query"].as_str().expect("query");
        for code in errors(query) {
            rejected += 1;
            assert!(
                listed.contains(&(query, code.as_str())),
                "{query:?}: {code}, not in EXCEPTIONS.toml"
            );
        }
    }
    assert_eq!(rejected, 4);
}

#[test]
fn every_broken_twin_reports_its_fault() {
    let published = lines("published.jsonl");
    let twins = lines("broken.jsonl");
    assert!(twins.len() >= 12, "{} twins", twins.len());
    for twin in &twins {
        let line = usize::try_from(twin["line"].as_u64().expect("line")).expect("a line");
        let original = published[line - 1]["query"].as_str().expect("query");
        let broken = twin["query"].as_str().expect("query");
        let code = twin["code"].as_str().expect("code");
        assert!(
            errors(original).is_empty(),
            "line {line}: the original has an error"
        );
        assert!(
            broken.contains(original),
            "line {line}: the twin is not its original with a fault"
        );
        let found = errors(broken);
        assert_eq!(
            found,
            vec![code.to_owned()],
            "{}: {broken:?}",
            twin["fault"]
        );
    }
}
