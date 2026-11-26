//! Datadog's own published queries (`crates/testdata/conformance/external/datadog/`, RFC §11):
//! every query is checked under profile `rule` (or `search`, for Observability Pipelines
//! examples, `context: op`), and none gets an error but the reasoned exceptions of
//! `EXCEPTIONS.toml`. The count of each code is pinned here and in `docs/engine/DATADOG.md`
//! ("Conformance"), so a change to a check shows as a reviewed change to both.

#![expect(
    clippy::expect_used,
    reason = "test helpers: a panic naming the query is how the test fails"
)]

use std::collections::BTreeMap;

use opentide_core::Severity;
use opentide_datadog::{Profile, findings};

const DIR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../testdata/conformance/external/datadog"
);

/// The findings on the corpus, per code: (findings, queries with one).
const COUNTS: &[(&str, usize, usize)] = &[
    ("datadog_curly_quote", 1, 1),
    ("datadog_full_text_in_rule", 5, 5),
    ("datadog_parse_error", 1, 1),
    ("datadog_pipelines_only", 3, 3),
    ("datadog_range", 1, 1),
    ("datadog_unescaped_colon", 3, 2),
    ("datadog_unescaped_special", 2, 2),
    ("datadog_unknown_attribute", 50, 49),
    ("datadog_wildcard_in_phrase", 3, 3),
];

#[derive(serde::Deserialize)]
struct Exceptions {
    rejected: Vec<Rejected>,
}

#[derive(serde::Deserialize)]
struct Rejected {
    query: String,
    code: String,
    reason: String,
}

struct Row {
    query: String,
    context: String,
}

fn corpus() -> Vec<Row> {
    let text = std::fs::read_to_string(format!("{DIR}/published.jsonl")).expect("published.jsonl");
    text.lines()
        .map(|line| {
            let row: serde_json::Value = serde_json::from_str(line).expect("a JSON line");
            Row {
                query: row["query"].as_str().expect("query").to_owned(),
                context: row["context"].as_str().expect("context").to_owned(),
            }
        })
        .collect()
}

fn profile(row: &Row) -> Profile {
    if row.context == "op" {
        Profile::Search
    } else {
        Profile::Rule
    }
}

#[test]
fn the_corpus_is_the_vendored_one() {
    assert_eq!(corpus().len(), 2_895);
}

#[test]
fn no_published_query_gets_an_error_but_the_listed_exceptions() {
    let text = std::fs::read_to_string(format!("{DIR}/EXCEPTIONS.toml")).expect("EXCEPTIONS.toml");
    let exceptions: Exceptions = toml::from_str(&text).expect("EXCEPTIONS.toml is TOML");
    let mut unexplained = Vec::new();
    let mut seen = vec![false; exceptions.rejected.len()];
    for row in corpus() {
        for finding in findings(&row.query, profile(&row)) {
            if finding.severity != Severity::Error {
                continue;
            }
            match exceptions
                .rejected
                .iter()
                .position(|e| e.query == row.query && e.code == finding.code)
            {
                Some(i) => seen[i] = true,
                None => unexplained.push(format!(
                    "{} on {:?}: {}",
                    finding.code, row.query, finding.message
                )),
            }
        }
    }
    assert!(
        unexplained.is_empty(),
        "errors on published queries, not in EXCEPTIONS.toml:\n  {}",
        unexplained.join("\n  ")
    );
    let stale: Vec<&str> = exceptions
        .rejected
        .iter()
        .zip(&seen)
        .filter(|(_, seen)| !**seen)
        .map(|(e, _)| e.query.as_str())
        .collect();
    assert!(
        stale.is_empty(),
        "EXCEPTIONS.toml entries no longer rejected: {stale:?}"
    );
    assert!(exceptions.rejected.iter().all(|e| !e.reason.is_empty()));
}

#[test]
fn the_count_of_each_code_is_pinned() {
    let mut counts: BTreeMap<&str, (usize, usize)> = BTreeMap::new();
    for row in corpus() {
        let found = findings(&row.query, profile(&row));
        let mut codes: Vec<&str> = found.iter().map(|f| f.code).collect();
        for code in &codes {
            counts.entry(code).or_default().0 += 1;
        }
        codes.sort_unstable();
        codes.dedup();
        for code in codes {
            counts.entry(code).or_default().1 += 1;
        }
    }
    let actual: Vec<(&str, usize, usize)> = counts
        .into_iter()
        .map(|(code, (findings, queries))| (code, findings, queries))
        .collect();
    assert_eq!(
        actual, COUNTS,
        "the findings on Datadog's published queries changed: update COUNTS and \
         docs/engine/DATADOG.md (Conformance) after reading the difference"
    );
}
