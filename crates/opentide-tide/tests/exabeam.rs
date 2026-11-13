//! An Exabeam block's sequence filters and a `system: exabeam` hunt in a Tide
//! object, through `analyze_queries` (exabeam-1.0): each sequence's `query`
//! is the Exabeam Query Language under the `rule` profile, where Search's
//! advanced operators are refused, and a hunt is a search, the `search`
//! profile, where they are not.

#![expect(
    clippy::unwrap_used,
    reason = "test helpers outside #[test] functions: a panic fails the test"
)]

use std::path::PathBuf;

use opentide_core::{LanguageId, Severity};
use opentide_tide::analyze_queries;

fn fixture(name: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../testdata/conformance/exabeam/objects/valid")
        .join(name);
    std::fs::read_to_string(path).unwrap()
}

/// `(field path, code, 0-based source line)` of every finding.
fn findings(source: &str) -> Vec<(String, String, u32)> {
    analyze_queries(source, &[])
        .into_iter()
        .flat_map(|query| {
            query.diagnostics.into_iter().map(move |d| {
                (
                    d.field_path.unwrap_or_default().join("."),
                    d.code,
                    d.range.start.line,
                )
            })
        })
        .collect()
}

#[test]
fn each_sequence_filter_and_the_hunt_are_exabeam_queries_and_the_spec_rule_is_clean() {
    let source = fixture("rule-exabeam-sequence-1.0.yaml");
    let queries = analyze_queries(&source, &[]);
    let sequences: Vec<(String, String)> = queries
        .iter()
        .filter(|q| q.query.language == LanguageId::Exabeam)
        .map(|q| (q.query.field_path.join("."), q.query.platform.clone()))
        .collect();
    assert_eq!(
        sequences,
        [
            (
                "response.procedure.searches.0.query".to_owned(),
                "exabeam".to_owned()
            ),
            (
                "configurations.exabeam.sequences.0.query".to_owned(),
                "exabeam".to_owned()
            ),
            (
                "configurations.exabeam.sequences.1.query".to_owned(),
                "exabeam".to_owned()
            ),
        ]
    );
    let errors: Vec<_> = queries
        .iter()
        .flat_map(|q| &q.diagnostics)
        .filter(|d| d.severity == Severity::Error)
        .collect();
    assert!(errors.is_empty(), "{errors:?}");
    // Each filter is highlighted.
    assert!(queries.iter().all(|q| !q.tokens.is_empty()));
}

#[test]
fn a_sequence_filter_is_a_rule_query_and_its_finding_lands_on_its_line() {
    let source = "name: r\nconfigurations:\n  exabeam:\n    sequences:\n      - query: \
                  activity_type:\"app-login\"\n      - query: SELECT user WHERE \
                  activity_type:\"app-login\" GROUP-BY user\n    correlation:\n      within: \
                  15m\n";
    let found = findings(source);
    assert_eq!(
        found,
        [(
            "configurations.exabeam.sequences.1.query".to_owned(),
            "exabeam_advanced_in_rule".to_owned(),
            5
        )]
    );
}

#[test]
fn a_hunt_is_a_search() {
    let hunt = |query: &str| {
        format!(
            "name: r\nresponse:\n  procedure:\n    searches:\n    - purpose: p\n      system: \
             exabeam\n      query: '{query}'\n"
        )
    };
    let source =
        hunt("SELECT user, COUNT(*) AS logins WHERE activity_type:\"app-login\" GROUP-BY user");
    let queries = analyze_queries(&source, &[]);
    assert_eq!(queries.len(), 1);
    assert_eq!(queries[0].query.language, LanguageId::Exabeam);
    assert_eq!(queries[0].query.platform, "exabeam");
    // Search takes what a correlation rule refuses.
    assert!(
        queries[0].diagnostics.is_empty(),
        "{:?}",
        queries[0].diagnostics
    );
    // And checks what only a search can get wrong.
    let found = findings(&hunt("Select user WHERE activity_type:\"app-login\""));
    assert!(
        found.iter().any(
            |(path, code, _)| path == "response.procedure.searches.0.query"
                && code == "exabeam_keyword_case"
        ),
        "{found:?}"
    );
}

#[test]
fn a_hunt_spelled_otherwise_is_not_analysed() {
    let source = "name: r\nresponse:\n  procedure:\n    searches:\n    - purpose: p\n      \
                  system: Exabeam\n      query: '*'\n";
    assert!(analyze_queries(source, &[]).is_empty());
}
