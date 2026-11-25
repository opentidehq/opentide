//! A Google SecOps block's YARA-L sections in a Tide object, through
//! `analyze_queries` (`docs/engine/YARAL.md` "In Tide objects"): the sections
//! are checked as the one rule deploy assembles, each finding on its own
//! section's line, and a hunt with `system: google_secops` as a search.

#![expect(
    clippy::unwrap_used,
    reason = "test helpers outside #[test] functions: a panic fails the test"
)]

use std::path::PathBuf;

use opentide_core::{LanguageId, Severity};
use opentide_tide::analyze_queries;

fn spec(name: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../testdata/conformance/specifications-google-secops")
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
fn the_spec_rule_is_one_clean_rule_of_yaral_sections() {
    let source = spec("rule-google-secops-process-1.0.yaml");
    let queries = analyze_queries(&source, &[]);
    let sections: Vec<String> = queries
        .iter()
        .filter(|q| q.query.language == LanguageId::Yaral)
        .map(|q| q.query.field_path.join("."))
        .collect();
    assert_eq!(
        sections,
        [
            "configurations.google_secops.events",
            "configurations.google_secops.outcome",
            "configurations.google_secops.condition"
        ]
    );
    let errors: Vec<_> = queries
        .iter()
        .flat_map(|q| &q.diagnostics)
        .filter(|d| d.severity == Severity::Error)
        .collect();
    assert!(errors.is_empty(), "{errors:?}");
    // Each section's text is highlighted.
    assert!(queries.iter().all(|q| !q.tokens.is_empty()));
}

#[test]
fn a_finding_lands_on_its_sections_line_in_the_file() {
    let source = spec("rule-google-secops-process-1.0.yaml").replace(
        "$e.target.process.command_line = ",
        "$e.target.process.command_lin = ",
    );
    let line = source
        .lines()
        .position(|l| l.contains("command_lin ="))
        .unwrap();
    let found = findings(&source);
    assert!(
        found.iter().any(
            |(path, code, at)| path == "configurations.google_secops.events"
                && code.starts_with("yaral_")
                && *at as usize == line
        ),
        "line {line}: {found:?}"
    );
}

#[test]
fn a_hunt_is_a_search() {
    let source = "name: r\nresponse:\n  procedure:\n    searches:\n    - purpose: p\n      \
                  system: google_secops\n      query: |\n        metadata.event_type = \
                  \"USER_LOGIN\"\n        limit: 10\n";
    let queries = analyze_queries(source, &[]);
    assert_eq!(queries.len(), 1);
    assert_eq!(queries[0].query.language, LanguageId::Yaral);
    assert_eq!(queries[0].query.platform, "google_secops");
    // `limit` is a search section, which a rule could not use.
    assert!(
        queries[0]
            .diagnostics
            .iter()
            .all(|d| d.code != "yaral_section_unavailable"),
        "{:?}",
        queries[0].diagnostics
    );
    let rule_only = source.replace("limit: 10", "options:\n          allow_zero_values = true");
    let found = findings(&rule_only);
    assert!(
        found
            .iter()
            .any(|(_, code, _)| code == "yaral_section_unavailable"),
        "{found:?}"
    );
}
