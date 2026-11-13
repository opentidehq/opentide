//! Google's own YARA-L examples (testdata/conformance/google-yaral/,
//! Apache-2.0 code samples): each has exactly the error codes `cases.tsv`
//! gives it under yara-l-1.0 1.1.

use opentide_core::Severity;
use opentide_yaral::{Context, analyze_with};
use std::collections::BTreeSet;
use std::path::PathBuf;

#[test]
fn google_examples_have_their_expected_errors() {
    let root =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/conformance/google-yaral");
    let cases = std::fs::read_to_string(root.join("cases.tsv")).unwrap();
    let mut checked = 0;
    for line in cases
        .lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
    {
        let cols: Vec<&str> = line.split('\t').collect();
        let (file, profile, expected) = (cols[0], cols[1], cols[2]);
        let text = std::fs::read_to_string(root.join(file)).unwrap();
        let ctx = if profile == "search" {
            Context::SEARCH
        } else {
            Context::FILE
        };
        let found: BTreeSet<String> = analyze_with(&text, &ctx)
            .diagnostics
            .into_iter()
            .filter(|d| d.severity == Severity::Error)
            .map(|d| d.code)
            .collect();
        let expected: BTreeSet<String> = if expected == "-" {
            BTreeSet::new()
        } else {
            expected.split(',').map(str::to_string).collect()
        };
        assert_eq!(found, expected, "{file}");
        checked += 1;
    }
    assert!(checked >= 10, "{checked} cases");
}
