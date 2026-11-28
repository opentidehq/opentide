//! Converting many findings to LSP ranges stays linear: the analysis converts
//! them through one line table (`opentide_core::with_line_index`), never by
//! a scan of the text from its start per finding, which made one with
//! thousands of findings take seconds. The guard counts the scans, not time.

#![expect(
    clippy::string_slice,
    reason = "a test: a slice off a char boundary panics, and a panic is a failed test"
)]

use opentide_core::scans_from_the_start;

fn findings_without_a_scan(source: &str) -> usize {
    let before = scans_from_the_start();
    let result = opentide_falco::analyze(source);
    assert_eq!(
        scans_from_the_start(),
        before,
        "a finding of `{}…` was converted by a scan from the start",
        &source[..30]
    );
    result.diagnostics.len()
}

#[test]
fn many_findings_are_converted_through_one_table() {
    for source in [
        format!("{}a", "a and not ".repeat(500)),
        format!("{}a", "a and not\n".repeat(500)),
    ] {
        let findings = findings_without_a_scan(&source);
        assert!(
            findings >= 500,
            "{findings} findings on `{}…`",
            &source[..30]
        );
    }
}

#[test]
fn many_output_findings_are_converted_through_one_table() {
    let source = "%proc.nmae ".repeat(500);
    let before = scans_from_the_start();
    let findings = opentide_falco::analyze_output(&source, &opentide_falco::Context::default())
        .diagnostics
        .len();
    assert_eq!(
        scans_from_the_start(),
        before,
        "a finding was converted by a scan"
    );
    assert!(findings >= 500, "{findings} findings");
}
