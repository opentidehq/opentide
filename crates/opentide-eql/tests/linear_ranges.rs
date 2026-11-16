//! Converting many findings to LSP ranges stays linear: `analyze` converts
//! them through one line table (`opentide_core::with_line_index`), never by
//! a scan of the query from its start per finding, which made a query with
//! thousands of findings take seconds. The guard counts the scans, not time.

use opentide_core::scans_from_the_start;

fn findings_without_a_scan(source: &str) -> usize {
    let before = scans_from_the_start();
    let result = opentide_eql::analyze(source);
    assert_eq!(
        scans_from_the_start(),
        before,
        "a finding of `{}…` was converted by a scan from the start",
        &source[..40]
    );
    result.diagnostics.len()
}

#[test]
fn many_findings_are_converted_through_one_table() {
    let n = 2_000;
    for source in [
        format!("any where {}true", "\"a\" and ".repeat(n)),
        format!("any where {}true", "a[1] and ".repeat(n)),
        format!("any where true {}", "| a ".repeat(n)),
        format!("any where true\n{}", "and \"a\"\n".repeat(n)),
    ] {
        let findings = findings_without_a_scan(&source);
        assert!(
            findings >= 10,
            "{findings} findings on `{}…`",
            &source[..40]
        );
    }
}

#[test]
fn many_ecs_findings_are_converted_through_one_table() {
    let source = format!("any where {}true", "process.nmae == 1 and ".repeat(2_000));
    let before = scans_from_the_start();
    let findings = opentide_eql::ecs_diagnostics(&source).len();
    assert_eq!(
        scans_from_the_start(),
        before,
        "a finding was converted by a scan"
    );
    assert!(findings >= 2_000, "{findings} findings");
}
