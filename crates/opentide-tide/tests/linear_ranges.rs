//! Placing many findings or hints of one object stays linear: the object's
//! analysis and its inlay hints convert them through one line table
//! (`opentide_core::with_line_index`), never by a scan of the object from its
//! start each. The guards count the scans, not time.

use opentide_core::scans_from_the_start;
use opentide_tide::{AnalyzeInput, analyze, index_object, inlay_hints};

const RULE: &str = include_str!(
    "../../testdata/workspaces/falco/objects/rules/terminal-shell-in-container-ci-runners-excluded.yaml"
);

/// The rule with `n` more exceptions, all named as its first: each repeat is
/// Falco's "Multiple definitions of exception" finding.
fn rule_with_repeated_exceptions(n: usize) -> String {
    let one = "    - name: build_namespaces\n      fields: k8s.ns.name\n      comps: in\n      values: [ci, builds]\n";
    RULE.replacen(
        "    exceptions:\n",
        &format!("    exceptions:\n{}", one.repeat(n)),
        1,
    )
}

#[test]
fn many_exception_findings_are_placed_through_one_table() {
    let n = 300;
    let source = rule_with_repeated_exceptions(n);
    let before = scans_from_the_start();
    let result = analyze(AnalyzeInput {
        path: "objects/rules/rule.yaml",
        source: &source,
        elastic_tenants: &[],
    });
    assert_eq!(
        scans_from_the_start(),
        before,
        "a finding was placed by a scan"
    );
    let repeats = result
        .diagnostics
        .iter()
        .filter(|d| d.message.contains("Multiple definitions of exception"))
        .count();
    assert!(repeats >= n, "{repeats} repeated-exception findings");
}

#[test]
fn many_inlay_hints_are_placed_through_one_table() {
    let target = index_object("objects/rules/target.yaml", RULE).expect("the fixture indexes");
    let uuid = target.uuid.clone();
    let n = 500;
    let source = format!("name: x\nrelated:\n{}", format!("  - {uuid}\n").repeat(n));
    let before = scans_from_the_start();
    let hints = inlay_hints(&source, &[target]);
    assert_eq!(
        scans_from_the_start(),
        before,
        "a hint was placed by a scan"
    );
    assert_eq!(hints.len(), n);
    assert_eq!(hints[n - 1].position.line, u32::try_from(n + 1).unwrap());
}
