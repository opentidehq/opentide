//! Every diagnostic code has a section in opentide's diagnostics reference,
//! which the server's `codeDescription.href` links to
//! (`https://opentide.org/docs/cli/diagnostics/#<code>`, #185 P2.3).
//!
//! The reference is this repository's `docs/cli/diagnostics.md`;
//! `OPENTIDE_DIAGNOSTICS_DOCS` names another copy.

use opentide_core::codes;

#[test]
fn every_code_has_a_section_in_the_diagnostics_reference() {
    let path = std::env::var("OPENTIDE_DIAGNOSTICS_DOCS").unwrap_or_else(|_| {
        concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/cli/diagnostics.md").to_string()
    });
    let text = std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("{path}: {err}"));
    let sections: std::collections::BTreeSet<&str> = text
        .lines()
        .filter_map(|line| line.strip_prefix("## "))
        .map(str::trim)
        .collect();
    let missing: Vec<&str> = codes::ALL
        .iter()
        .copied()
        .filter(|code| !sections.contains(code))
        .collect();
    assert!(
        missing.is_empty(),
        "{path} has no `## <code>` section for: {missing:?}"
    );
}
