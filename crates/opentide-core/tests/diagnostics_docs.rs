//! Every diagnostic code has a section in opentide's diagnostics reference,
//! which the server's `codeDescription.href` links to
//! (`https://opentide.org/docs/cli/diagnostics/#<code>`, #185 P2.3).
//!
//! `OPENTIDE_DIAGNOSTICS_DOCS` names opentide's `docs/cli/diagnostics.md`;
//! the opentide canary sets it. Without it the test has nothing to check.

use opentide_core::codes;

#[test]
fn every_code_has_a_section_in_the_diagnostics_reference() {
    let Ok(path) = std::env::var("OPENTIDE_DIAGNOSTICS_DOCS") else {
        eprintln!("OPENTIDE_DIAGNOSTICS_DOCS is not set: nothing to check");
        return;
    };
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
