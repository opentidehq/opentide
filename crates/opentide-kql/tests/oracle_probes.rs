//! The probes in `testdata/oracles/kql/` without the Kusto.Language oracle: each
//! is a valid detection form, so the Sentinel profile reports no error on it, and
//! each `.broken.` twin is a syntax error. CI's oracle job checks the same files
//! against Kusto.Language (`scripts/oracles/README.md`).

use std::fs;
use std::path::PathBuf;

use opentide_core::{Severity, codes};
use opentide_kql::{Profile, analyze};

#[test]
fn kql_probes_parse_and_broken_twins_do_not() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/oracles/kql");
    let mut paths: Vec<PathBuf> = fs::read_dir(&dir)
        .expect("testdata/oracles/kql")
        .map(|entry| entry.expect("entry").path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "kql"))
        .collect();
    paths.sort();
    assert!(!paths.is_empty());
    let mut failures = Vec::new();
    for path in &paths {
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        let source = fs::read_to_string(path).expect("probe");
        let diagnostics = analyze(&source, Profile::Sentinel).diagnostics;
        if name.contains(".broken.") {
            if !diagnostics.iter().any(|d| d.code == codes::KQL_PARSE_ERROR) {
                failures.push(format!("{name}: broken twin parses"));
            }
        } else {
            for d in diagnostics.iter().filter(|d| d.severity == Severity::Error) {
                failures.push(format!("{name}: {} {}", d.code, d.message));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
