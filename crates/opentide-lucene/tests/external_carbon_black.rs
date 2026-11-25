//! SigmaHQ rules converted to Carbon Black Cloud process search queries by
//! pySigma-backend-carbonblack (`crates/testdata/conformance/external/
//! lucene-carbon-black/`, #162): each parses in the Carbon Black dialect with
//! no error and names no field near a catalog field (the backend writes
//! Carbon Black's own field names), and each `.broken.` twin is diagnosed.

use opentide_core::{Severity, codes};
use opentide_lucene::{Dialect, analyze_dialect};
use std::fs;
use std::path::PathBuf;

#[test]
fn converted_sigma_queries_and_their_twins() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../testdata/conformance/external/lucene-carbon-black");
    let mut checked = 0;
    for entry in fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        if name.contains(".broken.") {
            continue;
        }
        let text = fs::read_to_string(&path).unwrap();
        let found = analyze_dialect(&text, Dialect::CarbonBlack).diagnostics;
        let errors: Vec<_> = found
            .iter()
            .filter(|d| d.severity == Severity::Error)
            .collect();
        assert!(errors.is_empty(), "{name}: {errors:?}");
        let unknown: Vec<_> = found
            .iter()
            .filter(|d| d.code == codes::CBC_UNKNOWN_FIELD)
            .collect();
        assert!(unknown.is_empty(), "{name}: {unknown:?}");
        let broken = fs::read_to_string(dir.join(name.replace(".lucene", ".broken.lucene")))
            .unwrap_or_else(|_| panic!("{name}: no broken twin"));
        let found = analyze_dialect(&broken, Dialect::CarbonBlack).diagnostics;
        assert!(
            found.iter().any(|d| d.severity == Severity::Error),
            "{name}: the twin is not diagnosed"
        );
        checked += 1;
    }
    assert!(checked >= 30, "{checked} queries");
}
