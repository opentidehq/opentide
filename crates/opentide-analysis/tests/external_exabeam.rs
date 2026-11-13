//! Exabeam queries written for opentide (`crates/testdata/conformance/external/exabeam/`),
//! each with a `.broken.` twin carrying one injected fault. Exabeam's own
//! published rules may not be redistributed (`docs/engine/EXABEAM.md` records the
//! measurement over them), so these are realistic queries of our own,
//! written with the CIM's field names.
//!
//! `FAULTS.toml` names each twin's fault and the code it must report. Every
//! clean query must come out with no finding of any severity under its
//! profile (`.rule.` or `.search.`), as a raw query and through
//! `analyze_query` (`platform: exabeam` is the `rule` profile).

use opentide_analysis::{LanguageId, QueryRequest, analyze_query};
use std::collections::BTreeSet;
use std::path::PathBuf;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../testdata/conformance/external/exabeam")
}

fn request(text: &str, profile: &str) -> QueryRequest {
    QueryRequest {
        language: LanguageId::Exabeam,
        platform: (profile == "rule").then(|| "exabeam".to_string()),
        stack: None,
        text: text.to_string(),
    }
}

#[test]
fn clean_queries_are_clean_and_every_twin_reports_its_fault() {
    let doc: toml::Table = std::fs::read_to_string(root().join("FAULTS.toml"))
        .unwrap()
        .parse()
        .unwrap();
    let entries = doc["query"].as_array().unwrap();
    let mut listed = BTreeSet::new();
    let mut faults = BTreeSet::new();
    for entry in entries {
        let file = entry["file"].as_str().unwrap();
        let profile = entry["profile"].as_str().unwrap();
        let code = entry["code"].as_str().unwrap();
        faults.insert(entry["fault"].as_str().unwrap().to_string());
        listed.insert(file.to_string());
        let clean = std::fs::read_to_string(root().join(file)).unwrap();
        let found = analyze_query(&request(&clean, profile));
        assert!(found.is_empty(), "{file}: {found:?}");
        let twin = file.replace(
            &format!(".{profile}.exabeam"),
            &format!(".broken.{profile}.exabeam"),
        );
        let broken = std::fs::read_to_string(root().join(&twin)).unwrap();
        let found = analyze_query(&request(&broken, profile));
        assert!(
            found.iter().any(|d| d.code == code),
            "{twin}: expected {code}, got {:?}",
            found.iter().map(|d| d.code.as_str()).collect::<Vec<_>>()
        );
    }
    // Every query in the directory is listed, and the faults vary.
    let on_disk: BTreeSet<String> = std::fs::read_dir(root())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".exabeam") && !n.contains(".broken."))
        .collect();
    assert_eq!(on_disk, listed);
    assert!(entries.len() >= 16, "{}", entries.len());
    assert!(faults.len() >= 14, "{faults:?}");
}
