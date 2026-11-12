//! The engine against the conformance data of specifications exabeam-1.0
//! (`testdata/conformance/exabeam/`, SOURCES.md): every valid query is clean
//! under its profile, every invalid one reports exactly its code, and the
//! highlight goldens match. The reference checker has no field catalogue, so
//! the two catalogue warnings are compared separately.

use opentide_core::Severity;
use opentide_exabeam::{Context, Profile, analyze_with, check};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const CATALOGUE_CODES: [&str; 2] = ["exabeam_unknown_field", "exabeam_string_field_number"];

fn dir(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/conformance/exabeam")
        .join(name)
}

fn files(name: &str, ext: &str) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = std::fs::read_dir(dir(name))
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.to_string_lossy().ends_with(ext))
        .collect();
    out.sort();
    out
}

fn profile_of(path: &Path) -> Profile {
    let name = path.file_name().unwrap().to_string_lossy();
    let parts: Vec<&str> = name.split('.').collect();
    Profile::parse(parts[parts.len() - 2]).unwrap()
}

fn language_codes(text: &str, profile: Profile) -> BTreeSet<&'static str> {
    check(text, profile)
        .findings
        .iter()
        .map(|f| f.code)
        .filter(|c| !CATALOGUE_CODES.contains(c))
        .collect()
}

#[test]
fn every_valid_query_is_clean() {
    let paths = files("valid", ".exabeam");
    assert!(paths.len() >= 9);
    for path in paths {
        let text = std::fs::read_to_string(&path).unwrap();
        let ctx = Context {
            profile: profile_of(&path),
        };
        let r = analyze_with(&text, &ctx);
        assert!(
            r.diagnostics.is_empty(),
            "{}: {:?}",
            path.display(),
            r.diagnostics
        );
    }
}

#[test]
fn every_invalid_query_reports_exactly_its_code() {
    let paths = files("invalid", ".exabeam");
    let mut covered = BTreeSet::new();
    for path in &paths {
        let text = std::fs::read_to_string(path).unwrap();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        let code = name.split('.').next().unwrap().to_string();
        let codes = language_codes(&text, profile_of(path));
        assert_eq!(
            codes.iter().copied().collect::<Vec<_>>(),
            vec![code.as_str()],
            "{name}"
        );
        covered.insert(code);
    }
    // One per catalogue-free code of the spec.
    let expected: BTreeSet<String> = opentide_core::codes::ALL
        .iter()
        .filter(|c| c.starts_with("exabeam_"))
        .filter(|c| !CATALOGUE_CODES.contains(c))
        .filter(|c| opentide_exabeam::check::LANGUAGE_CODES.contains(c))
        .map(|c| c.to_string())
        .collect();
    assert_eq!(covered, expected);
}

#[test]
fn severities_follow_the_spec() {
    for path in files("invalid", ".exabeam") {
        let text = std::fs::read_to_string(&path).unwrap();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        let code = name.split('.').next().unwrap();
        let r = analyze_with(
            &text,
            &Context {
                profile: profile_of(&path),
            },
        );
        let d = r.diagnostics.iter().find(|d| d.code == code).unwrap();
        let warning = opentide_exabeam::is_warning(code);
        assert_eq!(
            d.severity,
            if warning {
                Severity::Warning
            } else {
                Severity::Error
            },
            "{name}"
        );
    }
}

/// The goldens are the reference checker's tokens; the engine's verdict
/// parser and its tree-sitter highlighting must both produce them.
#[test]
fn highlight_goldens() {
    let paths = files("highlight", ".exabeam");
    assert!(paths.len() >= 3);
    for path in paths {
        let text = std::fs::read_to_string(&path).unwrap();
        let golden: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(path.with_extension("tokens.json")).unwrap(),
        )
        .unwrap();
        let expected: Vec<(usize, usize, String)> = golden
            .as_array()
            .unwrap()
            .iter()
            .map(|t| {
                (
                    t["range"][0].as_u64().unwrap() as usize,
                    t["range"][1].as_u64().unwrap() as usize,
                    t["capture"].as_str().unwrap().to_string(),
                )
            })
            .collect();
        let checked: Vec<(usize, usize, String)> = check(&text, profile_of(&path))
            .tokens
            .iter()
            .map(|t| (t.start, t.end, t.capture.to_string()))
            .collect();
        assert_eq!(checked, expected, "verdict parser, {}", path.display());
        let highlighted: Vec<(usize, usize, String)> = analyze_with(
            &text,
            &Context {
                profile: profile_of(&path),
            },
        )
        .tokens
        .iter()
        .map(|t| (t.span.start, t.span.end, t.capture.clone()))
        .collect();
        assert_eq!(highlighted, expected, "tree-sitter, {}", path.display());
    }
}
