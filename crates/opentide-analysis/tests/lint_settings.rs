//! Conformance (#214): the Tide checks follow `.opentide/configurations/lint.toml`
//! as `opentide lint` does. `crates/testdata/conformance/lint-toml/opentide-lint.json`
//! is what `opentide lint` reports for that workspace, in the engine's codes
//! (`scripts/engine/opentide_lint_findings.py` records it); the engine, given the same
//! `lint.toml`, must report exactly those filename and metadata findings.
//!
//! The lint settings are process-wide, as the declared datasets are, so the
//! tests of this binary take turns.

use opentide_analysis::{AnalyzeRequest, MemoryWorkspace, Severity, analyze, install_lint};
use opentide_core::LanguageId;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

const CASE: &str = "crates/testdata/conformance/lint-toml";
const CODES: [&str; 4] = [
    "filename_slug",
    "filename_pattern",
    "missing_author",
    "missing_organisation",
];

static SETTINGS: Mutex<()> = Mutex::new(());

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(CASE)
}

fn object_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            object_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "yaml") {
            out.push(path);
        }
    }
}

/// `(file relative to the case, code)` for every filename and metadata
/// finding the engine reports on the case's objects.
fn engine_findings() -> BTreeSet<(String, String)> {
    let root = root();
    let mut paths = Vec::new();
    object_files(&root.join("objects"), &mut paths);
    let host = MemoryWorkspace {
        files: paths
            .iter()
            .map(|p| (p.display().to_string(), fs::read_to_string(p).unwrap()))
            .collect(),
    };
    let mut found = BTreeSet::new();
    for (uri, text) in &host.files {
        let relative = Path::new(uri)
            .strip_prefix(&root)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        let response = analyze(
            &host,
            AnalyzeRequest {
                uri: uri.clone(),
                language: LanguageId::TideYaml,
                text: text.clone(),
            },
        );
        for d in response.diagnostics {
            if CODES.contains(&d.code.as_str()) {
                found.insert((relative.clone(), d.code));
            }
        }
    }
    found
}

fn oracle() -> BTreeSet<(String, String)> {
    let text = fs::read_to_string(root().join("opentide-lint.json")).unwrap();
    let document: serde_json::Value = serde_json::from_str(&text).unwrap();
    document["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| {
            (
                f["file"].as_str().unwrap().to_string(),
                f["code"].as_str().unwrap().to_string(),
            )
        })
        .collect()
}

fn lint_toml() -> String {
    fs::read_to_string(root().join(".opentide/configurations/lint.toml")).unwrap()
}

#[test]
fn the_engine_reports_what_opentide_lint_reports() {
    let _turn = SETTINGS.lock().unwrap_or_else(|p| p.into_inner());
    install_lint(Some(&lint_toml())).unwrap();
    let found = engine_findings();
    install_lint(None).unwrap();
    assert_eq!(found, oracle());
}

#[test]
fn without_lint_toml_the_defaults_still_apply() {
    let _turn = SETTINGS.lock().unwrap_or_else(|p| p.into_inner());
    install_lint(None).unwrap();
    let found = engine_findings();
    // `opentide lint`'s defaults: slug filenames, author and organisation.
    let organisation = found
        .iter()
        .filter(|(_, code)| code == "missing_organisation")
        .count();
    assert_eq!(organisation, 5, "{found:?}");
    assert!(found.contains(&(
        "objects/rules/[SEN]Example rule.yaml".into(),
        "filename_slug".into()
    )));
    assert!(!found.iter().any(|(_, code)| code == "filename_pattern"));
}

#[test]
fn a_check_lint_toml_disables_is_not_reported() {
    let _turn = SETTINGS.lock().unwrap_or_else(|p| p.into_inner());
    install_lint(Some(
        "[filenames]\nenabled = false\n[metadata]\nenabled = false\n",
    ))
    .unwrap();
    let found = engine_findings();
    install_lint(None).unwrap();
    assert!(found.is_empty(), "{found:?}");
}

#[test]
fn a_check_severity_replaces_the_findings() {
    let _turn = SETTINGS.lock().unwrap_or_else(|p| p.into_inner());
    install_lint(Some("[metadata]\nseverity = \"info\"\n")).unwrap();
    let root = root();
    let path = root.join("objects/objectives/O-0001.yaml");
    let text = fs::read_to_string(&path).unwrap();
    let host = MemoryWorkspace {
        files: vec![(path.display().to_string(), text.clone())],
    };
    let response = analyze(
        &host,
        AnalyzeRequest {
            uri: path.display().to_string(),
            language: LanguageId::TideYaml,
            text,
        },
    );
    install_lint(None).unwrap();
    let missing: Vec<_> = response
        .diagnostics
        .iter()
        .filter(|d| d.code.starts_with("missing_"))
        .collect();
    assert_eq!(missing.len(), 2, "{missing:?}");
    assert!(missing.iter().all(|d| d.severity == Severity::Information));
}

#[test]
fn text_that_is_not_toml_is_an_error() {
    let _turn = SETTINGS.lock().unwrap_or_else(|p| p.into_inner());
    assert!(install_lint(Some("[filenames")).is_err());
    assert!(opentide_analysis::check_lint("[metadata]\nrequired = []\n").is_ok());
}
