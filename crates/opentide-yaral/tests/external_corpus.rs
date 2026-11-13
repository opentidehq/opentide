//! Public YARA-L rules (chronicle/detection-rules, Apache-2.0), each file
//! unmodified, plus a twin with one injected fault.
//!
//! Sources and licence: `crates/testdata/conformance/external/yaral/SOURCES.md`. The
//! files are written by `scripts/engine/sync_yaral_corpus.py`. Google publishes no
//! offline compiler, so the rules' presence in Google's repository is the
//! evidence that they compile: every public file must parse and have no error,
//! except the findings listed in `EXCEPTIONS`, where yara-l-1.0 and Google's
//! repository disagree (none today). Every twin must get an error.

#![expect(
    clippy::case_sensitive_file_extension_comparisons,
    clippy::unwrap_used,
    reason = "test helpers outside #[test] functions: a panic fails the test"
)]

use opentide_core::{Severity, codes};
use opentide_yaral::analyze;
use std::fs;
use std::path::PathBuf;

/// `(file, code, why)`: errors yara-l-1.0 requires on rules Google ships.
/// None since 1.1, which made `yaral_string_escape` a warning.
const EXCEPTIONS: &[(&str, &str, &str)] = &[];

/// `(file name, text, broken twin)`.
fn corpus() -> Vec<(String, String, String)> {
    let root =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../testdata/conformance/external/yaral");
    let mut out = Vec::new();
    for entry in fs::read_dir(&root).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        if !name.ends_with(".yaral") || name.contains(".broken.") {
            continue;
        }
        let stem = name.trim_end_matches(".yaral");
        let text = fs::read_to_string(&path).unwrap();
        let broken = fs::read_to_string(root.join(format!("{stem}.broken.yaral")))
            .unwrap_or_else(|_| panic!("{name} has no broken twin"));
        out.push((name, text, broken));
    }
    out.sort();
    out
}

#[test]
fn every_public_rule_parses_and_is_clean() {
    let corpus = corpus();
    assert!(corpus.len() >= 50, "{} files", corpus.len());
    for (name, text, _) in &corpus {
        let errors: Vec<_> = analyze(text)
            .diagnostics
            .into_iter()
            .filter(|d| d.severity == Severity::Error)
            .filter(|d| {
                !EXCEPTIONS
                    .iter()
                    .any(|(file, code, _)| file == name && *code == d.code)
            })
            .collect();
        assert!(
            errors.is_empty(),
            "{name}: {:?}",
            errors
                .iter()
                .map(|d| (d.code.as_str(), d.range.start.line + 1, d.message.as_str()))
                .collect::<Vec<_>>()
        );
    }
}

#[test]
fn every_exception_still_applies() {
    let corpus = corpus();
    for (file, code, why) in EXCEPTIONS {
        let (_, text, _) = corpus
            .iter()
            .find(|(n, ..)| n == file)
            .unwrap_or_else(|| panic!("{file} is not in the corpus"));
        assert!(
            analyze(text).diagnostics.iter().any(|d| d.code == *code),
            "{file}: {code} is gone ({why}); drop the exception"
        );
    }
}

#[test]
fn every_broken_twin_is_an_error() {
    for (name, _, broken) in corpus() {
        let found = analyze(&broken).diagnostics;
        assert!(
            found.iter().any(|d| d.severity == Severity::Error),
            "{name}: the broken twin got {:?}",
            found.iter().map(|d| d.code.as_str()).collect::<Vec<_>>()
        );
    }
}

#[test]
fn an_unknown_escape_in_a_community_rule_is_a_warning() {
    // Its meta description writes `\TEMPLATE\LAYOUTS`: yara-l-1.0 1.1 warns.
    let (_, text, _) = corpus()
        .into_iter()
        .find(|(n, ..)| n == "ttp_windows_suspicious_filewrites_to_sharepoint_layouts.yaral")
        .expect("in the corpus");
    let escapes: Vec<_> = analyze(&text)
        .diagnostics
        .into_iter()
        .filter(|d| d.code == codes::YARAL_STRING_ESCAPE)
        .collect();
    assert!(!escapes.is_empty());
    assert!(escapes.iter().all(|d| d.severity == Severity::Warning));
}
