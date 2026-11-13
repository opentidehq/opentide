//! Public YARA rules (ReversingLabs, MIT; signature-base, DRL 1.1), each
//! file unmodified, plus a twin with one injected fault.
//!
//! Sources and licences: `crates/testdata/conformance/external/SOURCES.md`. The
//! files are written by `scripts/engine/sync_yara_corpus.py`. libyara 4.5 and
//! YARA-X 1.x compile every public file without a warning, so the engine
//! must report nothing under either dialect. libyara refuses every twin, so
//! the engine must report an error.

#![expect(
    clippy::unwrap_used,
    reason = "test helpers outside #[test] functions: a panic fails the test"
)]

use opentide_core::Severity;
use opentide_yara::{Context, Dialect, analyze_with};
use std::fs;
use std::path::PathBuf;

/// `(source, file name, text, broken twin)`.
fn corpus() -> Vec<(String, String, String, String)> {
    let root =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../testdata/conformance/external/yara");
    let mut out = Vec::new();
    for dir in fs::read_dir(&root).unwrap() {
        let dir = dir.unwrap().path();
        let source = dir.file_name().unwrap().to_string_lossy().into_owned();
        for entry in fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            if name.contains(".broken.") {
                continue;
            }
            let (stem, ext) = name.rsplit_once('.').unwrap();
            let text = fs::read_to_string(&path).unwrap();
            let broken = fs::read_to_string(dir.join(format!("{stem}.broken.{ext}")))
                .unwrap_or_else(|_| panic!("{source}/{name} has no broken twin"));
            out.push((source.clone(), name, text, broken));
        }
    }
    out.sort();
    out
}

#[test]
fn every_public_rule_file_is_clean() {
    let corpus = corpus();
    assert!(corpus.len() >= 50, "{} files", corpus.len());
    for source in ["reversinglabs", "signature-base"] {
        assert!(corpus.iter().any(|(s, ..)| s == source), "no {source} file");
    }
    for (source, name, text, _) in &corpus {
        for dialect in [Dialect::Libyara4, Dialect::YaraX] {
            let ctx = Context {
                dialect,
                profile: None,
            };
            let found = analyze_with(text, &ctx).diagnostics;
            assert!(
                found.is_empty(),
                "{source}/{name} ({dialect:?}): {:?}",
                found
                    .iter()
                    .map(|d| (d.code.as_str(), d.message.as_str()))
                    .collect::<Vec<_>>()
            );
        }
    }
}

#[test]
fn every_broken_twin_is_an_error() {
    for (source, name, _, broken) in corpus() {
        let found = analyze_with(&broken, &Context::default()).diagnostics;
        assert!(
            found.iter().any(|d| d.severity == Severity::Error),
            "{source}/{name}: the broken twin got {:?}",
            found.iter().map(|d| d.code.as_str()).collect::<Vec<_>>()
        );
    }
}
