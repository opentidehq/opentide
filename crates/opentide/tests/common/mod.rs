//! The workspaces the tests open, laid out under a temporary folder (a test
//! never writes into the checkout).

#![expect(
    clippy::unwrap_used,
    reason = "test helpers: a fixture that does not lay out is a failure"
)]
#![allow(
    dead_code,
    reason = "each test binary uses some of these helpers: an expectation would fail in the others"
)]

use std::path::{Path, PathBuf};

/// The repository's root.
pub fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), target).unwrap();
        }
    }
}

/// `tests/fixtures/tide_corpus/current` (one threat, one objective, ten
/// rules on the nine platforms, every platform enabled) in today's layout:
/// `objects/<family>/` and `.opentide/configurations/`.
pub fn tide_corpus() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let source = repo().join("tests/fixtures/tide_corpus/current");
    copy_tree(
        &source.join("Configurations"),
        &dir.path().join(".opentide/configurations"),
    );
    for (family, legacy) in [
        ("threats", "Objects/Threat Vectors"),
        ("objectives", "Objects/Detection Objectives"),
        ("rules", "Objects/Detection Rules"),
    ] {
        copy_tree(
            &source.join(legacy),
            &dir.path().join("objects").join(family),
        );
    }
    dir
}

/// The UUID of a rule of the corpus: its file's `uuid:` line.
pub fn uuid_of(ws: &Path, rule: &str) -> String {
    let text = std::fs::read_to_string(ws.join("objects/rules").join(rule)).unwrap();
    text.lines()
        .find_map(|line| line.trim().strip_prefix("uuid:"))
        .unwrap()
        .trim()
        .trim_matches('"')
        .to_owned()
}
