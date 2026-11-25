//! The fixtures the generation tests open, laid out as the command line's
//! snapshot harness lays them out (`crates/opentide-cli/tests/common/replay.rs`).

#![allow(dead_code, reason = "each test binary uses part of the helpers")]

use std::path::{Path, PathBuf};

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
            std::fs::copy(entry.path(), &target).unwrap();
        }
    }
}

/// Lays out the fixture `name` at `ws`.
#[cfg(unix)]
pub fn fixture(name: &str, ws: &Path) {
    match name {
        "tide-corpus" => {
            copy_tree(&repo().join("tests/fixtures/tide_corpus/current"), ws);
            copy_tree(
                &ws.join("Configurations"),
                &ws.join(".opentide/configurations"),
            );
            std::fs::create_dir_all(ws.join("objects")).unwrap();
            for (family, legacy) in [
                ("threats", "../Objects/Threat Vectors"),
                ("objectives", "../Objects/Detection Objectives"),
                ("rules", "../Objects/Detection Rules"),
            ] {
                std::os::unix::fs::symlink(legacy, ws.join("objects").join(family)).unwrap();
            }
            for dir in ["schemas", "templates", "exports", "inflight"] {
                std::fs::create_dir_all(ws.join(".opentide").join(dir)).unwrap();
            }
        }
        "vscode" => copy_tree(&repo().join("tests/golden/fixtures/vscode-workspace"), ws),
        other => panic!("{other}: a fixture these tests do not lay out"),
    }
}
