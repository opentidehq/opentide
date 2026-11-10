//! The golden recordings (`tests/golden/cases`) as the generation tests read
//! them: a fixture laid out as `cargo xtask golden record` lays it out
//! (`xtask/src/golden/fixture.rs`), and the files a recorded case wrote.

#![allow(dead_code, reason = "each test binary uses part of the helpers")]

use std::collections::BTreeMap;
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

/// The case directory of `id` (`<command>/<mode>/<fixture>/<variant>`).
pub fn case(id: &str) -> PathBuf {
    repo().join("tests/golden/cases").join(id)
}

/// The recorded exit code and every file the case created or modified under
/// `ws/`, by path relative to the workspace, with its bytes.
pub fn recorded(id: &str) -> (i64, BTreeMap<String, Vec<u8>>) {
    let dir = case(id);
    let outcome: toml::Table = std::fs::read_to_string(dir.join("outcome.toml"))
        .unwrap()
        .parse()
        .unwrap();
    let mut files = BTreeMap::new();
    for entry in outcome
        .get("files")
        .and_then(|files| files.as_array())
        .into_iter()
        .flatten()
    {
        let path = entry["path"].as_str().unwrap();
        if entry["kind"].as_str() != Some("file") || entry["change"].as_str() == Some("deleted") {
            continue;
        }
        let Some(relative) = path.strip_prefix("ws/") else {
            continue;
        };
        let bytes = match entry.get("blob").and_then(|blob| blob.as_str()) {
            Some(blob) => std::fs::read(repo().join("tests/golden/blobs").join(blob)).unwrap(),
            None => std::fs::read(dir.join("files").join(path)).unwrap(),
        };
        files.insert(relative.to_owned(), bytes);
    }
    (outcome["exit_code"].as_integer().unwrap(), files)
}
