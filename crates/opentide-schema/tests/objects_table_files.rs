//! What the object models' oracle table (`src/objects/table.rs`, a unit test
//! that reads nothing from the disk) relies on being true of the repository:
//! `tests/oracle/objects_table.json` holds every object file of
//! `tests/fixtures/tide_corpus` and of the VS Code fixture workspace, each as
//! it is on disk, and every `[[difference]]` of
//! `tests/oracle/objects_cases.toml` and `tests/oracle/platform_cases.toml`
//! has its CHANGELOG.md entry. When one
//! fails, run `objects_table.py` (or write the entry).

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde_json::Value as Json;

const TABLE: &str = include_str!("oracle/objects_table.json");
const CASES: &str = include_str!("oracle/objects_cases.toml");
const PLATFORM_CASES: &str = include_str!("oracle/platform_cases.toml");

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// The table's `file:` cases: (repository path, text the oracle read).
fn files() -> Vec<(String, String)> {
    let Ok(table) = serde_json::from_str::<Json>(TABLE) else {
        panic!("objects_table.json is not JSON: run objects_table.py");
    };
    let Some(cases) = table["cases"].as_array() else {
        panic!("objects_table.json has no cases: run objects_table.py");
    };
    cases
        .iter()
        .filter_map(|case| {
            let path = case["id"].as_str()?.strip_prefix("file:")?;
            Some((path.to_owned(), case["yaml"].as_str()?.to_owned()))
        })
        .collect()
}

#[test]
fn each_corpus_file_in_the_table_is_as_it_is_on_disk() {
    let files = files();
    assert!(!files.is_empty());
    for (path, text) in files {
        let current = std::fs::read_to_string(repo().join(&path))
            .unwrap_or_else(|error| panic!("{path}: {error}; run objects_table.py"));
        // A Windows checkout may write the fixture with CRLF.
        assert_eq!(
            current.replace("\r\n", "\n"),
            text,
            "{path} changed: run objects_table.py"
        );
    }
}

#[test]
fn every_object_file_of_the_corpora_is_in_the_table() {
    let listed: BTreeSet<String> = files().into_iter().map(|(path, _)| path).collect();
    let root = repo();
    let mut found = BTreeSet::new();
    for source in [
        "tests/fixtures/tide_corpus/current/Objects",
        "tests/golden/fixtures/vscode-workspace/objects",
    ] {
        let mut stack = vec![root.join(source)];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).expect("a fixture directory") {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    stack.push(path);
                } else if path.extension().is_some_and(|ext| ext == "yaml") {
                    let relative = path.strip_prefix(&root).unwrap();
                    found.insert(relative.to_string_lossy().replace('\\', "/"));
                }
            }
        }
    }
    assert_eq!(found, listed, "run objects_table.py");
}

#[derive(serde::Deserialize)]
struct Cases {
    difference: Vec<Difference>,
}

#[derive(serde::Deserialize)]
struct Difference {
    id: String,
    changelog: String,
}

#[test]
fn each_difference_has_its_changelog_entry() {
    let changelog = std::fs::read_to_string(repo().join("CHANGELOG.md")).unwrap();
    let mut differences = Vec::new();
    for text in [CASES, PLATFORM_CASES] {
        let cases: Cases = toml::from_str(text).unwrap();
        assert!(!cases.difference.is_empty());
        differences.extend(cases.difference);
    }
    let missing: Vec<String> = differences
        .iter()
        .filter(|difference| !changelog.contains(&difference.changelog))
        .map(|difference| format!("{}: {:?}", difference.id, difference.changelog))
        .collect();
    assert!(missing.is_empty(), "CHANGELOG.md has no {missing:?}");
}
