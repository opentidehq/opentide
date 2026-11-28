//! The MCP server keeps its workspace warm between tool calls (#1942): a
//! second call reads no file again, and an edit on disk between two calls is
//! read, alone, by the next one. In a binary of its own: the warm session is
//! the process's, and its counts are this test's only here.

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "a test: a server that does not answer as expected is a failure"
)]

use std::path::{Path, PathBuf};

use opentide_cli::embed::workspace_stats;
use opentide_cli::env::Env;
use opentide_cli::mcp::{Answer, Server};
use serde_json::{Map, Value, json};

const SENTINEL_RULE: &str = "00000000-0000-4000-8003-000000000001";
const RULE_FILE: &str = "objects/rules/rule-0001-sentinel-kql.yaml";

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

/// The CLI end-to-end corpus in the `.opentide/` layout; the number of its
/// object files.
fn corpus(root: &Path) -> (PathBuf, usize) {
    let source =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/tide_corpus/current");
    let ws = root.join("ws");
    copy_tree(
        &source.join("Configurations"),
        &ws.join(".opentide/configurations"),
    );
    let mut objects = 0;
    for (family, folder) in [
        ("threats", "Threat Vectors"),
        ("objectives", "Detection Objectives"),
        ("rules", "Detection Rules"),
    ] {
        let from = source.join("Objects").join(folder);
        objects += std::fs::read_dir(&from).unwrap().count();
        copy_tree(&from, &ws.join("objects").join(family));
    }
    (ws, objects)
}

/// The UUIDs `search` finds for `query`.
fn search(server: &Server, query: &str) -> Vec<String> {
    let arguments: Map<String, Value> = json!({"query": query})
        .as_object()
        .cloned()
        .unwrap_or_default();
    let Answer::Result(result) = server.call("search", &arguments) else {
        panic!("search: not a result");
    };
    assert_eq!(result["isError"], false, "{result}");
    result["structuredContent"]["result"]
        .as_array()
        .expect("a list")
        .iter()
        .filter_map(|hit| hit["uuid"].as_str().map(str::to_owned))
        .collect()
}

#[test]
fn tool_calls_share_one_warm_workspace_and_see_edits_between_them() {
    let scratch = tempfile::tempdir().unwrap();
    let (ws, objects) = corpus(scratch.path());
    let shown = ws.to_string_lossy().into_owned();
    let env = Env::from_pairs([
        ("OPENTIDE_REPO_ROOT", shown.clone()),
        ("OPENTIDE_TIDE_WORKSPACE", shown),
    ]);
    let server = Server::new(env, Some(ws.clone()), None, "1.0.0", None);

    assert!(search(&server, "Sentinel KQL").contains(&SENTINEL_RULE.to_owned()));
    let first = workspace_stats();
    assert_eq!(
        first.kept, 1,
        "the first call keeps its workspace: {first:?}"
    );
    assert_eq!(first.file_reads, objects, "{first:?}");

    // The second call reads nothing again.
    assert!(search(&server, "Sentinel KQL").contains(&SENTINEL_RULE.to_owned()));
    let second = workspace_stats();
    assert_eq!(second.hits, first.hits + 1, "{second:?}");
    assert_eq!(second.refreshes, first.refreshes, "{second:?}");
    assert_eq!(
        second.file_reads, objects,
        "a file was read twice: {second:?}"
    );

    // An edit on disk between two calls is seen by the next, which reads
    // that file alone.
    let rule = ws.join(RULE_FILE);
    let text = std::fs::read_to_string(&rule).unwrap();
    let edited = text.replacen("name: Sentinel KQL Rule", "name: Règle 😀 éditée", 1);
    assert_ne!(edited, text);
    std::fs::write(&rule, edited).unwrap();
    assert_eq!(search(&server, "Règle 😀"), vec![SENTINEL_RULE.to_owned()]);
    let third = workspace_stats();
    assert_eq!(third.refreshes, second.refreshes + 1, "{third:?}");
    assert_eq!(third.file_reads, objects + 1, "{third:?}");
}
