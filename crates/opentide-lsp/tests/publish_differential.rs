//! The diagnostics a server reports after a run of edits, against a server
//! started on the edited texts (#2122): what an edit checks again, and what
//! it keeps from the last check, changes no published byte.

#![expect(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers outside #[test] functions: a panic fails the test"
)]

mod common;

use std::collections::BTreeMap;

use common::*;
use serde_json::{Value, json};

const RULE: &str = "crates/testdata/objects/rules/rule-1.0.yaml";
const OBJECTIVE: &str = "crates/testdata/objects/objective-1.0.yaml";
const MODEL: &str = "00000000-0000-4000-8002-000000000001";
const UUID: &str = "00000000-0000-4000-8003-000000000001";
/// More rules than the files a run looks for one by one before it makes a
/// table of every file (eight).
const RULES: usize = 20;

/// A repository file with LF line endings: Git on Windows checks the
/// fixtures out with CRLF (`core.autocrlf`), and the tests edit them by
/// their `\n`-terminated lines.
fn fixture(path: &str) -> String {
    std::fs::read_to_string(repo_root().join(path))
        .unwrap()
        .replace("\r\n", "\n")
}

fn uuid(n: usize) -> String {
    format!("00000000-0000-4000-8003-0000000003{n:02}")
}

/// Rule `n`: its own UUID and a name with text outside ASCII.
fn rule(n: usize) -> String {
    fixture(RULE).replace(UUID, &uuid(n)).replacen(
        "name: Sentinel KQL Rule",
        &format!("name: Règle é😀 {n}"),
        1,
    )
}

/// A workspace of twenty rules and the objective, and the URIs of the two
/// rules the tests open: rule 0, and rule 1, which they edit.
fn workspace(name: &str) -> (Scratch, String, String) {
    let scratch = Scratch::new(name);
    let objects = scratch.0.join("objects");
    std::fs::create_dir_all(objects.join("rules")).unwrap();
    std::fs::create_dir_all(objects.join("objectives")).unwrap();
    std::fs::write(
        objects.join("objectives/objective-1.0.yaml"),
        fixture(OBJECTIVE),
    )
    .unwrap();
    for n in 0..RULES {
        std::fs::write(objects.join(format!("rules/rule-{n}.yaml")), rule(n)).unwrap();
    }
    let other = file_uri(&objects.join("rules/rule-0.yaml"));
    let edited = file_uri(&objects.join("rules/rule-1.yaml"));
    (scratch, other, edited)
}

/// The texts the two open rules are edited to, one step after another,
/// `(rule 0, rule 1)`: rule 1's text outside ASCII, a reference that names no
/// object, its name made rule 0's, its UUID made rule 0's, YAML that does
/// not load, nothing, and itself again; then both rules' descriptions in one
/// batch, and rule 1's reference again, each an edit the workspace makes in
/// its index in place.
fn steps() -> Vec<(String, String)> {
    let base = rule(1);
    let described = |text: String| text.replace("Minimal valid", "Une règle minimale é😀");
    let mut steps: Vec<(String, String)> = [
        described(base.clone()),
        base.replace(MODEL, "00000000-0000-4000-8002-0000000000ff"),
        base.replacen("name: Règle é😀 1", "name: Règle é😀 0", 1),
        base.replace(&uuid(1), &uuid(0)),
        base.replacen("name: Règle é😀 1", "name: [", 1),
        String::new(),
        base.clone(),
    ]
    .into_iter()
    .map(|text| (rule(0), text))
    .collect();
    steps.push((described(rule(0)), described(base.clone())));
    steps.push((
        described(rule(0)),
        described(base).replace(MODEL, "00000000-0000-4000-8002-0000000000ff"),
    ));
    steps
}

/// Sends the step's texts as edits, each document's only if it changes.
fn edit(lsp: &mut Lsp, uris: [&str; 2], texts: [&str; 2], before: &mut [String; 2]) {
    for ((uri, text), was) in uris.iter().zip(texts).zip(before.iter_mut()) {
        if *was != text {
            change(lsp, uri, text);
            text.clone_into(was);
        }
    }
}

fn start(params: &Value) -> Lsp {
    let mut lsp = Lsp::spawn();
    lsp.request("initialize", params.clone());
    lsp.notify("initialized", json!({}));
    lsp
}

fn open(lsp: &mut Lsp, uri: &str, text: &str) {
    lsp.notify(
        "textDocument/didOpen",
        json!({ "textDocument": { "uri": uri, "languageId": "opentide-yaml", "version": 1, "text": text } }),
    );
}

fn change(lsp: &mut Lsp, uri: &str, text: &str) {
    lsp.notify(
        "textDocument/didChange",
        json!({ "textDocument": { "uri": uri }, "contentChanges": [{ "text": text }] }),
    );
}

/// Reads until the server has handled everything sent so far, keeping into
/// `last` the body of each document's latest `publishDiagnostics`, as the
/// server wrote it. A batch's notifications follow its answers, so a second
/// request, sent once the first is answered, is in a later batch.
fn settle(lsp: &mut Lsp, last: &mut BTreeMap<String, Vec<u8>>) {
    for _ in 0..2 {
        let id = lsp.next_id;
        lsp.next_id += 1;
        lsp.write(&json!({ "jsonrpc": "2.0", "id": id, "method": "opentide/__stats" }));
        loop {
            let frame = lsp.read_frame();
            let message: Value = serde_json::from_slice(&frame).unwrap();
            if message["method"] == "textDocument/publishDiagnostics" {
                let uri = message["params"]["uri"].as_str().unwrap().to_owned();
                last.insert(uri, frame);
            } else if message["id"] == id && message.get("method").is_none() {
                break;
            }
        }
    }
}

/// The codes of the diagnostics a `publishDiagnostics` frame holds.
fn codes(frame: &[u8]) -> Vec<String> {
    let message: Value = serde_json::from_slice(frame).unwrap();
    codes_of(message["params"]["diagnostics"].as_array().unwrap())
}

/// Two open rules among twenty; the second is edited step by step
/// ([`steps`]). After each step, what the server published last for each
/// open rule is, byte for byte, what a server started on the same texts
/// publishes.
#[test]
fn diagnostics_published_after_edits_equal_a_fresh_server_s() {
    let (scratch, other, edited) = workspace("publish-differential");
    // With a file watcher, what an edit does not change is kept across
    // batches. Without `versionSupport`, a publish carries no version (the
    // two servers' differ).
    let params = json!({
        "capabilities": { "workspace": { "didChangeWatchedFiles": { "dynamicRegistration": true } } },
        "rootUri": file_uri(&scratch.0),
    });
    let mut kept = start(&params);
    let mut published = BTreeMap::new();
    open(&mut kept, &other, &rule(0));
    open(&mut kept, &edited, &rule(1));
    settle(&mut kept, &mut published);
    let mut seen: Vec<BTreeMap<String, Vec<String>>> = Vec::new();
    let mut texts = [rule(0), rule(1)];
    for (step, (other_text, text)) in steps().iter().enumerate() {
        edit(
            &mut kept,
            [&other, &edited],
            [other_text.as_str(), text.as_str()],
            &mut texts,
        );
        settle(&mut kept, &mut published);

        let mut fresh = start(&params);
        let mut opened = BTreeMap::new();
        open(&mut fresh, &other, other_text);
        open(&mut fresh, &edited, text);
        settle(&mut fresh, &mut opened);
        let mut now = BTreeMap::new();
        for uri in [&other, &edited] {
            let (Some(after), Some(from_scratch)) = (published.get(uri), opened.get(uri)) else {
                panic!("step {step}: no diagnostics published for {uri}");
            };
            assert_eq!(
                String::from_utf8_lossy(after),
                String::from_utf8_lossy(from_scratch),
                "step {step}: {uri}, after the edits and on a fresh server"
            );
            now.insert(uri.clone(), codes(after));
        }
        seen.push(now);
    }
    // The steps reached what they are about: the reference, the UUID used
    // twice, the YAML that does not load.
    let has = |step: usize, code: &str| seen[step][&edited].iter().any(|c| c == code);
    assert!(has(1, "invalid_ref"), "{seen:?}");
    assert!(has(3, "duplicate_id"), "{seen:?}");
    assert!(has(4, "yaml_parse"), "{seen:?}");
    assert!(!has(6, "duplicate_id"), "{seen:?}");
    assert!(!has(7, "invalid_ref"), "{seen:?}");
    assert!(has(8, "invalid_ref"), "{seen:?}");
}

/// Each closed file's diagnostics in a `workspace/diagnostic` report, and
/// each of `open`'s in its `textDocument/diagnostic` report, as JSON text:
/// the `resultId`s, which count the server's own runs, left out.
fn pulled(lsp: &mut Lsp, open: &[&str]) -> BTreeMap<String, String> {
    let report = lsp.request("workspace/diagnostic", json!({ "previousResultIds": [] }));
    let mut found: BTreeMap<String, String> = report["result"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| {
            (
                item["uri"].as_str().unwrap().to_owned(),
                serde_json::to_string(&item["items"]).unwrap(),
            )
        })
        .collect();
    for uri in open {
        let report = lsp.request(
            "textDocument/diagnostic",
            json!({ "textDocument": { "uri": uri } }),
        );
        found.insert(
            (*uri).to_owned(),
            serde_json::to_string(&report["result"]["items"]).unwrap(),
        );
    }
    found
}

/// For a client that pulls, the findings of every object are kept across
/// edits and only what an edit changed is checked again: after each step
/// ([`steps`]), each file's diagnostics in the workspace's report are the
/// ones a server started on the same texts reports.
#[test]
fn workspace_diagnostics_pulled_after_edits_equal_a_fresh_server_s() {
    let (scratch, other, edited) = workspace("pull-differential");
    let params = json!({
        "capabilities": {
            "textDocument": { "diagnostic": { "dynamicRegistration": false } },
            "workspace": {
                "diagnostics": { "refreshSupport": true },
                "didChangeWatchedFiles": { "dynamicRegistration": true }
            }
        },
        "rootUri": file_uri(&scratch.0),
    });
    let mut kept = start(&params);
    open(&mut kept, &other, &rule(0));
    open(&mut kept, &edited, &rule(1));
    let open_rules = [other.as_str(), edited.as_str()];
    // Every rule and the objective.
    let first = pulled(&mut kept, &open_rules);
    assert_eq!(first.len(), RULES + 1, "{first:#?}");
    let mut texts = [rule(0), rule(1)];
    for (step, (other_text, text)) in steps().iter().enumerate() {
        edit(
            &mut kept,
            open_rules,
            [other_text.as_str(), text.as_str()],
            &mut texts,
        );
        let after = pulled(&mut kept, &open_rules);

        let mut fresh = start(&params);
        open(&mut fresh, &other, other_text);
        open(&mut fresh, &edited, text);
        assert_eq!(
            after,
            pulled(&mut fresh, &open_rules),
            "step {step}: the report after the edits and a fresh server's"
        );
    }
}
