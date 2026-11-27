//! The protocol host over stdio (#185 P1–P3): capabilities, batches,
//! cancellation, the analysis cache, refresh requests, workspace roots,
//! watched files, richer diagnostics, code actions, logs and the editor
//! features built on the Tide index.

#![expect(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers outside #[test] functions: a panic fails the test"
)]

mod common;

use common::*;
use serde_json::{Value, json};

const RULE: &str = "crates/testdata/objects/rules/rule-1.0.yaml";
const OBJECTIVE: &str = "crates/testdata/objects/objective-1.0.yaml";
const THREAT: &str = "crates/testdata/objects/threat-1.0.yaml";

fn fixture(path: &str) -> String {
    std::fs::read_to_string(repo_root().join(path)).unwrap()
}

/// A workspace with the rule and, if asked, the objective it references.
fn workspace(name: &str, with_objective: bool) -> Scratch {
    let scratch = Scratch::new(name);
    let objects = scratch.0.join("objects");
    std::fs::create_dir_all(objects.join("rules")).unwrap();
    std::fs::create_dir_all(objects.join("objectives")).unwrap();
    std::fs::write(objects.join("rules/rule-1.0.yaml"), fixture(RULE)).unwrap();
    if with_objective {
        std::fs::write(
            objects.join("objectives/objective-1.0.yaml"),
            fixture(OBJECTIVE),
        )
        .unwrap();
    }
    scratch
}

fn start(params: Value) -> (Lsp, Value) {
    let mut lsp = Lsp::spawn();
    let init = lsp.request("initialize", params);
    lsp.notify("initialized", json!({}));
    (lsp, init["result"].clone())
}

fn open(lsp: &mut Lsp, uri: &str, language: &str, text: &str) {
    lsp.notify(
        "textDocument/didOpen",
        json!({ "textDocument": { "uri": uri, "languageId": language, "version": 1, "text": text } }),
    );
}

fn stats(lsp: &mut Lsp) -> u64 {
    lsp.request("opentide/__stats", Value::Null)["result"]["analyses"]
        .as_u64()
        .unwrap()
}

/// Messages until (and with) the response to `id`.
fn until_response(lsp: &mut Lsp, id: i64) -> Vec<Value> {
    let mut seen = Vec::new();
    loop {
        let message = lsp.read_any();
        let done = message["id"] == id && message.get("method").is_none();
        seen.push(message);
        if done {
            return seen;
        }
    }
}

fn send(lsp: &mut Lsp, id: i64, method: &str, params: Value) {
    lsp.write(&json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params }));
}

/// Have the server sleep, and wait until it does: what is sent next queues
/// up as one batch.
fn hold(lsp: &mut Lsp, id: i64) {
    send(lsp, id, "opentide/__sleep", json!({ "ms": 700 }));
    std::thread::sleep(std::time::Duration::from_millis(150));
}

fn watch() -> Value {
    json!({ "workspace": { "didChangeWatchedFiles": { "dynamicRegistration": true } } })
}

#[test]
fn capabilities_say_what_the_server_does_and_who_hosts_it() {
    let (_lsp, init) = start(json!({ "capabilities": {} }));
    let caps = &init["capabilities"];
    assert_eq!(caps["positionEncoding"], "utf-16");
    assert!(caps.get("diagnosticProvider").is_none(), "{caps}");
    assert!(caps.get("workspace").is_none(), "{caps}");
    let kinds = caps["codeActionProvider"]["codeActionKinds"]
        .as_array()
        .unwrap();
    assert!(kinds.contains(&json!("source.fixAll.opentide")), "{caps}");
    assert!(caps["documentLinkProvider"].is_object());
    assert!(caps["codeLensProvider"].is_object());
    // #172: the binary alone has no host; it checks configuration natively
    // (UC-2.6), and generates the field catalogs and configuration schemas
    // from the models (#926).
    let opentide = &caps["experimental"]["opentide"];
    assert!(opentide["host"].is_null(), "{opentide}");
    assert_eq!(opentide["catalog"], "models");
    assert_eq!(opentide["configurationChecks"], true);
    assert_eq!(opentide["configurationSchemas"], true);
    assert_eq!(opentide["engine"], init["serverInfo"]["version"]);

    let (_lsp, init) =
        start(json!({ "capabilities": { "workspace": { "workspaceFolders": true } } }));
    assert_eq!(
        init["capabilities"]["workspace"]["workspaceFolders"]["supported"],
        true
    );
}

/// `--version --json` prints what `initialize` reports, without a session.
#[test]
fn version_json_matches_initialize() {
    let out = std::process::Command::new(bin())
        .args(["--version", "--json"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let info: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(info["host"].is_null(), "{info}");
    assert_eq!(info["catalog"], "models");
    assert_eq!(info["engine"], env!("CARGO_PKG_VERSION"));
}

#[test]
fn params_of_the_wrong_shape_are_invalid_params() {
    let (mut lsp, _) = start(json!({ "capabilities": {} }));
    let reply = lsp.request("textDocument/hover", json!([1, 2]));
    assert_eq!(reply["error"]["code"], -32602, "{reply}");
    let reply = lsp.request("textDocument/hover", json!({ "textDocument": {} }));
    assert_eq!(reply["error"]["code"], -32602, "{reply}");
    assert!(lsp.request("shutdown", Value::Null)["error"].is_null());
}

/// P1.3: one analysis per document state, shared by every request. The
/// client watches files, so an analysis outlives its batch.
#[test]
fn one_analysis_serves_every_request_on_a_document_state() {
    let scratch = workspace("one-analysis", true);
    let uri = file_uri(&scratch.0.join("objects/rules/rule-1.0.yaml"));
    let (mut lsp, _) = start(json!({ "capabilities": watch(), "rootUri": file_uri(&scratch.0) }));
    open(&mut lsp, &uri, "opentide-yaml", &fixture(RULE));
    published_for(&mut lsp, &uri);
    let after_open = stats(&mut lsp);
    let document = json!({ "textDocument": { "uri": uri } });
    let range =
        json!({ "start": { "line": 0, "character": 0 }, "end": { "line": 99, "character": 0 } });
    lsp.request("textDocument/semanticTokens/full", document.clone());
    lsp.request(
        "textDocument/codeAction",
        json!({ "textDocument": { "uri": uri }, "range": range, "context": { "diagnostics": [] } }),
    );
    lsp.request("textDocument/documentSymbol", document.clone());
    lsp.request(
        "textDocument/inlayHint",
        json!({ "textDocument": { "uri": uri }, "range": range }),
    );
    lsp.request("textDocument/documentLink", document.clone());
    lsp.request("textDocument/codeLens", document);
    assert_eq!(stats(&mut lsp), after_open);
    // An edit is a new state: one more analysis.
    lsp.notify(
        "textDocument/didChange",
        json!({ "textDocument": { "uri": uri }, "contentChanges": [{ "text": fixture(RULE) }] }),
    );
    published_for(&mut lsp, &uri);
    assert_eq!(stats(&mut lsp), after_open + 1);
}

/// P1.4: what arrives while a request is handled is one batch. Twenty
/// queued edits are analysed and published once.
#[test]
fn queued_edits_are_analysed_and_published_once() {
    let (mut lsp, _) = start(json!({ "capabilities": watch() }));
    let uri = "file:///tmp/batch.kql";
    open(&mut lsp, uri, "kql", "SecurityEvent | take 1");
    published_for(&mut lsp, uri);
    let before = stats(&mut lsp);
    hold(&mut lsp, 900);
    for n in 0..20 {
        lsp.notify(
            "textDocument/didChange",
            json!({ "textDocument": { "uri": uri }, "contentChanges": [{ "text": format!("SecurityEvent | take {n}") }] }),
        );
    }
    send(&mut lsp, 901, "opentide/__stats", Value::Null);
    let seen = until_response(&mut lsp, 901);
    let publishes = seen
        .iter()
        .filter(|m| m["method"] == "textDocument/publishDiagnostics")
        .count();
    let analyses = seen.last().unwrap()["result"]["analyses"].as_u64().unwrap();
    // The stats request is in the batch too: it ran before the publish.
    assert_eq!(analyses, before, "{seen:#?}");
    assert_eq!(stats(&mut lsp), before + 1);
    assert!(publishes <= 1, "{seen:#?}");
}

/// P1.4: a request the batch cancels is `RequestCanceled`; one about a
/// document the batch edits after it is `ContentModified`.
#[test]
fn cancelled_and_outdated_requests_are_answered_so() {
    let (mut lsp, _) = start(json!({ "capabilities": {} }));
    let uri = "file:///tmp/cancel.kql";
    open(&mut lsp, uri, "kql", "SecurityEvent | take 1");
    published_for(&mut lsp, uri);
    hold(&mut lsp, 800);
    send(
        &mut lsp,
        801,
        "textDocument/hover",
        json!({ "textDocument": { "uri": uri }, "position": { "line": 0, "character": 2 } }),
    );
    lsp.notify("$/cancelRequest", json!({ "id": 801 }));
    send(
        &mut lsp,
        802,
        "textDocument/semanticTokens/full",
        json!({ "textDocument": { "uri": uri } }),
    );
    lsp.notify(
        "textDocument/didChange",
        json!({ "textDocument": { "uri": uri }, "contentChanges": [{ "text": "SecurityEvent | take 2" }] }),
    );
    send(
        &mut lsp,
        803,
        "textDocument/semanticTokens/full",
        json!({ "textDocument": { "uri": uri } }),
    );
    let seen = until_response(&mut lsp, 803);
    let reply = |id: i64| seen.iter().find(|m| m["id"] == id).unwrap().clone();
    assert_eq!(reply(801)["error"]["code"], -32800, "{seen:#?}");
    assert_eq!(reply(802)["error"]["code"], -32801, "{seen:#?}");
    assert!(reply(803)["result"]["data"].is_array(), "{seen:#?}");
}

/// P1.6: a change beyond one document asks the client to refresh what it
/// shows, when it can.
#[test]
fn a_visibility_edit_asks_the_client_to_refresh() {
    let scratch = Scratch::new("refresh");
    let capabilities = json!({ "workspace": {
        "semanticTokens": { "refreshSupport": true },
        "inlayHint": { "refreshSupport": true },
        "codeLens": { "refreshSupport": true }
    } });
    let (mut lsp, _) =
        start(json!({ "capabilities": capabilities, "rootUri": file_uri(&scratch.0) }));
    let visibility = file_uri(&scratch.0.join(".opentide/configurations/visibility.toml"));
    open(&mut lsp, &visibility, "toml", "");
    send(&mut lsp, 700, "shutdown", Value::Null);
    let seen = until_response(&mut lsp, 700);
    let methods: Vec<&str> = seen.iter().filter_map(|m| m["method"].as_str()).collect();
    for refresh in [
        "workspace/semanticTokens/refresh",
        "workspace/inlayHint/refresh",
        "workspace/codeLens/refresh",
    ] {
        assert!(methods.contains(&refresh), "{methods:?}");
    }

    let (mut lsp, _) = start(json!({ "capabilities": {}, "rootUri": file_uri(&scratch.0) }));
    open(&mut lsp, &visibility, "toml", "");
    send(&mut lsp, 700, "shutdown", Value::Null);
    let seen = until_response(&mut lsp, 700);
    assert!(
        !seen.iter().any(|m| m["method"]
            .as_str()
            .is_some_and(|m| m.ends_with("/refresh"))),
        "{seen:#?}"
    );
}

fn codes_for(lsp: &mut Lsp, uri: &str, text: &str) -> Vec<String> {
    open(lsp, uri, "opentide-yaml", text);
    codes_of(&published_for(lsp, uri))
}

/// P2.1: a client that sends only `workspaceFolders` gets each folder's
/// index, and folders do not see each other's objects.
#[test]
fn workspace_folders_each_have_their_own_index() {
    let with = workspace("folder-with", true);
    let without = workspace("folder-without", false);
    let folder = |s: &Scratch, name: &str| json!({ "uri": file_uri(&s.0), "name": name });
    let (mut lsp, _) = start(json!({
        "capabilities": { "workspace": { "workspaceFolders": true } },
        "workspaceFolders": [folder(&with, "with"), folder(&without, "without")]
    }));
    let rule = fixture(RULE);
    let in_with = file_uri(&with.0.join("objects/rules/rule-1.0.yaml"));
    let in_without = file_uri(&without.0.join("objects/rules/rule-1.0.yaml"));
    let codes = codes_for(&mut lsp, &in_with, &rule);
    assert!(!codes.contains(&"invalid_ref".to_string()), "{codes:?}");
    // The same rule in the other folder: no objective there, and the first
    // folder's copy is not a duplicate.
    let codes = codes_for(&mut lsp, &in_without, &rule);
    assert!(codes.contains(&"invalid_ref".to_string()), "{codes:?}");
    assert!(!codes.contains(&"duplicate_id".to_string()), "{codes:?}");

    // A folder added later is a root too.
    let (mut lsp, _) = start(json!({
        "capabilities": { "workspace": { "workspaceFolders": true } },
        "workspaceFolders": [folder(&without, "without")]
    }));
    lsp.notify(
        "workspace/didChangeWorkspaceFolders",
        json!({ "event": { "added": [folder(&with, "with")], "removed": [] } }),
    );
    let codes = codes_for(&mut lsp, &in_with, &rule);
    assert!(!codes.contains(&"invalid_ref".to_string()), "{codes:?}");
}

/// P2.2: the server watches what the analysis reads, and a referenced
/// objective deleted on disk is an `invalid_ref` without an edit.
#[test]
fn files_changed_on_disk_reach_the_open_documents() {
    let scratch = workspace("watched", true);
    let root = &scratch.0;
    let rule_uri = file_uri(&root.join("objects/rules/rule-1.0.yaml"));
    let mut lsp = Lsp::spawn();
    lsp.request(
        "initialize",
        json!({ "capabilities": watch(), "rootUri": file_uri(root) }),
    );
    lsp.notify("initialized", json!({}));
    let register = lsp.read();
    assert_eq!(
        register["method"], "client/registerCapability",
        "{register}"
    );
    let globs: Vec<&str> = register["params"]["registrations"][0]["registerOptions"]["watchers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|w| w["globPattern"].as_str().unwrap())
        .collect();
    assert_eq!(
        globs,
        [
            "**/objects",
            "**/objects/**",
            "**/.opentide/configurations/**/*.toml",
            "**/.opentide/states/deployment/**",
            "**/.opentide/states",
            "**/.opentide/states/deployment",
        ]
    );
    lsp.write(&json!({ "jsonrpc": "2.0", "id": register["id"], "result": null }));
    let codes = codes_for(&mut lsp, &rule_uri, &fixture(RULE));
    assert!(!codes.contains(&"invalid_ref".to_string()), "{codes:?}");

    let objective = root.join("objects/objectives/objective-1.0.yaml");
    std::fs::remove_file(&objective).unwrap();
    lsp.notify(
        "workspace/didChangeWatchedFiles",
        json!({ "changes": [{ "uri": file_uri(&objective), "type": 3 }] }),
    );
    let codes = codes_of(&published_for(&mut lsp, &rule_uri));
    assert!(codes.contains(&"invalid_ref".to_string()), "{codes:?}");

    // A configuration file changed on disk re-checks it too.
    let changed = root.join(".opentide/configurations/platforms/sentinel.toml");
    lsp.notify(
        "workspace/didChangeWatchedFiles",
        json!({ "changes": [{ "uri": file_uri(&changed), "type": 2 }] }),
    );
    published_for(&mut lsp, &rule_uri);
}

fn loading(lsp: &mut Lsp) -> (u64, u64) {
    let stats = lsp.request("opentide/__stats", Value::Null)["result"]["workspace"].clone();
    (
        stats["parses"].as_u64().unwrap(),
        stats["configResolutions"].as_u64().unwrap(),
    )
}

/// UC-2.6: the root's workspace is loaded once; an edit, a file a watcher
/// reports and a configuration file reach it through its invalidation API,
/// each re-reading only what it names, and the findings follow.
#[test]
fn edits_and_watched_files_invalidate_only_what_they_name() {
    let scratch = workspace("invalidation", true);
    let root = &scratch.0;
    let rule_uri = file_uri(&root.join("objects/rules/rule-1.0.yaml"));
    let (mut lsp, _) = start(json!({ "capabilities": watch(), "rootUri": file_uri(root) }));
    let register = lsp.read();
    lsp.write(&json!({ "jsonrpc": "2.0", "id": register["id"], "result": null }));
    let rule = fixture(RULE);
    let codes = codes_for(&mut lsp, &rule_uri, &rule);
    assert!(!codes.contains(&"vocab_unknown".to_string()), "{codes:?}");
    // The two object files, read once; the configuration resolved once.
    assert_eq!(loading(&mut lsp), (2, 1));

    // An edit re-reads that buffer alone, and validate reports on it.
    let edited = rule.replacen("tlp: clear", "tlp: clearr", 1);
    assert_ne!(edited, rule);
    lsp.notify(
        "textDocument/didChange",
        json!({ "textDocument": { "uri": rule_uri, "version": 2 },
                "contentChanges": [{ "text": edited }] }),
    );
    let diagnostics = published_for(&mut lsp, &rule_uri);
    let tlp = diagnostics
        .iter()
        .find(|d| d["code"] == "vocab_unknown")
        .unwrap_or_else(|| panic!("{diagnostics:#?}"));
    assert_eq!(tlp["data"]["field_path"], json!(["metadata", "tlp"]));
    assert_eq!(tlp["data"]["suggestion"], "clear", "{tlp}");
    assert_eq!(loading(&mut lsp), (3, 1));

    // The objective changes on disk: that file alone is read again.
    let objective = root.join("objects/objectives/objective-1.0.yaml");
    let text = std::fs::read_to_string(&objective).unwrap();
    std::fs::write(&objective, format!("{text}\n")).unwrap();
    lsp.notify(
        "workspace/didChangeWatchedFiles",
        json!({ "changes": [{ "uri": file_uri(&objective), "type": 2 }] }),
    );
    published_for(&mut lsp, &rule_uri);
    assert_eq!(loading(&mut lsp), (4, 1));

    // A configuration file: resolved again, no object re-read.
    let platforms = root.join(".opentide/configurations/platforms");
    std::fs::create_dir_all(&platforms).unwrap();
    std::fs::write(
        platforms.join("sentinel.toml"),
        "[platform]\nenabled = true\n",
    )
    .unwrap();
    lsp.notify(
        "workspace/didChangeWatchedFiles",
        json!({ "changes": [{ "uri": file_uri(&platforms.join("sentinel.toml")), "type": 1 }] }),
    );
    published_for(&mut lsp, &rule_uri);
    assert_eq!(loading(&mut lsp), (4, 2));
}

fn editor_indexed(lsp: &mut Lsp) -> u64 {
    lsp.request("opentide/__stats", Value::Null)["result"]["editorIndexed"]
        .as_u64()
        .unwrap()
}

/// #914: the first diagnostics of a Tide object that cannot read the other
/// objects (no Elastic block) do not wait for the editor's index of the
/// root: it is built on the first request that reads it, every file then,
/// from the parse the workspace made of each for `validate` (#926): no file
/// is parsed a second time.
#[test]
fn the_first_diagnostics_do_not_build_the_editor_index() {
    let scratch = workspace("lazy-index", true);
    let root = &scratch.0;
    let rule_uri = file_uri(&root.join("objects/rules/rule-1.0.yaml"));
    let (mut lsp, _) = start(json!({ "capabilities": watch(), "rootUri": file_uri(root) }));
    let register = lsp.read();
    lsp.write(&json!({ "jsonrpc": "2.0", "id": register["id"], "result": null }));
    let rule = fixture(RULE);
    assert!(!rule.contains("elastic"));
    let codes = codes_for(&mut lsp, &rule_uri, &rule);
    // validate checked it against the objective on disk.
    assert!(!codes.contains(&"invalid_ref".to_string()), "{codes:?}");
    assert_eq!(editor_indexed(&mut lsp), 0);

    let symbols = lsp.request("workspace/symbol", json!({ "query": "Credential" }));
    let names: Vec<&str> = symbols["result"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|s| s["name"].as_str())
        .collect();
    assert_eq!(names, ["Credential Access Objective"], "{symbols}");
    assert_eq!(editor_indexed(&mut lsp), 2);
    let parsed = lsp.request("opentide/__stats", Value::Null)["result"]["editorParsed"].clone();
    assert_eq!(parsed, 0, "the index read the workspace's parses");
}

/// #821 (UC-2.6): an Elastic rule's advisories are not the editor's. The
/// language server publishes `validate`'s findings, and the Elastic block's
/// advisories are `opentide lint`'s, so a technique the rule inherits
/// through `detection_model` that is not Enterprise ATT&CK
/// (`technique_not_enterprise`, which lint reports:
/// `lint_reports_every_elastic_block_advisory`) is not published, and the
/// editor's index is not read for the first diagnostics.
#[test]
fn an_elastic_rule_publishes_no_advisory_of_its_own() {
    let scratch = workspace("lazy-index-elastic", false);
    let root = &scratch.0;
    let objective = fixture(OBJECTIVE).replacen(
        "  threats:\n",
        "  mitre_attack:\n    - T1626\n  threats:\n",
        1,
    );
    assert_ne!(objective, fixture(OBJECTIVE));
    std::fs::write(
        root.join("objects/objectives/objective-1.0.yaml"),
        objective,
    )
    .unwrap();
    let rule_uri = file_uri(&root.join("objects/rules/rule-1.0.yaml"));
    let (mut lsp, _) = start(json!({ "capabilities": watch(), "rootUri": file_uri(root) }));
    let register = lsp.read();
    lsp.write(&json!({ "jsonrpc": "2.0", "id": register["id"], "result": null }));
    let rule = format!(
        "{}  elastic:\n    type: query\n    query: x\n",
        fixture(RULE)
    );
    open(&mut lsp, &rule_uri, "opentide-yaml", &rule);
    let diagnostics = published_for(&mut lsp, &rule_uri);
    assert!(
        !diagnostics
            .iter()
            .any(|d| d["code"] == "technique_not_enterprise"),
        "{diagnostics:#?}"
    );
    assert_eq!(editor_indexed(&mut lsp), 0);
}

/// #821 (UC-2.6): no object of the root is indexed by the editor for an
/// Elastic rule's first diagnostics, now that the platform-block advisories
/// that looked up the objects it inherits from are `lint`'s alone. The index
/// is still built, every file at once, on the first request that reads it.
#[test]
fn an_elastic_rule_indexes_nothing_of_the_root_for_its_diagnostics() {
    let scratch = workspace("scoped-index-elastic", true);
    let root = &scratch.0;
    let threats = root.join("objects/threats");
    std::fs::create_dir_all(&threats).unwrap();
    let threat = fixture(THREAT).replacen("    - T1059\n", "    - T1626\n", 1);
    assert_ne!(threat, fixture(THREAT));
    std::fs::write(threats.join("threat-1.0.yaml"), threat).unwrap();
    // Objects that name neither the objective nor its threat.
    for i in 0..4 {
        let other = fixture(THREAT)
            .replacen(
                "00000000-0000-4000-8001-000000000001",
                &format!("00000000-0000-4000-8001-00000000010{i}"),
                1,
            )
            .replacen("Simulated Actor", &format!("Other Actor {i}"), 1);
        std::fs::write(threats.join(format!("other-{i}.yaml")), other).unwrap();
    }
    let rule_uri = file_uri(&root.join("objects/rules/rule-1.0.yaml"));
    let (mut lsp, _) = start(json!({ "capabilities": watch(), "rootUri": file_uri(root) }));
    let register = lsp.read();
    lsp.write(&json!({ "jsonrpc": "2.0", "id": register["id"], "result": null }));
    let rule = format!(
        "{}  elastic:\n    type: query\n    query: x\n",
        fixture(RULE)
    );
    open(&mut lsp, &rule_uri, "opentide-yaml", &rule);
    published_for(&mut lsp, &rule_uri);
    assert_eq!(editor_indexed(&mut lsp), 0);

    // A request that reads the whole index indexes every object.
    let symbols = lsp.request("workspace/symbol", json!({ "query": "Other Actor" }));
    assert_eq!(symbols["result"].as_array().unwrap().len(), 4, "{symbols}");
    assert_eq!(editor_indexed(&mut lsp), 7);
}

/// #914: the root's workspace starts loading when the folder is known,
/// before a document is opened; a buffer opened meanwhile is what
/// `validate` checks, whether it holds what the disk does or not.
#[test]
fn a_buffer_opened_while_the_workspace_loads_is_checked() {
    let scratch = workspace("prefetch", true);
    let root = &scratch.0;
    let path = root.join("objects/rules/rule-1.0.yaml");
    let rule = fixture(RULE);
    let broken = rule.replacen("tlp: clear", "tlp: clearr", 1);
    assert_ne!(broken, rule);
    // On disk the rule is broken; the editor's buffer is not.
    std::fs::write(&path, &broken).unwrap();
    let rule_uri = file_uri(&path);
    let (mut lsp, _) = start(json!({ "capabilities": watch(), "rootUri": file_uri(root) }));
    let register = lsp.read();
    lsp.write(&json!({ "jsonrpc": "2.0", "id": register["id"], "result": null }));
    let codes = codes_for(&mut lsp, &rule_uri, &rule);
    assert!(!codes.contains(&"vocab_unknown".to_string()), "{codes:?}");
    // Loaded once, and the buffer parsed again for what it changed.
    assert_eq!(loading(&mut lsp), (3, 1));

    // The other way round: the disk is fine, the buffer is not.
    std::fs::write(&path, &rule).unwrap();
    let (mut lsp, _) = start(json!({ "capabilities": watch(), "rootUri": file_uri(root) }));
    let register = lsp.read();
    lsp.write(&json!({ "jsonrpc": "2.0", "id": register["id"], "result": null }));
    let codes = codes_for(&mut lsp, &rule_uri, &broken);
    assert!(codes.contains(&"vocab_unknown".to_string()), "{codes:?}");
}

/// P2.3: a code's documentation, a `Deprecated` tag and the other file of a
/// `duplicate_id`, each for a client that reads it.
#[test]
fn diagnostics_carry_what_the_client_reads() {
    let scratch = workspace("rich", false);
    let root = &scratch.0;
    // A second file with the rule's UUID.
    std::fs::write(root.join("objects/rules/copy.yaml"), fixture(RULE)).unwrap();
    let rule_uri = file_uri(&root.join("objects/rules/rule-1.0.yaml"));
    // `deprecated_field` is validate's, and no bundled field is deprecated
    // (opentide#745): a deprecated KQL function exercises the tag.
    let legacy = "SecurityEvent | summarize argmax(TimeGenerated, Account)\n";
    let legacy_uri = file_uri(&root.join("queries/legacy.kql"));
    let rich = json!({ "textDocument": { "publishDiagnostics": {
        "codeDescriptionSupport": true,
        "tagSupport": { "valueSet": [1, 2] },
        "relatedInformation": true
    } } });
    let (mut lsp, _) = start(json!({ "capabilities": rich, "rootUri": file_uri(root) }));
    open(&mut lsp, &rule_uri, "opentide-yaml", &fixture(RULE));
    let diagnostics = published_for(&mut lsp, &rule_uri);
    let duplicate = diagnostics
        .iter()
        .find(|d| d["code"] == "duplicate_id")
        .unwrap_or_else(|| panic!("{diagnostics:#?}"));
    assert_eq!(
        duplicate["codeDescription"]["href"],
        "https://opentide.org/docs/cli/diagnostics/#duplicate_id"
    );
    let related = duplicate["relatedInformation"].as_array().unwrap();
    assert_eq!(related.len(), 1, "{duplicate}");
    assert!(
        related[0]["location"]["uri"]
            .as_str()
            .unwrap()
            .ends_with("objects/rules/copy.yaml"),
        "{duplicate}"
    );
    open(&mut lsp, &legacy_uri, "kql", legacy);
    let diagnostics = published_for(&mut lsp, &legacy_uri);
    let deprecated = diagnostics
        .iter()
        .find(|d| d["code"] == "kql_deprecated_function")
        .unwrap_or_else(|| panic!("{diagnostics:#?}"));
    assert_eq!(deprecated["tags"], json!([2]));

    // A client that says nothing gets none of them.
    let (mut lsp, _) = start(json!({ "capabilities": {}, "rootUri": file_uri(root) }));
    open(&mut lsp, &rule_uri, "opentide-yaml", &fixture(RULE));
    for d in published_for(&mut lsp, &rule_uri) {
        for key in ["codeDescription", "relatedInformation", "tags"] {
            assert!(d.get(key).is_none(), "{d}");
        }
    }
}

const TYPOS: &str = "SecurityEvent | wher EventID == 4688 | projct Account";

/// P2.4, P3.4: quick fixes name their diagnostic and are preferred;
/// `source.fixAll.opentide` applies every suggestion, and only when asked.
#[test]
fn code_actions_follow_the_context() {
    let (mut lsp, _) = start(json!({ "capabilities": {} }));
    let uri = "file:///tmp/typos.kql";
    open(&mut lsp, uri, "kql", TYPOS);
    let diagnostics = published_for(&mut lsp, uri);
    assert_eq!(diagnostics.len(), 2, "{diagnostics:#?}");
    let whole =
        json!({ "start": { "line": 0, "character": 0 }, "end": { "line": 0, "character": 60 } });
    let actions = |lsp: &mut Lsp, context: Value| {
        lsp.request(
            "textDocument/codeAction",
            json!({ "textDocument": { "uri": uri }, "range": whole, "context": context }),
        )["result"]
            .as_array()
            .unwrap()
            .clone()
    };

    // The client names one diagnostic: one fix, for it.
    let found = actions(&mut lsp, json!({ "diagnostics": [diagnostics[0]] }));
    assert_eq!(found.len(), 1, "{found:#?}");
    assert_eq!(found[0]["title"], "Apply suggestion: where");
    let edit = &found[0]["edit"]["changes"][uri][0];
    assert_eq!(edit["range"]["start"]["character"], 16, "{edit}");
    assert_eq!(edit["range"]["end"]["character"], 20, "{edit}");
    // The diagnostic itself still covers the stage (plan §3 invariant 3).
    assert!(
        diagnostics[0]["range"]["end"]["character"]
            .as_u64()
            .unwrap()
            > 20
    );
    assert_eq!(found[0]["isPreferred"], true);
    assert_eq!(found[0]["diagnostics"][0], diagnostics[0]);

    // No `only`: quick fixes, no source action.
    let found = actions(&mut lsp, json!({ "diagnostics": [] }));
    assert!(found.iter().all(|a| a["kind"] == "quickfix"), "{found:#?}");
    assert_eq!(found.len(), 2);

    // `source.fixAll`: one edit with both suggestions.
    let found = actions(
        &mut lsp,
        json!({ "diagnostics": [], "only": ["source.fixAll"] }),
    );
    assert_eq!(found.len(), 1, "{found:#?}");
    assert_eq!(found[0]["kind"], "source.fixAll.opentide");
    let edits = found[0]["edit"]["changes"][uri].as_array().unwrap();
    let texts: Vec<&str> = edits
        .iter()
        .map(|e| e["newText"].as_str().unwrap())
        .collect();
    assert_eq!(texts, ["where", "project"]);
    // Each replaces the operator's word, not its stage: the arguments stay (#887).
    let ranges: Vec<(u64, u64)> = edits
        .iter()
        .map(|e| {
            (
                e["range"]["start"]["character"].as_u64().unwrap(),
                e["range"]["end"]["character"].as_u64().unwrap(),
            )
        })
        .collect();
    assert_eq!(ranges, [(16, 20), (39, 45)], "{edits:#?}");

    let found = actions(&mut lsp, json!({ "diagnostics": [], "only": ["quickfix"] }));
    assert!(found.iter().all(|a| a["kind"] == "quickfix"), "{found:#?}");
}

/// A Microsoft Defender rule whose block names a column its query does not
/// return, and whose query ends without a `project` (#1885).
const DEFENDER_RULE: &str = "name: Defender rule
configurations:
  microsoft_defender:
    query: |
      DeviceProcessEvents
      | where FileName =~ 'powershell.exe' // encoded
    entities:
      hosts:
        - device_id: DevicId
      accounts:
        - upn: AccountUpn
";

/// #1885: the Defender block's columns against its query's output, with a
/// quick fix for each: the column it most likely means, and the `| project`
/// appended after the query's last operator, on its line.
#[test]
fn defender_output_findings_have_quick_fixes() {
    let scratch = workspace("defender_output", false);
    let uri = file_uri(&scratch.0.join("objects/rules/defender.yaml"));
    let (mut lsp, _) = start(json!({ "capabilities": {}, "rootUri": file_uri(&scratch.0) }));
    open(&mut lsp, &uri, "opentide-yaml", DEFENDER_RULE);
    let diagnostics = published_for(&mut lsp, &uri);
    let find = |code: &str| {
        diagnostics
            .iter()
            .find(|d| d["code"] == code)
            .unwrap_or_else(|| panic!("{code}: {diagnostics:#?}"))
            .clone()
    };
    let column = find("microsoft_defender_column_not_in_output");
    assert_eq!(column["severity"], 1, "{column}");
    assert_eq!(
        column["range"]["start"],
        json!({ "line": 8, "character": 21 })
    );
    assert_eq!(
        column["range"]["end"],
        json!({ "line": 8, "character": 28 })
    );
    let unprojected = find("microsoft_defender_unprojected_output");
    // A note: it never fails `lint --strict`.
    assert_eq!(unprojected["severity"], 3, "{unprojected}");
    assert_eq!(
        unprojected["range"]["start"],
        json!({ "line": 5, "character": 8 })
    );
    assert_eq!(
        unprojected["range"]["end"],
        json!({ "line": 5, "character": 42 })
    );

    let actions = |lsp: &mut Lsp, diagnostic: &Value| {
        lsp.request(
            "textDocument/codeAction",
            json!({
                "textDocument": { "uri": uri },
                "range": diagnostic["range"],
                "context": { "diagnostics": [diagnostic] }
            }),
        )["result"]
            .as_array()
            .unwrap()
            .clone()
    };
    let found = actions(&mut lsp, &column);
    assert_eq!(found.len(), 1, "{found:#?}");
    assert_eq!(found[0]["title"], "Apply suggestion: DeviceId");
    let edit = &found[0]["edit"]["changes"][&uri][0];
    assert_eq!(edit["range"], column["range"]);
    assert_eq!(edit["newText"], "DeviceId");

    let found = actions(&mut lsp, &unprojected);
    assert_eq!(found.len(), 1, "{found:#?}");
    let project = "| project Timestamp, DeviceId, ReportId, AccountUpn";
    assert_eq!(found[0]["title"], format!("Append {project}"));
    let edit = &found[0]["edit"]["changes"][&uri][0];
    // An insertion after the operator, before the line's comment.
    assert_eq!(edit["range"]["start"], unprojected["range"]["end"]);
    assert_eq!(edit["range"]["end"], unprojected["range"]["end"]);
    assert_eq!(edit["newText"], format!(" {project}"));

    // fixAll applies the column's suggestion, never the project.
    let all = lsp.request(
        "textDocument/codeAction",
        json!({
            "textDocument": { "uri": uri },
            "range": { "start": { "line": 0, "character": 0 }, "end": { "line": 12, "character": 0 } },
            "context": { "diagnostics": [], "only": ["source.fixAll.opentide"] }
        }),
    )["result"]
        .as_array()
        .unwrap()
        .clone();
    let edits = all
        .iter()
        .flat_map(|a| {
            a["edit"]["changes"][&uri]
                .as_array()
                .cloned()
                .unwrap_or_default()
        })
        .collect::<Vec<_>>();
    assert!(
        edits.iter().all(|e| !e["newText"]
            .as_str()
            .unwrap_or_default()
            .contains("project")),
        "{all:#?}"
    );
    assert!(edits.iter().any(|e| e["newText"] == "DeviceId"), "{all:#?}");
}

/// #887: an unknown SPL command's fix replaces the command, not its stage.
#[test]
fn an_spl_command_fix_keeps_the_stage_s_arguments() {
    let (mut lsp, _) = start(json!({ "capabilities": {} }));
    let uri = "file:///tmp/typo.spl";
    let text = "index=main | stast count by host";
    open(&mut lsp, uri, "spl", text);
    let diagnostics = published_for(&mut lsp, uri);
    let typo: Vec<&Value> = diagnostics
        .iter()
        .filter(|d| d["code"] == "spl_unknown_command")
        .collect();
    assert_eq!(typo.len(), 1, "{diagnostics:#?}");
    let found = lsp.request(
        "textDocument/codeAction",
        json!({
            "textDocument": { "uri": uri },
            "range": typo[0]["range"],
            "context": { "diagnostics": [typo[0]] },
        }),
    )["result"]
        .as_array()
        .unwrap()
        .clone();
    assert_eq!(found.len(), 1, "{found:#?}");
    assert_eq!(found[0]["title"], "Apply suggestion: stats");
    let edit = &found[0]["edit"]["changes"][uri][0];
    assert_eq!(edit["newText"], "stats");
    assert_eq!(edit["range"]["start"]["character"], 13, "{edit}");
    assert_eq!(edit["range"]["end"]["character"], 18, "{edit}");
    // Applied, the edit keeps `count by host`.
    let start = usize::try_from(edit["range"]["start"]["character"].as_u64().unwrap()).unwrap();
    let end = usize::try_from(edit["range"]["end"]["character"].as_u64().unwrap()).unwrap();
    let fixed = format!("{}stats{}", &text[..start], &text[end..]);
    assert_eq!(fixed, "index=main | stats count by host");
}

/// P2.5: loads are logged, and a broken `visibility.toml` is shown once.
#[test]
fn a_broken_visibility_file_is_logged_and_shown_once() {
    let scratch = Scratch::new("broken-visibility");
    let configurations = scratch.0.join(".opentide/configurations");
    std::fs::create_dir_all(&configurations).unwrap();
    std::fs::write(configurations.join("visibility.toml"), "[[logsources]\n").unwrap();
    let (mut lsp, _) = start(json!({ "capabilities": {}, "rootUri": file_uri(&scratch.0) }));
    open(
        &mut lsp,
        "file:///tmp/a.kql",
        "kql",
        "SecurityEvent | take 1",
    );
    open(
        &mut lsp,
        "file:///tmp/b.kql",
        "kql",
        "SecurityEvent | take 1",
    );
    send(&mut lsp, 600, "shutdown", Value::Null);
    let seen = until_response(&mut lsp, 600);
    let shown: Vec<&Value> = seen
        .iter()
        .filter(|m| m["method"] == "window/showMessage")
        .collect();
    assert_eq!(shown.len(), 1, "{seen:#?}");
    assert_eq!(shown[0]["params"]["type"], 2);
    assert!(
        shown[0]["params"]["message"]
            .as_str()
            .unwrap()
            .contains("visibility.toml"),
        "{shown:?}"
    );
    assert!(
        seen.iter()
            .any(|m| m["method"] == "window/logMessage" && m["params"]["type"] == 2),
        "{seen:#?}"
    );
}

/// P2.6: plain text for a client without Markdown, no list on a space in
/// YAML, versions on published diagnostics, and an outdated edit ignored.
#[test]
fn the_server_follows_what_the_client_can_do() {
    let caps = json!({ "textDocument": {
        "hover": { "contentFormat": ["plaintext"] },
        "publishDiagnostics": { "versionSupport": true }
    } });
    let (mut lsp, _) = start(json!({ "capabilities": caps }));
    let uri = "file:///tmp/plain.kql";
    open(
        &mut lsp,
        uri,
        "kql",
        "SecurityEvent | where EventID == 4688",
    );
    published_for(&mut lsp, uri);
    let hover = lsp.request(
        "textDocument/hover",
        json!({ "textDocument": { "uri": uri }, "position": { "line": 0, "character": 18 } }),
    );
    assert_eq!(hover["result"]["contents"]["kind"], "plaintext", "{hover}");
    assert!(
        !hover["result"]["contents"]["value"]
            .as_str()
            .unwrap()
            .contains("**")
    );

    lsp.notify(
        "textDocument/didChange",
        json!({ "textDocument": { "uri": uri, "version": 5 }, "contentChanges": [{ "text": TYPOS }] }),
    );
    loop {
        let message = lsp.read();
        if message["method"] == "textDocument/publishDiagnostics" {
            assert_eq!(message["params"]["version"], 5, "{message}");
            break;
        }
    }
    // Version 3 is older than the text the server has: dropped.
    lsp.notify(
        "textDocument/didChange",
        json!({ "textDocument": { "uri": uri, "version": 3 }, "contentChanges": [{ "text": "SecurityEvent" }] }),
    );
    let fixes = lsp.request(
        "textDocument/codeAction",
        json!({
            "textDocument": { "uri": uri },
            "range": { "start": { "line": 0, "character": 0 }, "end": { "line": 0, "character": 60 } },
            "context": { "diagnostics": [] }
        }),
    );
    assert_eq!(fixes["result"].as_array().unwrap().len(), 2, "{fixes}");

    let yaml = "file:///tmp/objects/rules/space.yaml";
    open(
        &mut lsp,
        yaml,
        "opentide-yaml",
        "name: x\ndescription: a \n",
    );
    let space = |lsp: &mut Lsp, uri: &str, character: u32| {
        lsp.request(
            "textDocument/completion",
            json!({
                "textDocument": { "uri": uri },
                "position": { "line": 0, "character": character },
                "context": { "triggerKind": 2, "triggerCharacter": " " }
            }),
        )
    };
    let in_yaml = space(&mut lsp, yaml, 6);
    assert!(in_yaml["result"].is_null(), "{in_yaml}");
    let kql = "file:///tmp/space.kql";
    open(&mut lsp, kql, "kql", "SecurityEvent | ");
    let in_kql = space(&mut lsp, kql, 16);
    assert!(!in_kql["result"].as_array().unwrap().is_empty(), "{in_kql}");
}

/// P3.1: a Tide object's symbols nest: sections, platform blocks, queries.
#[test]
fn tide_symbols_are_a_tree() {
    let (mut lsp, _) = start(json!({ "capabilities": {} }));
    let uri = "file:///tmp/objects/rules/tree.yaml";
    open(&mut lsp, uri, "opentide-yaml", &fixture(RULE));
    let symbols = lsp.request(
        "textDocument/documentSymbol",
        json!({ "textDocument": { "uri": uri } }),
    );
    let object = &symbols["result"][0];
    assert_eq!(
        object["detail"], "00000000-0000-4000-8003-000000000001",
        "{symbols}"
    );
    let configurations = object["children"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "configurations")
        .unwrap_or_else(|| panic!("{symbols}"));
    let platform = &configurations["children"][0];
    assert!(platform["name"].is_string(), "{configurations}");
    assert_eq!(platform["children"][0]["kind"], 15, "{platform}");
}

/// P3.2, P3.3: links to ATT&CK and to referenced objects, and a lens on an
/// objective counting the rules that use it.
#[test]
fn links_and_lenses_come_from_the_index() {
    let scratch = workspace("links", true);
    let root = &scratch.0;
    let (mut lsp, _) = start(json!({ "capabilities": {}, "rootUri": file_uri(root) }));
    let rule_uri = file_uri(&root.join("objects/rules/rule-1.0.yaml"));
    let text = format!("{}\nreferences:\n  - T1059.001\n", fixture(RULE).trim_end());
    open(&mut lsp, &rule_uri, "opentide-yaml", &text);
    let links = lsp.request(
        "textDocument/documentLink",
        json!({ "textDocument": { "uri": rule_uri } }),
    );
    let targets: Vec<&str> = links["result"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| l["target"].as_str().unwrap())
        .collect();
    assert!(
        targets.contains(&"https://attack.mitre.org/techniques/T1059/001/"),
        "{targets:?}"
    );
    assert!(
        targets
            .iter()
            .any(|t| t.ends_with("objects/objectives/objective-1.0.yaml")),
        "{targets:?}"
    );

    let objective_uri = file_uri(&root.join("objects/objectives/objective-1.0.yaml"));
    open(
        &mut lsp,
        &objective_uri,
        "opentide-yaml",
        &fixture(OBJECTIVE),
    );
    let lenses = lsp.request(
        "textDocument/codeLens",
        json!({ "textDocument": { "uri": objective_uri } }),
    );
    let lens = &lenses["result"][0];
    assert_eq!(
        lens["command"]["title"], "1 rule uses this objective",
        "{lenses}"
    );
    assert_eq!(lens["command"]["command"], "opentide.showReferences");
    assert_eq!(lens["command"]["arguments"][2][0]["uri"], rule_uri.as_str());
}

/// lint's file-name finding as a client sends it back with a code action
/// request: `filename_mismatch`, whose suggestion is the file name (KG-03;
/// the server reports it once `lint::lint_file` is wired in, #905).
fn file_name_finding(text: &str, suggestion: &str) -> Value {
    let line = text.lines().position(|l| l.starts_with("name:")).unwrap();
    let name = text.lines().nth(line).unwrap();
    json!({
        "range": {
            "start": { "line": line, "character": 6 },
            "end": { "line": line, "character": name.len() }
        },
        "severity": 2,
        "code": "filename_mismatch",
        "source": "opentide",
        "message": "the file name is not the object's",
        "data": { "field_path": ["name"], "suggestion": suggestion }
    })
}

/// #926 (KG-03, KG-05): the editor shows lint's file name and metadata
/// findings, with `lint.toml`'s severities: `filename_mismatch`, which
/// suggests the file name the object's name gives and is renamed to it, and
/// `metadata_recommended`; a `lint.toml` that turns the checks off leaves
/// both out.
#[test]
fn lint_s_file_name_and_metadata_findings_are_published() {
    let scratch = workspace("lint-findings", true);
    let root = &scratch.0;
    let path = root.join("objects/rules/rule-1.0.yaml");
    let uri = file_uri(&path);
    let renaming = json!({ "workspace": { "workspaceEdit": {
        "documentChanges": true, "resourceOperations": ["create", "rename"]
    } } });
    let (mut lsp, _) = start(json!({ "capabilities": renaming, "rootUri": file_uri(root) }));
    open(&mut lsp, &uri, "opentide-yaml", &fixture(RULE));
    let published = published_for(&mut lsp, &uri);
    let found = |code: &str| {
        published
            .iter()
            .find(|d| d["code"] == code)
            .unwrap_or_else(|| panic!("no {code} in {published:#?}"))
            .clone()
    };
    let file_name = found("filename_mismatch");
    assert_eq!(file_name["severity"], 2, "{file_name}");
    assert_eq!(
        file_name["data"]["suggestion"], "sentinel-kql-rule.yaml",
        "{file_name}"
    );
    // No author, no organisation: lint's `info`.
    let metadata = found("metadata_recommended");
    assert_eq!(metadata["severity"], 3, "{metadata}");
    let actions = lsp.request(
        "textDocument/codeAction",
        json!({ "textDocument": { "uri": uri },
                "range": { "start": { "line": 0, "character": 0 }, "end": { "line": 0, "character": 0 } },
                "context": { "diagnostics": [file_name] } }),
    );
    let titles: Vec<&str> = actions["result"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|a| a["title"].as_str())
        .collect();
    assert_eq!(titles, ["Rename the file to sentinel-kql-rule.yaml"]);
    drop(lsp);

    std::fs::create_dir_all(root.join(".opentide/configurations")).unwrap();
    std::fs::write(
        root.join(".opentide/configurations/lint.toml"),
        "[filenames]\nenabled = false\n\n[metadata]\nenabled = false\n",
    )
    .unwrap();
    let (mut lsp, _) = start(json!({ "capabilities": {}, "rootUri": file_uri(root) }));
    let codes = codes_for(&mut lsp, &uri, &fixture(RULE));
    assert!(
        !codes.contains(&"filename_mismatch".to_string()),
        "{codes:?}"
    );
    assert!(
        !codes.contains(&"metadata_recommended".to_string()),
        "{codes:?}"
    );
}

/// opentide 0.28.1 (#1028, language-server #250): a missing optional field
/// is information. A rule without `response` gets lint's
/// `recommended_field_missing` as an Information diagnostic (severity 3,
/// not a warning), at the top of the file; `[recommended] enabled = false` leaves
/// it out, and a rule with both fields has none.
#[test]
fn a_missing_recommended_field_is_information() {
    let scratch = workspace("recommended-field", true);
    let root = &scratch.0;
    let path = root.join("objects/rules/rule-1.0.yaml");
    let full = fixture(RULE);
    let start_at = full.find("\nresponse:").unwrap() + 1;
    let end_at = full.find("\nconfigurations:").unwrap() + 1;
    let text = format!("{}{}", &full[..start_at], &full[end_at..]);
    std::fs::write(&path, &text).unwrap();
    let uri = file_uri(&path);
    let (mut lsp, _) = start(json!({ "capabilities": {}, "rootUri": file_uri(root) }));
    open(&mut lsp, &uri, "opentide-yaml", &text);
    let published = published_for(&mut lsp, &uri);
    let found: Vec<&Value> = published
        .iter()
        .filter(|d| d["code"] == "recommended_field_missing")
        .collect();
    assert_eq!(found.len(), 1, "{published:#?}");
    assert_eq!(found[0]["severity"], 3, "{}", found[0]);
    assert_eq!(found[0]["range"]["start"]["line"], 0, "{}", found[0]);
    assert!(
        found[0]["message"]
            .as_str()
            .unwrap()
            .contains("Recommended field missing: response"),
        "{}",
        found[0]
    );
    drop(lsp);

    std::fs::create_dir_all(root.join(".opentide/configurations")).unwrap();
    std::fs::write(
        root.join(".opentide/configurations/lint.toml"),
        "[recommended]\nenabled = false\n",
    )
    .unwrap();
    let (mut lsp, _) = start(json!({ "capabilities": {}, "rootUri": file_uri(root) }));
    let codes = codes_for(&mut lsp, &uri, &text);
    assert!(
        !codes.contains(&"recommended_field_missing".to_string()),
        "{codes:?}"
    );
    drop(lsp);
    std::fs::write(&path, &full).unwrap();
    std::fs::remove_file(root.join(".opentide/configurations/lint.toml")).unwrap();
    let (mut lsp, _) = start(json!({ "capabilities": {}, "rootUri": file_uri(root) }));
    let codes = codes_for(&mut lsp, &uri, &full);
    assert!(
        !codes.contains(&"recommended_field_missing".to_string()),
        "{codes:?}"
    );
}

/// #219: a file-name rename is offered only where it can land: not
/// for an unsaved `untitled:` buffer, which has no file to rename, and not
/// onto a path another open document already has.
#[test]
fn a_file_name_rename_lands_only_on_a_free_name() {
    let scratch = Scratch::new("filename-slug-no-rename");
    let path = scratch.0.join("objects/rules/not-the-slug.yaml");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let text = fixture(RULE);
    std::fs::write(&path, &text).unwrap();
    let uri = file_uri(&path);
    let whole =
        json!({ "start": { "line": 0, "character": 0 }, "end": { "line": 200, "character": 0 } });
    let renaming = json!({ "workspace": { "workspaceEdit": {
        "documentChanges": true, "resourceOperations": ["create", "rename"]
    } } });
    let (mut lsp, _) = start(json!({ "capabilities": renaming, "rootUri": file_uri(&scratch.0) }));
    open(&mut lsp, &uri, "opentide-yaml", &text);
    published_for(&mut lsp, &uri);
    let suggestion = "process-creation.yaml".to_string();
    let slug = file_name_finding(&text, &suggestion);
    let actions = |lsp: &mut Lsp, uri: &str| {
        lsp.request(
            "textDocument/codeAction",
            json!({ "textDocument": { "uri": uri }, "range": whole, "context": { "diagnostics": [slug] } }),
        )["result"]
            .as_array()
            .unwrap()
            .clone()
    };
    assert_eq!(actions(&mut lsp, &uri).len(), 1);

    // An unsaved buffer: nothing to rename.
    let untitled = "untitled:Untitled-1";
    open(&mut lsp, untitled, "opentide-yaml", &text);
    let found = actions(&mut lsp, untitled);
    assert!(found.is_empty(), "{found:#?}");

    // Another open document has the target path, not yet on disk.
    let taken = file_uri(&path.with_file_name(&suggestion));
    open(&mut lsp, &taken, "opentide-yaml", &text);
    let found = actions(&mut lsp, &uri);
    assert!(found.is_empty(), "{found:#?}");
}

/// P3.6: closed files are checked too, for a client that pulls.
#[test]
fn workspace_diagnostics_cover_closed_files() {
    let scratch = workspace("workspace-diagnostics", false);
    let capabilities = json!({
        "textDocument": { "diagnostic": { "dynamicRegistration": false } },
        "workspace": { "diagnostics": { "refreshSupport": true } }
    });
    let (mut lsp, init) =
        start(json!({ "capabilities": capabilities, "rootUri": file_uri(&scratch.0) }));
    assert_eq!(
        init["capabilities"]["diagnosticProvider"]["workspaceDiagnostics"],
        true
    );
    let report = lsp.request("workspace/diagnostic", json!({ "previousResultIds": [] }));
    let items = report["result"]["items"].as_array().unwrap();
    assert_eq!(items.len(), 1, "{report}");
    let rule = &items[0];
    assert!(rule["uri"].as_str().unwrap().ends_with("rule-1.0.yaml"));
    assert_eq!(rule["kind"], "full");
    let codes = codes_of(rule["items"].as_array().unwrap());
    assert!(codes.contains(&"invalid_ref".to_string()), "{codes:?}");
    // Asked again with its id: unchanged.
    let again = lsp.request(
        "workspace/diagnostic",
        json!({ "previousResultIds": [{ "uri": rule["uri"], "value": rule["resultId"] }] }),
    );
    assert_eq!(again["result"]["items"][0]["kind"], "unchanged", "{again}");
}

/// The editor's client pulls the workspace's diagnostics again two seconds
/// after every answer, for as long as it runs: a closed file's analysis is
/// made once, not on every pull, and typing in an object (or editing one on
/// disk) does not make it again, since no other object's analysis reads it.
/// A configuration change does.
#[test]
fn a_workspace_pull_analyses_each_closed_file_once() {
    let scratch = workspace("workspace-pull-cache", true);
    let capabilities = json!({
        "textDocument": { "diagnostic": { "dynamicRegistration": false } },
        "workspace": {
            "diagnostics": { "refreshSupport": true },
            "didChangeWatchedFiles": { "dynamicRegistration": true }
        }
    });
    let (mut lsp, _) =
        start(json!({ "capabilities": capabilities, "rootUri": file_uri(&scratch.0) }));
    let objective = file_uri(&scratch.0.join("objects/objectives/objective-1.0.yaml"));
    let objective_text = fixture(OBJECTIVE);
    open(&mut lsp, &objective, "opentide-yaml", &objective_text);
    let closed_analyses = |lsp: &mut Lsp| {
        lsp.request("opentide/__stats", Value::Null)["result"]["closedAnalyses"]
            .as_u64()
            .unwrap()
    };
    let pull = |lsp: &mut Lsp| {
        let report = lsp.request("workspace/diagnostic", json!({ "previousResultIds": [] }));
        report["result"]["items"].as_array().unwrap().len()
    };
    // The rule is the one closed file; the objective is open.
    assert_eq!(pull(&mut lsp), 1);
    assert_eq!(closed_analyses(&mut lsp), 1);
    assert_eq!(pull(&mut lsp), 1);
    assert_eq!(
        closed_analyses(&mut lsp),
        1,
        "the second pull analysed again"
    );

    // A keystroke in the open object changes what the workspace's findings
    // are, not how the rule is analysed.
    lsp.notify(
        "textDocument/didChange",
        json!({ "textDocument": { "uri": objective, "version": 2 },
                "contentChanges": [{ "text": format!("{objective_text}\n# typed\n") }] }),
    );
    assert_eq!(pull(&mut lsp), 1);
    assert_eq!(
        closed_analyses(&mut lsp),
        1,
        "a keystroke made every closed file analysed again"
    );

    // A configuration file changed on disk is read by every analysis.
    lsp.notify(
        "workspace/didChangeWatchedFiles",
        json!({ "changes": [{
            "uri": file_uri(&scratch.0.join(".opentide/configurations/platforms/sentinel.toml")),
            "type": 2
        }] }),
    );
    assert_eq!(pull(&mut lsp), 1);
    assert_eq!(
        closed_analyses(&mut lsp),
        2,
        "a configuration change kept the old analysis"
    );
}

/// The client pulls again two seconds after every answer: when nothing changed
/// since, the answer is the last one, not made again, and an edit (or any other
/// change of what an analysis reads) makes it again.
#[test]
fn a_workspace_pull_with_nothing_changed_is_answered_from_the_last_report() {
    let scratch = workspace("workspace-pull-report", true);
    let capabilities = json!({
        "textDocument": { "diagnostic": { "dynamicRegistration": false } },
        "workspace": {
            "diagnostics": { "refreshSupport": true },
            "didChangeWatchedFiles": { "dynamicRegistration": true }
        }
    });
    let (mut lsp, _) =
        start(json!({ "capabilities": capabilities, "rootUri": file_uri(&scratch.0) }));
    let objective = file_uri(&scratch.0.join("objects/objectives/objective-1.0.yaml"));
    let objective_text = fixture(OBJECTIVE);
    open(&mut lsp, &objective, "opentide-yaml", &objective_text);
    let hits = |lsp: &mut Lsp| {
        lsp.request("opentide/__stats", Value::Null)["result"]["workspaceReportHits"]
            .as_u64()
            .unwrap()
    };
    let pull = |lsp: &mut Lsp, previous: Value| {
        lsp.request(
            "workspace/diagnostic",
            json!({ "previousResultIds": previous }),
        )
    };
    let first = pull(&mut lsp, json!([]));
    assert_eq!(hits(&mut lsp), 0);
    let rule = &first["result"]["items"][0];
    let again = pull(&mut lsp, json!([]));
    assert_eq!(hits(&mut lsp), 1, "the second pull was made again");
    assert_eq!(first["result"], again["result"], "a cached report differs");
    // What the client sends back, the cached report answers as unchanged.
    let third = pull(
        &mut lsp,
        json!([{ "uri": rule["uri"], "value": rule["resultId"] }]),
    );
    assert_eq!(hits(&mut lsp), 2);
    assert_eq!(third["result"]["items"][0]["kind"], "unchanged", "{third}");

    // A keystroke in an open object: what the workspace's findings are may
    // have changed, so the report is made again.
    lsp.notify(
        "textDocument/didChange",
        json!({ "textDocument": { "uri": objective, "version": 2 },
                "contentChanges": [{ "text": format!("{objective_text}\n# typed\n") }] }),
    );
    pull(&mut lsp, json!([]));
    assert_eq!(
        hits(&mut lsp),
        2,
        "a pull after an edit came from the old report"
    );
    pull(&mut lsp, json!([]));
    assert_eq!(hits(&mut lsp), 3);
}

/// The codes of the diagnostics a workspace pull reports for the closed rule.
fn workspace_pull_codes(lsp: &mut Lsp) -> Vec<String> {
    let report = lsp.request("workspace/diagnostic", json!({ "previousResultIds": [] }));
    let items = report["result"]["items"]
        .as_array()
        .unwrap_or_else(|| panic!("{report}"));
    let rule = items
        .iter()
        .find(|item| {
            item["uri"]
                .as_str()
                .is_some_and(|uri| uri.ends_with("rule-1.0.yaml"))
        })
        .unwrap_or_else(|| panic!("no report for the rule: {report}"));
    codes_of(rule["items"].as_array().unwrap_or(&Vec::new()))
}

fn workspace_pulling() -> Value {
    pulling(json!({ "workspace": { "diagnostics": { "refreshSupport": true } } }))
}

/// A client that does not watch files has the disk read again with each
/// batch, and the configuration resolved again: what a workspace pull
/// reports for a closed file follows a configuration written under it,
/// as it did before the pull's report was kept.
#[test]
fn without_a_watcher_a_workspace_pull_follows_a_configuration_written_on_disk() {
    let scratch = workspace("workspace-pull-no-watcher", true);
    let root = &scratch.0;
    let (mut lsp, _) =
        start(json!({ "capabilities": workspace_pulling(), "rootUri": file_uri(root) }));
    // The objective is open; the rule is the closed file the pull reports.
    let objective = file_uri(&root.join("objects/objectives/objective-1.0.yaml"));
    open(&mut lsp, &objective, "opentide-yaml", &fixture(OBJECTIVE));
    let unknown = "config_enum_unknown".to_string();
    let codes = workspace_pull_codes(&mut lsp);
    assert!(!codes.contains(&unknown), "{codes:?}");

    let configurations = root.join(".opentide/configurations");
    std::fs::create_dir_all(&configurations).unwrap();
    std::fs::write(configurations.join("deployment.toml"), DESIGN_ONLY).unwrap();
    let codes = workspace_pull_codes(&mut lsp);
    assert!(
        codes.contains(&unknown),
        "a cached report hid the new configuration: {codes:?}"
    );

    std::fs::remove_file(configurations.join("deployment.toml")).unwrap();
    let codes = workspace_pull_codes(&mut lsp);
    assert!(!codes.contains(&unknown), "{codes:?}");
}

/// An object folder `paths.toml` moved is read by `validate`, not by the
/// object index: a file changed there changes what the workspace pull says of
/// a rule that references it. The server asks the client to watch the folder,
/// and the event it sends makes the pull follow the disk.
#[test]
fn a_moved_object_folders_file_changed_on_disk_is_followed_by_the_next_pull() {
    let scratch = workspace("workspace-pull-moved-folder", false);
    let root = &scratch.0;
    let configurations = root.join(".opentide/configurations");
    std::fs::create_dir_all(&configurations).unwrap();
    std::fs::write(
        configurations.join("paths.toml"),
        "[paths.objects]\nobjective = \"objectives-moved/\"\n",
    )
    .unwrap();
    let moved = root.join("objectives-moved");
    std::fs::create_dir_all(&moved).unwrap();
    let objective = moved.join("objective-1.0.yaml");
    std::fs::write(&objective, fixture(OBJECTIVE)).unwrap();

    let capabilities = json!({
        "textDocument": { "diagnostic": { "dynamicRegistration": false } },
        "workspace": {
            "diagnostics": { "refreshSupport": true },
            "didChangeWatchedFiles": { "dynamicRegistration": true, "relativePatternSupport": true }
        }
    });
    let (mut lsp, _) = start(json!({ "capabilities": capabilities, "rootUri": file_uri(root) }));
    let invalid = "invalid_ref".to_string();
    let codes = workspace_pull_codes(&mut lsp);
    assert!(!codes.contains(&invalid), "{codes:?}");

    std::fs::remove_file(&objective).unwrap();
    lsp.notify(
        "workspace/didChangeWatchedFiles",
        json!({ "changes": [{ "uri": file_uri(&objective), "type": 3 }] }),
    );
    let codes = workspace_pull_codes(&mut lsp);
    assert!(
        codes.contains(&invalid),
        "the pull did not follow the moved folder's file: {codes:?}"
    );
}

/// Every message the server sent the client since the last call (requests and
/// notifications), gathered as [`server_requests`] does.
fn server_messages(lsp: &mut Lsp) -> Vec<Value> {
    let mut seen = Vec::new();
    for id in [7000, 7001] {
        send(lsp, id, "opentide/__stats", Value::Null);
        seen.extend(
            until_response(lsp, id)
                .into_iter()
                .filter(|m| !(m["id"] == id && m.get("method").is_none())),
        );
    }
    seen
}

/// Every request the server sent the client since the last call: a request
/// the test sends in between is answered after them.
fn server_requests(lsp: &mut Lsp) -> Vec<Value> {
    // What the server asks after a batch is written after its answers: a second
    // request, answered in a batch of its own, gathers it.
    let mut asked = Vec::new();
    for id in [7000, 7001] {
        send(lsp, id, "opentide/__stats", Value::Null);
        asked.extend(
            until_response(lsp, id)
                .into_iter()
                .filter(|m| m.get("method").is_some() && m.get("id").is_some()),
        );
    }
    asked
}

/// The watchers of the registrations among `requests`, as `(base, pattern)`:
/// a relative pattern's folder and glob, or `("", glob)` for a string.
fn registered_watchers(requests: &[Value]) -> Vec<(String, String)> {
    let mut watchers = Vec::new();
    for request in requests {
        if request["method"] != "client/registerCapability" {
            continue;
        }
        for registration in request["params"]["registrations"].as_array().unwrap() {
            for watcher in registration["registerOptions"]["watchers"]
                .as_array()
                .unwrap()
            {
                let glob = &watcher["globPattern"];
                watchers.push(match glob.as_str() {
                    Some(text) => (String::new(), text.to_string()),
                    None => (
                        glob["baseUri"].as_str().unwrap().to_string(),
                        glob["pattern"].as_str().unwrap().to_string(),
                    ),
                });
            }
        }
    }
    watchers
}

/// What the workspace's own folders ask: the watchers outside the scratch
/// folder's parent, whose `.opentide/configurations/` is layered in whatever
/// is above the test's folder.
fn own_watchers(requests: &[Value], root: &std::path::Path) -> Vec<(String, String)> {
    let layered = root.parent().unwrap().join(".opentide/configurations");
    let by_path = format!(
        "{}/**/*.toml",
        layered.display().to_string().replace('\\', "/")
    );
    let layered = file_uri(&layered);
    registered_watchers(requests)
        .into_iter()
        .filter(|(base, glob)| !(*base == layered && glob == "**/*.toml") && *glob != by_path)
        .collect()
}

fn watching_relative() -> Value {
    json!({
        "textDocument": { "diagnostic": { "dynamicRegistration": false } },
        "workspace": {
            "diagnostics": { "refreshSupport": true },
            "didChangeWatchedFiles": { "dynamicRegistration": true, "relativePatternSupport": true }
        }
    })
}

/// `paths.toml` in `root`, naming where the objectives are.
fn move_objectives(root: &std::path::Path, folder: &str) -> std::path::PathBuf {
    let configurations = root.join(".opentide/configurations");
    std::fs::create_dir_all(&configurations).unwrap();
    std::fs::write(
        configurations.join("paths.toml"),
        format!("[paths.objects]\nobjective = \"{folder}/\"\n"),
    )
    .unwrap();
    root.join(folder)
}

/// The folders the loaded workspace reads (where `paths.toml` put the
/// objects, a parent's configuration) are watched, from the moment the
/// workspace is loaded, and again when `paths.toml` moves one.
#[test]
fn the_folders_a_workspace_reads_are_watched_and_watched_again_when_they_move() {
    let scratch = workspace("workspace-watch-folders", false);
    let root = &scratch.0;
    let moved = move_objectives(root, "objectives-moved");
    std::fs::create_dir_all(&moved).unwrap();
    std::fs::write(moved.join("objective-1.0.yaml"), fixture(OBJECTIVE)).unwrap();
    let (mut lsp, _) =
        start(json!({ "capabilities": watching_relative(), "rootUri": file_uri(root) }));
    // `paths.toml`'s folders are not known before the workspace loads.
    let first = server_requests(&mut lsp);
    let fixed = registered_watchers(&first);
    assert!(
        fixed
            .iter()
            .any(|(_, glob)| glob == "**/.opentide/states/deployment/**"),
        "the state shards are not watched: {fixed:?}"
    );
    assert!(
        !fixed
            .iter()
            .any(|(base, _)| base.contains("objectives-moved")),
        "{fixed:?}"
    );

    workspace_pull_codes(&mut lsp);
    let after_load = server_requests(&mut lsp);
    assert_eq!(
        own_watchers(&after_load, root),
        vec![(file_uri(&moved), "**".to_string())],
        "{after_load:#?}"
    );

    // Nothing changed: nothing is asked again.
    workspace_pull_codes(&mut lsp);
    assert!(server_requests(&mut lsp).is_empty());

    // `paths.toml` moves the objectives: the old folder is let go of.
    let elsewhere = move_objectives(root, "objectives-elsewhere");
    std::fs::create_dir_all(&elsewhere).unwrap();
    lsp.notify(
        "workspace/didChangeWatchedFiles",
        json!({ "changes": [{
            "uri": file_uri(&root.join(".opentide/configurations/paths.toml")),
            "type": 2
        }] }),
    );
    workspace_pull_codes(&mut lsp);
    let moved_again = server_requests(&mut lsp);
    let methods: Vec<&str> = moved_again
        .iter()
        .map(|m| m["method"].as_str().unwrap())
        .filter(|method| method.contains("Capability"))
        .collect();
    assert_eq!(
        methods,
        ["client/unregisterCapability", "client/registerCapability"],
        "{moved_again:#?}"
    );
    assert_eq!(
        own_watchers(&moved_again, root),
        vec![(file_uri(&elsewhere), "**".to_string())]
    );
    let old = moved_again
        .iter()
        .find(|m| m["method"] == "client/unregisterCapability")
        .unwrap()["params"]["unregisterations"][0]["id"]
        .clone();
    let earlier = after_load
        .iter()
        .find(|m| m["method"] == "client/registerCapability")
        .unwrap()["params"]["registrations"][0]["id"]
        .clone();
    assert_eq!(old, earlier, "another registration was let go of");
}

/// A client that cannot watch a folder by a base and a pattern is asked by
/// the folder's whole path.
#[test]
fn a_client_without_relative_patterns_is_asked_to_watch_by_a_path_glob() {
    let scratch = workspace("workspace-watch-glob", false);
    let moved = move_objectives(&scratch.0, "objectives-moved");
    std::fs::create_dir_all(&moved).unwrap();
    let (mut lsp, _) = start(json!({ "capabilities": {
        "textDocument": { "diagnostic": { "dynamicRegistration": false } },
        "workspace": { "diagnostics": { "refreshSupport": true }, "didChangeWatchedFiles": { "dynamicRegistration": true } }
    }, "rootUri": file_uri(&scratch.0) }));
    server_requests(&mut lsp);
    workspace_pull_codes(&mut lsp);
    let watchers = own_watchers(&server_requests(&mut lsp), &scratch.0);
    assert_eq!(
        watchers,
        vec![(
            String::new(),
            format!("{}/**", moved.display().to_string().replace('\\', "/"))
        )]
    );
}

/// A configuration folder layered in from above the root is watched, and a
/// change in it is followed by the next pull.
#[test]
fn a_parents_configuration_folder_is_watched_and_followed() {
    let scratch = workspace("workspace-watch-parent", false);
    let root = scratch.0.join("child");
    std::fs::create_dir_all(root.join("objects/rules")).unwrap();
    std::fs::write(root.join("objects/rules/rule-1.0.yaml"), fixture(RULE)).unwrap();
    let parent = scratch.0.join(".opentide/configurations");
    std::fs::create_dir_all(&parent).unwrap();
    let (mut lsp, _) =
        start(json!({ "capabilities": watching_relative(), "rootUri": file_uri(&root) }));
    let mut sent = Vec::new();
    all_server_requests(&mut lsp, &mut sent);
    let unknown = "config_enum_unknown".to_string();
    assert!(!workspace_pull_codes(&mut lsp).contains(&unknown));
    all_server_requests(&mut lsp, &mut sent);
    let watchers = watchers_in_force(&sent);
    assert!(
        watchers.contains(&(file_uri(&parent), "**/*.toml".to_string())),
        "{watchers:?}"
    );

    std::fs::write(parent.join("deployment.toml"), DESIGN_ONLY).unwrap();
    lsp.notify(
        "workspace/didChangeWatchedFiles",
        json!({ "changes": [{ "uri": file_uri(&parent.join("deployment.toml")), "type": 1 }] }),
    );
    let codes = workspace_pull_codes(&mut lsp);
    assert!(
        codes.contains(&unknown),
        "the parent's configuration was not followed: {codes:?}"
    );
}

/// A deployment state shard is read by `validate` alone: its event makes the
/// workspace's findings be made again, and no analysis.
#[test]
fn a_state_shard_written_on_disk_makes_the_next_pull_be_made_again() {
    let scratch = workspace("workspace-watch-shard", true);
    let root = &scratch.0;
    let (mut lsp, _) =
        start(json!({ "capabilities": watching_relative(), "rootUri": file_uri(root) }));
    let objective = file_uri(&root.join("objects/objectives/objective-1.0.yaml"));
    open(&mut lsp, &objective, "opentide-yaml", &fixture(OBJECTIVE));
    let stat = |lsp: &mut Lsp, key: &str| {
        lsp.request("opentide/__stats", Value::Null)["result"][key]
            .as_u64()
            .unwrap()
    };
    workspace_pull_codes(&mut lsp);
    workspace_pull_codes(&mut lsp);
    assert_eq!(stat(&mut lsp, "workspaceReportHits"), 1);
    let analyses = stat(&mut lsp, "closedAnalyses");

    let shards = root.join(".opentide/states/deployment");
    std::fs::create_dir_all(&shards).unwrap();
    let shard = shards.join("00000000-0000-4000-8003-000000000001.json");
    std::fs::write(&shard, "{}").unwrap();
    lsp.notify(
        "workspace/didChangeWatchedFiles",
        json!({ "changes": [{ "uri": file_uri(&shard), "type": 1 }] }),
    );
    workspace_pull_codes(&mut lsp);
    assert_eq!(
        stat(&mut lsp, "workspaceReportHits"),
        1,
        "the pull after a shard was written came from the old report"
    );
    assert_eq!(
        stat(&mut lsp, "closedAnalyses"),
        analyses,
        "a shard changes no analysis"
    );
}

const SHARD_UUID: &str = "00000000-0000-4000-8003-000000000001";

/// A shard of `SHARD_UUID` that `validate` takes: the schema, its own UUID,
/// and a platform's vendor id in the shape it expects.
fn usable_shard() -> String {
    format!(
        r#"{{"schema":"deployment.state::1.0","object_uuid":"{SHARD_UUID}","platforms":{{"sentinel_one":{{"prod":"12"}}}}}}"#
    )
}

/// A workspace pull: its reports for the shard, `(uri, result id, codes)`,
/// with `previous` as the result ids the client holds.
fn shard_reports(
    lsp: &mut Lsp,
    previous: &[(String, String)],
) -> Vec<(String, String, Vec<String>)> {
    let previous: Vec<Value> = previous
        .iter()
        .map(|(uri, id)| json!({ "uri": uri, "value": id }))
        .collect();
    let report = lsp.request(
        "workspace/diagnostic",
        json!({ "previousResultIds": previous }),
    );
    report["result"]["items"]
        .as_array()
        .unwrap_or_else(|| panic!("{report}"))
        .iter()
        .filter(|item| {
            item["uri"].as_str().is_some_and(|uri| {
                uri.ends_with(&format!("/.opentide/states/deployment/{SHARD_UUID}.json"))
            })
        })
        .map(|item| {
            assert_eq!(item["kind"], "full", "{item}");
            (
                item["uri"].as_str().unwrap().to_string(),
                item["resultId"].as_str().unwrap().to_string(),
                codes_of(item["items"].as_array().unwrap_or(&Vec::new())),
            )
        })
        .collect()
}

/// `validate` reports a deployment state shard's findings on the shard
/// (#1750): the workspace pull has an entry for it, made again when the
/// watcher reports the shard changed, and an empty one once it is fixed, so
/// the client does not keep showing what was fixed. A shard's change scans
/// the shards again, and checks no object.
#[test]
fn a_state_shards_findings_are_in_the_workspace_pull_and_clear_when_fixed() {
    let scratch = workspace("workspace-shard-findings", true);
    let root = &scratch.0;
    let (mut lsp, _) =
        start(json!({ "capabilities": watching_relative(), "rootUri": file_uri(root) }));
    let objective = file_uri(&root.join("objects/objectives/objective-1.0.yaml"));
    open(&mut lsp, &objective, "opentide-yaml", &fixture(OBJECTIVE));
    let validations = |lsp: &mut Lsp| {
        let stats = lsp.request("opentide/__stats", Value::Null);
        stats["result"]["validations"]["full"].as_u64().unwrap()
    };
    assert!(shard_reports(&mut lsp, &[]).is_empty(), "no shard yet");
    let full = validations(&mut lsp);

    // A shard deploy wrote, then broke: not a JSON object.
    let shards = root.join(".opentide/states/deployment");
    std::fs::create_dir_all(&shards).unwrap();
    let shard = shards.join(format!("{SHARD_UUID}.json"));
    std::fs::write(&shard, "[]").unwrap();
    let event = |lsp: &mut Lsp, kind: u8| {
        lsp.notify(
            "workspace/didChangeWatchedFiles",
            json!({ "changes": [{ "uri": file_uri(&shard), "type": kind }] }),
        );
    };
    event(&mut lsp, 1);
    let reports = shard_reports(&mut lsp, &[]);
    assert_eq!(reports.len(), 1, "{reports:?}");
    assert_eq!(reports[0].2, vec!["deployment_state_shape"]);
    let (uri, shaped, _) = reports[0].clone();
    assert_eq!(
        validations(&mut lsp),
        full,
        "a shard's change checked every object again"
    );

    // Edited on disk: the finding follows the shard.
    std::fs::write(
        &shard,
        r#"{"schema":"deployment.state::1.0","object_uuid":"00000000-0000-4000-8003-000000000002","platforms":{}}"#,
    )
    .unwrap();
    event(&mut lsp, 2);
    let reports = shard_reports(&mut lsp, &[(uri.clone(), shaped.clone())]);
    assert_eq!(reports.len(), 1, "{reports:?}");
    assert_eq!(reports[0].2, vec!["deployment_state_uuid_mismatch"]);
    assert_ne!(reports[0].1, shaped);
    let mismatched = reports[0].1.clone();

    // Fixed: an empty report replaces the one the client holds, once.
    std::fs::write(&shard, usable_shard()).unwrap();
    event(&mut lsp, 2);
    let reports = shard_reports(&mut lsp, &[(uri.clone(), mismatched)]);
    assert_eq!(
        reports.len(),
        1,
        "the fixed shard was not cleared: {reports:?}"
    );
    assert!(reports[0].2.is_empty(), "{reports:?}");
    let cleared = reports[0].1.clone();
    assert!(
        shard_reports(&mut lsp, &[(uri.clone(), cleared)]).is_empty(),
        "a client that holds the empty report is not sent it again"
    );

    // Broken again, then deleted: the deletion clears it too.
    std::fs::write(&shard, "{").unwrap();
    event(&mut lsp, 2);
    let reports = shard_reports(&mut lsp, &[]);
    assert_eq!(reports.len(), 1, "{reports:?}");
    assert_eq!(reports[0].2, vec!["deployment_state_shape"]);
    let broken = reports[0].1.clone();
    std::fs::remove_file(&shard).unwrap();
    event(&mut lsp, 3);
    let reports = shard_reports(&mut lsp, &[(uri, broken)]);
    assert_eq!(
        reports.len(),
        1,
        "the deleted shard was not cleared: {reports:?}"
    );
    assert!(reports[0].2.is_empty(), "{reports:?}");
    assert_eq!(
        validations(&mut lsp),
        full,
        "a shard's change checked every object again"
    );
}

/// Whether any of `codes` is a `deployment_state_*` code.
fn has_state_code(codes: &[String]) -> bool {
    codes
        .iter()
        .any(|code| code.starts_with("deployment_state_"))
}

/// A closed rule's shard finding is on the shard alone, as `validate` files
/// it on a full run: the runs narrowed to the files an edit or a watched
/// event changed check the rule's shard too, and filed what they found on the
/// rule, where it stayed once the shard was fixed. An open rule shows it, as
/// `validate --file` on the rule does (the editor's diagnostics are
/// `validate`'s, #678), and clears it once the shard is fixed.
#[test]
fn a_rules_shard_finding_is_on_the_shard_and_the_open_rule_and_clears_everywhere() {
    let scratch = workspace("workspace-shard-not-on-rule", true);
    let root = &scratch.0;
    let shards = root.join(".opentide/states/deployment");
    std::fs::create_dir_all(&shards).unwrap();
    // The rule's own shard (the rule's UUID is `SHARD_UUID`), broken.
    let shard = shards.join(format!("{SHARD_UUID}.json"));
    std::fs::write(&shard, "[]").unwrap();
    let (mut lsp, _) =
        start(json!({ "capabilities": watching_relative(), "rootUri": file_uri(root) }));
    let rule_path = root.join("objects/rules/rule-1.0.yaml");
    let rule = file_uri(&rule_path);
    let rule_codes = |lsp: &mut Lsp| -> Vec<String> {
        workspace_pull_items(lsp)
            .into_iter()
            .find(|(uri, _)| uri.ends_with("rule-1.0.yaml"))
            .map(|(_, codes)| codes)
            .unwrap_or_default()
    };
    assert!(!has_state_code(&rule_codes(&mut lsp)));
    assert_eq!(shard_reports(&mut lsp, &[]).len(), 1);

    // The closed rule written on disk: the narrowed run checks it again.
    let text = fixture(RULE);
    std::fs::write(&rule_path, format!("{text}\n")).unwrap();
    lsp.notify(
        "workspace/didChangeWatchedFiles",
        json!({ "changes": [{ "uri": rule, "type": 2 }] }),
    );
    let codes = rule_codes(&mut lsp);
    assert!(!has_state_code(&codes), "the closed rule: {codes:?}");
    let reports = shard_reports(&mut lsp, &[]);
    assert_eq!(reports.len(), 1, "{reports:?}");
    assert_eq!(reports[0].2, vec!["deployment_state_shape"]);

    // The rule open, then typed in.
    open(&mut lsp, &rule, "opentide-yaml", &text);
    lsp.notify(
        "textDocument/didChange",
        json!({ "textDocument": { "uri": rule, "version": 2 },
                "contentChanges": [{ "text": format!("{text}\n\n") }] }),
    );
    let codes = pulled(&mut lsp, &rule);
    assert!(
        codes.iter().any(|code| code == "deployment_state_shape"),
        "the open rule: {codes:?}"
    );
    assert_eq!(shard_reports(&mut lsp, &[]).len(), 1);

    // Fixed: gone from the shard, and on neither rule nor shard after.
    std::fs::write(&shard, usable_shard()).unwrap();
    lsp.notify(
        "workspace/didChangeWatchedFiles",
        json!({ "changes": [{ "uri": file_uri(&shard), "type": 2 }] }),
    );
    assert!(shard_reports(&mut lsp, &[]).is_empty());
    let codes = pulled(&mut lsp, &rule);
    assert!(!has_state_code(&codes), "the open rule: {codes:?}");
}

/// An open rule whose shard is broken shows what `validate --file` on the
/// rule reports, where it reports it (#1750): the shard's finding on the
/// rule, over the first line. The language server's parity with `validate`
/// (`cargo xtask lsp parity`, `deployment-state-*`) failed on it when the
/// server dropped it. Before a workspace pull the open rule is checked on its
/// own; after one it is read from the findings of every object, a full run's,
/// which have the finding on the shard: the same finding is added.
#[test]
fn an_open_rule_shows_its_shard_finding_as_validate_file_does() {
    let scratch = workspace("workspace-shard-open-rule", true);
    let root = &scratch.0;
    let shards = root.join(".opentide/states/deployment");
    std::fs::create_dir_all(&shards).unwrap();
    let shard = shards.join(format!("{SHARD_UUID}.json"));
    std::fs::write(&shard, "[]").unwrap();
    let (mut lsp, _) =
        start(json!({ "capabilities": watching_relative(), "rootUri": file_uri(root) }));
    let rule_path = root.join("objects/rules/rule-1.0.yaml");
    let rule = file_uri(&rule_path);
    let text = std::fs::read_to_string(&rule_path).unwrap();
    open(&mut lsp, &rule, "opentide-yaml", &text);
    let first = text.lines().next().unwrap_or("");
    let over_the_first_line = json!({ "start": { "line": 0, "character": 0 },
        "end": { "line": 0, "character": first.encode_utf16().count() } });
    let state_of = |lsp: &mut Lsp| -> Vec<Value> {
        let report = lsp.request(
            "textDocument/diagnostic",
            json!({ "textDocument": { "uri": rule } }),
        );
        report["result"]["items"]
            .as_array()
            .unwrap_or_else(|| panic!("{report}"))
            .iter()
            .filter(|item| item["code"] == "deployment_state_shape")
            .cloned()
            .collect()
    };
    let state = state_of(&mut lsp);
    assert_eq!(state.len(), 1, "{state:?}");
    assert_eq!(state[0]["severity"], 1);
    assert_eq!(state[0]["range"], over_the_first_line, "{state:?}");

    // The findings of every object made, then the rule typed in.
    assert_eq!(shard_reports(&mut lsp, &[]).len(), 1);
    lsp.notify(
        "textDocument/didChange",
        json!({ "textDocument": { "uri": rule, "version": 2 },
                "contentChanges": [{ "text": format!("{text}\n") }] }),
    );
    let state = state_of(&mut lsp);
    assert_eq!(state.len(), 1, "{state:?}");
    assert_eq!(state[0]["range"], over_the_first_line, "{state:?}");

    // Fixed on disk: the open rule clears.
    std::fs::write(&shard, usable_shard()).unwrap();
    lsp.notify(
        "workspace/didChangeWatchedFiles",
        json!({ "changes": [{ "uri": file_uri(&shard), "type": 2 }] }),
    );
    let codes = pulled(&mut lsp, &rule);
    assert!(!has_state_code(&codes), "the open rule: {codes:?}");
}

/// `validate` walks the folders below `deployment/` and reports a shard in
/// one (deploy never reads it): the watchers cover them, so such a shard is
/// shown, and cleared when it is deleted.
#[test]
fn a_shard_in_a_folder_below_deployment_is_shown_and_cleared() {
    let scratch = workspace("workspace-shard-subfolder", true);
    let root = &scratch.0;
    let (mut lsp, _) =
        start(json!({ "capabilities": watching_relative(), "rootUri": file_uri(root) }));
    let fixed = registered_watchers(&server_requests(&mut lsp));
    assert!(
        fixed
            .iter()
            .any(|(_, glob)| glob == "**/.opentide/states/deployment/**"),
        "the folders below deployment/ are not watched: {fixed:?}"
    );
    let objective = file_uri(&root.join("objects/objectives/objective-1.0.yaml"));
    open(&mut lsp, &objective, "opentide-yaml", &fixture(OBJECTIVE));
    let nested_reports = |lsp: &mut Lsp, previous: Value| -> Vec<(String, Vec<String>)> {
        let report = lsp.request(
            "workspace/diagnostic",
            json!({ "previousResultIds": previous }),
        );
        report["result"]["items"]
            .as_array()
            .unwrap_or_else(|| panic!("{report}"))
            .iter()
            .filter(|item| {
                item["uri"]
                    .as_str()
                    .is_some_and(|uri| uri.contains("/.opentide/states/deployment/old/"))
            })
            .map(|item| {
                (
                    item["resultId"].as_str().unwrap().to_string(),
                    codes_of(item["items"].as_array().unwrap_or(&Vec::new())),
                )
            })
            .collect()
    };
    assert!(nested_reports(&mut lsp, json!([])).is_empty());

    let old = root.join(".opentide/states/deployment/old");
    std::fs::create_dir_all(&old).unwrap();
    let shard = old.join(format!("{SHARD_UUID}.json"));
    std::fs::write(&shard, usable_shard()).unwrap();
    lsp.notify(
        "workspace/didChangeWatchedFiles",
        json!({ "changes": [{ "uri": file_uri(&shard), "type": 1 }] }),
    );
    let reports = nested_reports(&mut lsp, json!([]));
    assert_eq!(reports.len(), 1, "{reports:?}");
    assert_eq!(reports[0].1, vec!["deployment_state_uuid_mismatch"]);
    let held = reports[0].0.clone();

    // The folder deleted: one event, for the folder.
    std::fs::remove_dir_all(&old).unwrap();
    lsp.notify(
        "workspace/didChangeWatchedFiles",
        json!({ "changes": [{ "uri": file_uri(&old), "type": 3 }] }),
    );
    let reports = nested_reports(
        &mut lsp,
        json!([{ "uri": file_uri(&shard), "value": held }]),
    );
    assert_eq!(
        reports.len(),
        1,
        "the deleted shard was not cleared: {reports:?}"
    );
    assert!(reports[0].1.is_empty(), "{reports:?}");
}

/// A shard broken before the server started is in the first workspace pull
/// (the run over every object scans the shards), placed at the start of the
/// file, and a document pull for it, as a client that has it open sends,
/// says the same.
#[test]
fn a_broken_shard_on_disk_is_in_the_first_pull_and_a_document_pull() {
    let scratch = workspace("workspace-shard-first-pull", true);
    let root = &scratch.0;
    let shards = root.join(".opentide/states/deployment");
    std::fs::create_dir_all(&shards).unwrap();
    let shard = shards.join(format!("{SHARD_UUID}.json"));
    std::fs::write(&shard, r#"{"schema":"x"}"#).unwrap();
    let (mut lsp, _) =
        start(json!({ "capabilities": watching_relative(), "rootUri": file_uri(root) }));
    let reports = shard_reports(&mut lsp, &[]);
    assert_eq!(reports.len(), 1, "{reports:?}");
    assert_eq!(reports[0].2, vec!["deployment_state_shape"]);

    let report = lsp.request(
        "textDocument/diagnostic",
        json!({ "textDocument": { "uri": file_uri(&shard) } }),
    );
    let items = report["result"]["items"]
        .as_array()
        .unwrap_or_else(|| panic!("{report}"));
    assert_eq!(codes_of(items), vec!["deployment_state_shape"], "{report}");
    assert_eq!(items[0]["source"], "opentide");
    assert_eq!(items[0]["severity"], 1);
    assert_eq!(
        items[0]["range"]["start"],
        json!({ "line": 0, "character": 0 })
    );
}

/// Typing in an object checks that object, not every object of the workspace
/// again: the findings of every object are made once, and an edit that leaves
/// what other objects' checks read as it was (a UUID, a name) checks the file
/// it changed alone; one that changes a name checks them all again, as the
/// other objects may now be told of it.
#[test]
fn a_keystroke_checks_the_file_it_changed_not_every_object() {
    let scratch = workspace("workspace-pull-incremental", true);
    let (mut lsp, _) = start(json!({
        "capabilities": watching_relative(),
        "rootUri": file_uri(&scratch.0)
    }));
    let objective = file_uri(&scratch.0.join("objects/objectives/objective-1.0.yaml"));
    let text = fixture(OBJECTIVE);
    open(&mut lsp, &objective, "opentide-yaml", &text);
    let validations = |lsp: &mut Lsp| {
        let stats = lsp.request("opentide/__stats", Value::Null);
        (
            stats["result"]["validations"]["full"].as_u64().unwrap(),
            stats["result"]["validations"]["partial"].as_u64().unwrap(),
        )
    };
    let edit = |lsp: &mut Lsp, version: i32, text: &str| {
        lsp.notify(
            "textDocument/didChange",
            json!({ "textDocument": { "uri": objective, "version": version },
                    "contentChanges": [{ "text": text }] }),
        );
        workspace_pull_codes(lsp)
    };
    workspace_pull_codes(&mut lsp);
    assert_eq!(
        validations(&mut lsp),
        (1, 0),
        "the first pull checks everything"
    );

    edit(&mut lsp, 2, &format!("{text}\n# typed\n"));
    assert_eq!(
        validations(&mut lsp),
        (1, 1),
        "a typed line checked every object again"
    );
    edit(&mut lsp, 3, &format!("{text}\n# typed again\n"));
    assert_eq!(validations(&mut lsp), (1, 2));

    let renamed = text.replacen("name: ", "name: Renamed ", 1);
    assert_ne!(renamed, text, "the fixture has a name");
    edit(&mut lsp, 4, &renamed);
    assert_eq!(
        validations(&mut lsp),
        (2, 2),
        "a new name did not check every object again"
    );
}

/// A client that resolves a completion item's detail and reads `itemDefaults`
/// is sent the list of a Tide field's values (the ATT&CK techniques) as
/// labels: what every item would say again (the data `completionItem/resolve`
/// reads, the range each replaces) is said once. Applied as the client
/// applies them, the items are what a client that reads neither gets.
#[test]
fn the_values_of_a_tide_field_are_listed_by_label_and_say_the_same_once() {
    let text = fixture(RULE).replacen("  - T1059\n", "  - T10\n", 1);
    let line = text.lines().position(|l| l == "  - T10").unwrap();
    let uri = "file:///tmp/objects/rules/techniques.yaml";
    let complete = |capabilities: Value| {
        let (mut lsp, _) = start(json!({ "capabilities": capabilities }));
        open(&mut lsp, uri, "opentide-yaml", &text);
        let list = lsp.request(
            "textDocument/completion",
            json!({
                "textDocument": { "uri": uri },
                "position": { "line": line, "character": 7 }
            }),
        );
        (lsp, list["result"].clone())
    };
    let (mut plain, whole) = complete(json!({}));
    let whole = whole
        .as_array()
        .expect("an array for a client with no defaults");
    let (mut lsp, list) = complete(json!({ "textDocument": { "completion": {
        "completionItem": {
            "labelDetailsSupport": true,
            "resolveSupport": { "properties": ["documentation", "detail"] }
        },
        "completionList": { "itemDefaults": ["commitCharacters", "editRange", "data"] }
    } } }));
    let items = list["items"]
        .as_array()
        .expect("a list for a client with defaults");
    // The techniques from T1000 to T1099 and their sub-techniques, each once
    // (each was listed twice, with its search hint, before #1745).
    assert!(whole.len() > 150, "the ATT&CK list: {}", whole.len());
    assert_eq!(items.len(), whole.len());
    assert_eq!(list["isIncomplete"], false);
    let size = |value: &Value| serde_json::to_string(value).unwrap().len();
    // A label, a kind, the name shown beside it and the text it is found by
    // (the label, the name and the aliases), and where it differs, the text:
    // about 64 bytes an item besides what it names, where each item that says
    // its data and its range again takes 330 more.
    // A label, a kind, the technique's name beside it (`labelDetails`) and the
    // text it is found by (the value, the name and the aliases): 167 bytes an
    // item here (30.8 KB for 185 techniques), where each item that says its
    // data and its range again takes 360.
    assert!(
        size(&list) < items.len() * 180,
        "labels: {} bytes for {} items, whole: {} bytes",
        size(&list),
        items.len(),
        size(&Value::Array(whole.clone()))
    );
    let defaults = &list["itemDefaults"];
    for (item, held) in items.iter().zip(whole).take(60) {
        // What the client makes of the item and the defaults.
        assert_eq!(item["label"], held["label"]);
        for key in ["data", "textEdit", "detail", "documentation"] {
            assert!(
                item.get(key).is_none(),
                "{key} is said once or resolved: {item}"
            );
        }
        let text = item.get("textEditText").unwrap_or(&item["label"]);
        assert_eq!(*text, held["textEdit"]["newText"]);
        assert_eq!(defaults["editRange"], held["textEdit"]["range"]);
        assert_eq!(defaults["data"], held["data"]);
        // And what resolving it gives, as a client sends it back.
        let mut sent = item.clone();
        sent["data"] = defaults["data"].clone();
        let resolved = lsp.request("completionItem/resolve", sent);
        let expected = plain.request("completionItem/resolve", held.clone());
        assert_eq!(
            resolved["result"]["documentation"],
            expected["result"]["documentation"]
        );
        assert_eq!(resolved["result"]["detail"], expected["result"]["detail"]);
        assert!(resolved["result"]["detail"].is_string(), "{resolved}");
    }
}

/// Each item's `(label, documentation, detail)`.
type Items = Vec<(String, Value, Value)>;

/// What a client that resolves documentation makes of each item at `line` and
/// `character` of `text` (the item, then resolved as the client sends it back)
/// is what a client that does not gets: `(label, documentation, detail)`.
fn resolved_and_plain(
    language: &str,
    uri: &str,
    text: &str,
    line: usize,
    character: usize,
) -> (Items, Items) {
    let complete = |capabilities: Value| {
        let (mut lsp, _) = start(json!({ "capabilities": capabilities }));
        open(&mut lsp, uri, language, text);
        let list = lsp.request(
            "textDocument/completion",
            json!({
                "textDocument": { "uri": uri },
                "position": { "line": line, "character": character }
            }),
        );
        let result = list["result"].clone();
        let defaults = result["itemDefaults"].clone();
        let items = result
            .as_array()
            .or_else(|| result["items"].as_array())
            .unwrap_or_else(|| panic!("{result}"))
            .clone();
        (lsp, items, defaults)
    };
    let (_plain_lsp, plain, _) = complete(json!({}));
    let (mut lsp, items, defaults) = complete(json!({ "textDocument": { "completion": {
        "completionItem": { "resolveSupport": { "properties": ["documentation", "detail"] } },
        "completionList": { "itemDefaults": ["commitCharacters", "editRange", "data"] }
    } } }));
    let resolved = items
        .iter()
        .map(|item| {
            let mut sent = item.clone();
            if sent.get("data").is_none() {
                sent["data"] = defaults["data"].clone();
            }
            let answer = lsp.request("completionItem/resolve", sent);
            let result = &answer["result"];
            (
                result["label"].as_str().unwrap().to_string(),
                result["documentation"].clone(),
                result["detail"].clone(),
            )
        })
        .collect();
    let plain = plain
        .iter()
        .map(|item| {
            (
                item["label"].as_str().unwrap().to_string(),
                item["documentation"].clone(),
                item["detail"].clone(),
            )
        })
        .collect();
    (resolved, plain)
}

/// A value that is not a field of the Tide models (an ECS value, a Bitdefender
/// target, `configurations.elastic.type`) keeps the documentation and the
/// detail the list gave it when the client resolves them: resolving gives it
/// no other field's.
#[test]
fn values_outside_the_tide_models_keep_their_documentation_when_resolved() {
    let head = "name: GravityZone rule
metadata:
  uuid: 00000000-0000-4000-8003-000000000098
  schema: rule::1.0
  version: 1
  created: 2026-01-01
  modified: 2026-01-02
  tlp: clear
description: A GravityZone rule.
response:
  alert_severity: Critical
configurations:
  bitdefender:
    enabled: true
    schema: platform::bitdefender::1.0
    status: STAGING
";
    let bitdefender = format!("{head}    detection:\n      target: reg\n");
    let elastic = "name: Elastic rule
metadata:
  uuid: 00000000-0000-4000-8003-000000000099
  schema: rule::1.0
  version: 1
configurations:
  elastic:
    enabled: true
    schema: platform::elastic::1.0
    status: STAGING
    type: ";
    let kuery = "event.category : ";
    let secops = "name: Google SecOps rule
metadata:
  uuid: 00000000-0000-4000-8003-000000000097
  schema: rule::1.0
  version: 1
configurations:
  google_secops:
    enabled: true
    schema: platform::google_secops::1.0
    status: STAGING
    severity: ";
    // `(language, uri, text, line, character, documented)`: whether any item
    // of the site is documented by the list.
    let sites: [(&str, &str, String, usize, usize, bool); 4] = [
        (
            "opentide-yaml",
            "file:///tmp/objects/rules/bitdefender.yaml",
            bitdefender.clone(),
            bitdefender.lines().count() - 1,
            "      target: reg".len(),
            true,
        ),
        (
            "opentide-yaml",
            "file:///tmp/objects/rules/elastic.yaml",
            elastic.to_string(),
            elastic.lines().count() - 1,
            "    type: ".len(),
            true,
        ),
        (
            "kuery",
            "file:///tmp/ecs.kuery",
            kuery.to_string(),
            0,
            kuery.len(),
            true,
        ),
        // `Low`, `Medium` and `High` are values of other fields too, which
        // document them (the objective's severity SLAs): this field says
        // nothing of them, and resolving does not take theirs.
        (
            "opentide-yaml",
            "file:///tmp/objects/rules/secops.yaml",
            secops.to_string(),
            secops.lines().count() - 1,
            "    severity: ".len(),
            false,
        ),
    ];
    for (language, uri, text, line, character, documented) in sites {
        let (resolved, plain) = resolved_and_plain(language, uri, &text, line, character);
        assert!(!plain.is_empty(), "no completion at {uri}");
        assert_eq!(
            plain.iter().any(|(_, docs, _)| !docs.is_null()),
            documented,
            "what the list documents at {uri}: {plain:?}"
        );
        assert_eq!(resolved, plain, "resolving changed an item at {uri}");
    }
    // An item that names no field is documented from none, by its label.
    let (mut lsp, _) = start(json!({ "capabilities": {} }));
    for label in ["High", "query", "description"] {
        let bare = lsp.request(
            "completionItem/resolve",
            json!({ "label": label, "kind": 20 }),
        );
        assert!(
            bare["result"]
                .get("documentation")
                .is_none_or(Value::is_null),
            "{label} was documented by its label: {bare}"
        );
    }
}

/// The watchers in force after `requests`, in the order the server sent them:
/// each registration's, less those unregistered.
fn watchers_in_force(requests: &[Value]) -> Vec<(String, String)> {
    let mut registrations: Vec<(String, Vec<(String, String)>)> = Vec::new();
    for request in requests {
        match request["method"].as_str() {
            Some("client/registerCapability") => {
                for registration in request["params"]["registrations"].as_array().unwrap() {
                    registrations.push((
                        registration["id"].as_str().unwrap().to_string(),
                        registered_watchers(&[json!({
                            "method": "client/registerCapability",
                            "params": { "registrations": [registration] }
                        })]),
                    ));
                }
            }
            Some("client/unregisterCapability") => {
                for gone in request["params"]["unregisterations"].as_array().unwrap() {
                    registrations.retain(|(id, _)| id != gone["id"].as_str().unwrap());
                }
            }
            _ => {}
        }
    }
    registrations.into_iter().flat_map(|(_, w)| w).collect()
}

/// Every server request since the client started, across calls.
fn all_server_requests(lsp: &mut Lsp, so_far: &mut Vec<Value>) -> Vec<Value> {
    let fresh = server_requests(lsp);
    so_far.extend(fresh.clone());
    fresh
}

/// A workspace pull's reports, by file URI.
fn workspace_pull_items(lsp: &mut Lsp) -> Vec<(String, Vec<String>)> {
    let report = lsp.request("workspace/diagnostic", json!({ "previousResultIds": [] }));
    report["result"]["items"]
        .as_array()
        .unwrap_or_else(|| panic!("{report}"))
        .iter()
        .map(|item| {
            (
                item["uri"].as_str().unwrap().to_string(),
                codes_of(item["items"].as_array().unwrap_or(&Vec::new())),
            )
        })
        .collect()
}

/// `visibility.toml` is the root's own configuration file, which the fixed
/// globs name: once the workspace has loaded (and with it the folders it
/// reads), writing it still declares the datasets the open queries are
/// checked against.
#[test]
fn visibility_toml_written_after_the_workspace_loaded_rechecks_an_open_query() {
    let scratch = workspace("visibility-loaded", true);
    let root = &scratch.0;
    let (mut lsp, _) = start(json!({
        "capabilities": watching_relative(),
        "rootUri": file_uri(root)
    }));
    // The workspace loads with the first pull.
    workspace_pull_codes(&mut lsp);
    let uri = file_uri(&root.join("hunt.kql"));
    open(&mut lsp, &uri, "kql", "NTAIpDetails | take 1");
    assert!(pulled(&mut lsp, &uri).is_empty());

    let config = root.join(".opentide/configurations");
    std::fs::create_dir_all(&config).unwrap();
    let visibility = config.join("visibility.toml");
    std::fs::write(
        &visibility,
        "[[logsources]]\nname = \"NTANetAnalytics\"\ndescription = \"x\"\nsystem = \"sentinel\"\n",
    )
    .unwrap();
    lsp.notify(
        "workspace/didChangeWatchedFiles",
        json!({ "changes": [{ "uri": file_uri(&visibility), "type": 1 }] }),
    );
    assert_eq!(
        pulled(&mut lsp, &uri),
        ["kql_table_not_declared"],
        "the file's event went to the configuration branch, not the datasets'"
    );
}

/// A root named through a symbolic link: the workspace names its folders
/// resolved, the editor by the link. The root's own folders are the fixed
/// globs', whatever the spelling, and the client is not asked for them twice.
#[cfg(unix)]
#[test]
fn a_root_named_through_a_symbolic_link_registers_no_folder_of_its_own() {
    let scratch = workspace("workspace-watch-link-real", true);
    let link = scratch.0.parent().unwrap().join(format!(
        "opentide-e2e-link-{}",
        scratch.0.file_name().unwrap().to_string_lossy()
    ));
    let _ = std::fs::remove_file(&link);
    std::os::unix::fs::symlink(&scratch.0, &link).unwrap();
    let (mut lsp, _) = start(json!({
        "capabilities": watching_relative(),
        "rootUri": file_uri(&link)
    }));
    server_requests(&mut lsp);
    workspace_pull_codes(&mut lsp);
    let after_load = server_requests(&mut lsp);
    let extra = own_watchers(&after_load, &link);
    let _ = std::fs::remove_file(&link);
    assert!(
        extra.is_empty(),
        "folders of the root's own were registered: {extra:?}"
    );
}

/// A configuration that does not resolve (it is being mended) does not take
/// the watch on the layered folder away, and one that is broken from the start
/// is watched too: the file that mends it is what is waited for.
#[test]
fn the_layered_configuration_stays_watched_while_it_does_not_resolve() {
    let scratch = workspace("workspace-watch-broken", false);
    let root = scratch.0.join("child");
    std::fs::create_dir_all(root.join("objects/rules")).unwrap();
    std::fs::write(root.join("objects/rules/rule-1.0.yaml"), fixture(RULE)).unwrap();
    let parent = scratch.0.join(".opentide/configurations");
    std::fs::create_dir_all(&parent).unwrap();
    let layered = (file_uri(&parent), "**/*.toml".to_string());
    let deployment = parent.join("deployment.toml");
    // Broken from the start.
    std::fs::write(&deployment, "[[statuses\n").unwrap();
    let (mut lsp, _) =
        start(json!({ "capabilities": watching_relative(), "rootUri": file_uri(&root) }));
    let mut sent = Vec::new();
    all_server_requests(&mut lsp, &mut sent);
    workspace_pull_codes(&mut lsp);
    all_server_requests(&mut lsp, &mut sent);
    assert!(
        watchers_in_force(&sent).contains(&layered),
        "the broken layer is not watched: {:?}",
        watchers_in_force(&sent)
    );

    // Mended, then broken again once the workspace has loaded.
    std::fs::write(&deployment, DESIGN_ONLY).unwrap();
    lsp.notify(
        "workspace/didChangeWatchedFiles",
        json!({ "changes": [{ "uri": file_uri(&deployment), "type": 1 }] }),
    );
    let unknown = "config_enum_unknown".to_string();
    assert!(workspace_pull_codes(&mut lsp).contains(&unknown));
    all_server_requests(&mut lsp, &mut sent);
    std::fs::write(&deployment, "[[statuses\n").unwrap();
    lsp.notify(
        "workspace/didChangeWatchedFiles",
        json!({ "changes": [{ "uri": file_uri(&deployment), "type": 2 }] }),
    );
    workspace_pull_codes(&mut lsp);
    all_server_requests(&mut lsp, &mut sent);
    assert!(
        watchers_in_force(&sent).contains(&layered),
        "the layer was let go of when it broke: {:?}",
        watchers_in_force(&sent)
    );
    // And what mends it is followed.
    std::fs::write(&deployment, DESIGN_ONLY).unwrap();
    lsp.notify(
        "workspace/didChangeWatchedFiles",
        json!({ "changes": [{ "uri": file_uri(&deployment), "type": 2 }] }),
    );
    assert!(workspace_pull_codes(&mut lsp).contains(&unknown));
}

/// A status the rule's block has, so the layer resolves and the rule has no
/// `config_enum_unknown`; [`DESIGN_ONLY`] without it is the layer that has.
const DESIGN_AND_STAGING: &str = "[[statuses]]\nname = \"DESIGN\"\ndescription = \"d\"\nstrategy = \"INERT\"\n\n[[statuses]]\nname = \"STAGING\"\ndescription = \"s\"\nstrategy = \"INERT\"\n";

/// Two workspace folders, each with a configuration layered in from its
/// parent, both resolving: a change to the second's makes its rule's findings
/// change, and only that (the first's layer is not the file that changed).
/// A path under neither root used to be handed to the first.
#[test]
fn a_parents_configuration_change_goes_to_the_root_it_is_layered_into() {
    let scratch = workspace("workspace-watch-two-parents", false);
    let rule = fixture(RULE);
    let child = |name: &str| {
        let root = scratch.0.join(name).join("child");
        std::fs::create_dir_all(root.join("objects/rules")).unwrap();
        std::fs::write(root.join("objects/rules/rule-1.0.yaml"), &rule).unwrap();
        let layer = root.parent().unwrap().join(".opentide/configurations");
        std::fs::create_dir_all(&layer).unwrap();
        std::fs::write(layer.join("deployment.toml"), DESIGN_AND_STAGING).unwrap();
        root
    };
    let (first, second) = (child("one"), child("two"));
    let folder =
        |root: &std::path::Path, name: &str| json!({ "uri": file_uri(root), "name": name });
    let (mut lsp, _) = start(json!({
        "capabilities": watching_relative(),
        "workspaceFolders": [folder(&first, "one"), folder(&second, "two")]
    }));
    let unknown = "config_enum_unknown".to_string();
    let by_root = |items: &[(String, Vec<String>)], root: &std::path::Path| {
        let rule = file_uri(&root.join("objects/rules/rule-1.0.yaml"));
        items
            .iter()
            .find(|(uri, _)| *uri == rule)
            .map(|(_, codes)| codes.clone())
            .unwrap_or_else(|| panic!("no report for {rule}: {items:?}"))
    };
    let items = workspace_pull_items(&mut lsp);
    assert!(!by_root(&items, &first).contains(&unknown), "{items:?}");
    assert!(!by_root(&items, &second).contains(&unknown), "{items:?}");

    let deployment = second
        .parent()
        .unwrap()
        .join(".opentide/configurations/deployment.toml");
    std::fs::write(&deployment, DESIGN_ONLY).unwrap();
    lsp.notify(
        "workspace/didChangeWatchedFiles",
        json!({ "changes": [{ "uri": file_uri(&deployment), "type": 2 }] }),
    );
    let items = workspace_pull_items(&mut lsp);
    assert!(by_root(&items, &second).contains(&unknown), "{items:?}");
    assert!(
        !by_root(&items, &first).contains(&unknown),
        "the first root's findings changed with the second's parent: {items:?}"
    );
}

/// The workspace's folders `/w` and `/w/child`: the child's parent is `/w`,
/// whose configuration folder is also `/w`'s own. A change there is the outer
/// root's configuration as much as the child's layer: both are told, and the
/// client is not asked to watch the folder twice.
#[test]
fn a_nested_root_does_not_take_the_outer_roots_configuration_event() {
    let scratch = workspace("workspace-watch-nested", false);
    let outer = &scratch.0;
    let inner = outer.join("child");
    std::fs::create_dir_all(inner.join("objects/rules")).unwrap();
    std::fs::write(inner.join("objects/rules/rule-1.0.yaml"), fixture(RULE)).unwrap();
    let layer = outer.join(".opentide/configurations");
    std::fs::create_dir_all(&layer).unwrap();
    std::fs::write(layer.join("deployment.toml"), DESIGN_AND_STAGING).unwrap();
    let folder =
        |root: &std::path::Path, name: &str| json!({ "uri": file_uri(root), "name": name });
    let (mut lsp, _) = start(json!({
        "capabilities": watching_relative(),
        "workspaceFolders": [folder(outer, "outer"), folder(&inner, "inner")]
    }));
    let mut sent = Vec::new();
    all_server_requests(&mut lsp, &mut sent);
    let unknown = "config_enum_unknown".to_string();
    let codes_of_rule = |items: &[(String, Vec<String>)], root: &std::path::Path| {
        let rule = file_uri(&root.join("objects/rules/rule-1.0.yaml"));
        items
            .iter()
            .find(|(uri, _)| *uri == rule)
            .map(|(_, codes)| codes.clone())
            .unwrap_or_else(|| panic!("no report for {rule}: {items:?}"))
    };
    let items = workspace_pull_items(&mut lsp);
    assert!(
        !codes_of_rule(&items, outer).contains(&unknown),
        "{items:?}"
    );
    assert!(
        !codes_of_rule(&items, &inner).contains(&unknown),
        "{items:?}"
    );
    all_server_requests(&mut lsp, &mut sent);
    let twice = watchers_in_force(&sent)
        .into_iter()
        .filter(|(base, _)| *base == file_uri(&layer))
        .count();
    assert_eq!(twice, 0, "the outer root's own folder was registered again");

    let deployment = layer.join("deployment.toml");
    std::fs::write(&deployment, DESIGN_ONLY).unwrap();
    lsp.notify(
        "workspace/didChangeWatchedFiles",
        json!({ "changes": [{ "uri": file_uri(&deployment), "type": 2 }] }),
    );
    let items = workspace_pull_items(&mut lsp);
    assert!(
        codes_of_rule(&items, outer).contains(&unknown),
        "the outer root was not told of its own configuration: {items:?}"
    );
    assert!(
        codes_of_rule(&items, &inner).contains(&unknown),
        "{items:?}"
    );
}

/// What each root's workspace has loaded so far, by root, as `(file reads,
/// parses, configuration resolutions)`.
fn loads_by_root(lsp: &mut Lsp) -> Vec<(u64, u64, u64)> {
    lsp.request("opentide/__stats", Value::Null)["result"]["roots"]
        .as_array()
        .unwrap()
        .iter()
        .map(|root| {
            (
                root["fileReads"].as_u64().unwrap(),
                root["parses"].as_u64().unwrap(),
                root["configResolutions"].as_u64().unwrap(),
            )
        })
        .collect()
}

/// A change to one root's layered configuration costs the others nothing:
/// the other folder's workspace is not opened again (which re-reads every
/// object) for a path that is not under it.
#[test]
fn a_layered_configuration_change_does_not_reload_the_other_roots() {
    let scratch = workspace("workspace-watch-reload", false);
    let rule = fixture(RULE);
    let child = |name: &str| {
        let root = scratch.0.join(name).join("child");
        std::fs::create_dir_all(root.join("objects/rules")).unwrap();
        std::fs::write(root.join("objects/rules/rule-1.0.yaml"), &rule).unwrap();
        let layer = root.parent().unwrap().join(".opentide/configurations");
        std::fs::create_dir_all(&layer).unwrap();
        std::fs::write(layer.join("deployment.toml"), DESIGN_AND_STAGING).unwrap();
        root
    };
    let (first, second) = (child("one"), child("two"));
    let folder =
        |root: &std::path::Path, name: &str| json!({ "uri": file_uri(root), "name": name });
    let (mut lsp, _) = start(json!({
        "capabilities": watching_relative(),
        "workspaceFolders": [folder(&first, "one"), folder(&second, "two")]
    }));
    workspace_pull_items(&mut lsp);
    let before = loads_by_root(&mut lsp);
    assert_eq!(before.len(), 2);

    let deployment = second
        .parent()
        .unwrap()
        .join(".opentide/configurations/deployment.toml");
    std::fs::write(&deployment, DESIGN_ONLY).unwrap();
    lsp.notify(
        "workspace/didChangeWatchedFiles",
        json!({ "changes": [{ "uri": file_uri(&deployment), "type": 2 }] }),
    );
    let items = workspace_pull_items(&mut lsp);
    assert!(
        items
            .iter()
            .any(|(_, codes)| codes.contains(&"config_enum_unknown".to_string())),
        "the change was not followed: {items:?}"
    );
    let after = loads_by_root(&mut lsp);
    assert_eq!(
        after[0], before[0],
        "the first root's workspace was loaded again for the second's configuration"
    );
    assert!(
        after[1].2 > before[1].2,
        "the second root's configuration was not resolved again: {before:?} {after:?}"
    );
}

/// `visibility.toml` of the outer one of two nested roots is also read by the
/// inner one, which layers the outer's configuration folder in: its
/// configuration is resolved again.
#[test]
fn a_nested_roots_layered_visibility_toml_is_followed() {
    let scratch = workspace("workspace-watch-nested-visibility", false);
    let outer = &scratch.0;
    let inner = outer.join("child");
    std::fs::create_dir_all(inner.join("objects/rules")).unwrap();
    std::fs::write(inner.join("objects/rules/rule-1.0.yaml"), fixture(RULE)).unwrap();
    let layer = outer.join(".opentide/configurations");
    std::fs::create_dir_all(&layer).unwrap();
    let folder =
        |root: &std::path::Path, name: &str| json!({ "uri": file_uri(root), "name": name });
    let (mut lsp, _) = start(json!({
        "capabilities": watching_relative(),
        "workspaceFolders": [folder(outer, "outer"), folder(&inner, "inner")]
    }));
    workspace_pull_items(&mut lsp);
    let before = loads_by_root(&mut lsp);

    let visibility = layer.join("visibility.toml");
    std::fs::write(
        &visibility,
        "[[logsources]]\nname = \"NTANetAnalytics\"\ndescription = \"x\"\nsystem = \"sentinel\"\n",
    )
    .unwrap();
    lsp.notify(
        "workspace/didChangeWatchedFiles",
        json!({ "changes": [{ "uri": file_uri(&visibility), "type": 1 }] }),
    );
    workspace_pull_items(&mut lsp);
    let after = loads_by_root(&mut lsp);
    assert!(
        after[1].2 > before[1].2,
        "the inner root's configuration was not resolved again: {before:?} {after:?}"
    );
}

/// A root named through a symbolic link to a folder whose parent differs from
/// the link's: the configuration the workspace layers in is the resolved
/// root's parent's, and that is the folder watched and followed.
#[cfg(unix)]
#[test]
fn the_layered_folder_is_the_resolved_roots_parents() {
    let scratch = workspace("workspace-watch-link-parent", false);
    let real = scratch.0.join("real").join("child");
    std::fs::create_dir_all(real.join("objects/rules")).unwrap();
    std::fs::write(real.join("objects/rules/rule-1.0.yaml"), fixture(RULE)).unwrap();
    let layer = scratch.0.join("real/.opentide/configurations");
    std::fs::create_dir_all(&layer).unwrap();
    std::fs::write(layer.join("deployment.toml"), DESIGN_AND_STAGING).unwrap();
    let elsewhere = scratch.0.join("elsewhere");
    std::fs::create_dir_all(&elsewhere).unwrap();
    let link = elsewhere.join("child");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let (mut lsp, _) =
        start(json!({ "capabilities": watching_relative(), "rootUri": file_uri(&link) }));
    let mut sent = Vec::new();
    all_server_requests(&mut lsp, &mut sent);
    let unknown = "config_enum_unknown".to_string();
    assert!(!workspace_pull_codes(&mut lsp).contains(&unknown));
    all_server_requests(&mut lsp, &mut sent);
    let watchers = watchers_in_force(&sent);
    // The workspace names the folder resolved (macOS's `/var` is `/private/var`).
    let spelled = |folder: &std::path::Path| {
        [
            file_uri(folder),
            file_uri(
                &folder
                    .canonicalize()
                    .unwrap_or_else(|_| folder.to_path_buf()),
            ),
        ]
    };
    assert!(
        spelled(&layer)
            .iter()
            .any(|base| watchers.contains(&(base.clone(), "**/*.toml".to_string()))),
        "the resolved parent's configuration is not watched: {watchers:?}"
    );
    assert!(
        !watchers
            .iter()
            .any(|(base, _)| *base == file_uri(&elsewhere.join(".opentide/configurations"))),
        "the link's parent was watched: {watchers:?}"
    );

    let deployment = layer.join("deployment.toml");
    std::fs::write(&deployment, DESIGN_ONLY).unwrap();
    lsp.notify(
        "workspace/didChangeWatchedFiles",
        json!({ "changes": [{ "uri": file_uri(&deployment), "type": 2 }] }),
    );
    assert!(
        workspace_pull_codes(&mut lsp).contains(&unknown),
        "the layered configuration was not followed"
    );
}

/// A brace cannot be escaped in a glob, so a folder with one is watched by
/// the folder above it; when that is above the workspace (here, a brace in
/// the name of the root's parent) the folder is not watched, never the
/// filesystem's root or a drive, and the log says so.
#[test]
fn a_brace_above_the_workspace_is_never_watched_by_a_folder_above_it() {
    let scratch = workspace("workspace-watch-brace-above", false);
    let root = scratch.0.join("{team}").join("child");
    std::fs::create_dir_all(root.join("objects/rules")).unwrap();
    std::fs::write(root.join("objects/rules/rule-1.0.yaml"), fixture(RULE)).unwrap();
    let layer = root.parent().unwrap().join(".opentide/configurations");
    std::fs::create_dir_all(&layer).unwrap();
    std::fs::write(layer.join("deployment.toml"), DESIGN_ONLY).unwrap();
    // A client that watches by path glob, without relative patterns.
    let (mut lsp, _) = start(json!({ "capabilities": {
        "textDocument": { "diagnostic": { "dynamicRegistration": false } },
        "workspace": { "diagnostics": { "refreshSupport": true }, "didChangeWatchedFiles": { "dynamicRegistration": true } }
    }, "rootUri": file_uri(&root) }));
    let mut seen = server_messages(&mut lsp);
    workspace_pull_codes(&mut lsp);
    seen.extend(server_messages(&mut lsp));
    let requests: Vec<Value> = seen
        .iter()
        .filter(|m| m.get("id").is_some() && m.get("method").is_some())
        .cloned()
        .collect();
    let above = scratch.0.display().to_string().replace('\\', "/");
    for (_, glob) in registered_watchers(&requests) {
        assert!(
            glob.starts_with("**") || glob.starts_with(&format!("{above}/{{team}}")),
            "a glob above the workspace was registered: {glob}"
        );
    }
    let warned = seen.iter().any(|m| {
        m["method"] == "window/logMessage"
            && m["params"]["type"] == 2
            && m["params"]["message"]
                .as_str()
                .is_some_and(|text| text.contains("brace"))
    });
    assert!(warned, "no warning was logged: {seen:?}");
}

/// A parent's `visibility.toml` is a layered configuration file, not the
/// root's own datasets: its event makes the workspace's findings be made
/// again, even while the root's own `visibility.toml` is open (an open buffer
/// is what the datasets' branch leaves alone).
#[test]
fn a_parents_visibility_toml_is_a_layered_configuration_file() {
    let scratch = workspace("workspace-watch-parent-visibility", true);
    let root = scratch.0.join("child");
    std::fs::create_dir_all(root.join("objects/rules")).unwrap();
    std::fs::write(root.join("objects/rules/rule-1.0.yaml"), fixture(RULE)).unwrap();
    let layer = scratch.0.join(".opentide/configurations");
    std::fs::create_dir_all(&layer).unwrap();
    let own = root.join(".opentide/configurations/visibility.toml");
    std::fs::create_dir_all(own.parent().unwrap()).unwrap();
    let (mut lsp, _) =
        start(json!({ "capabilities": watching_relative(), "rootUri": file_uri(&root) }));
    open(&mut lsp, &file_uri(&own), "toml", "");
    let hits = |lsp: &mut Lsp| {
        lsp.request("opentide/__stats", Value::Null)["result"]["workspaceReportHits"]
            .as_u64()
            .unwrap()
    };
    workspace_pull_codes(&mut lsp);
    workspace_pull_codes(&mut lsp);
    let before = hits(&mut lsp);
    assert_eq!(before, 1);

    let visibility = layer.join("visibility.toml");
    std::fs::write(
        &visibility,
        "[[logsources]]\nname = \"NTANetAnalytics\"\ndescription = \"x\"\nsystem = \"sentinel\"\n",
    )
    .unwrap();
    lsp.notify(
        "workspace/didChangeWatchedFiles",
        json!({ "changes": [{ "uri": file_uri(&visibility), "type": 1 }] }),
    );
    workspace_pull_codes(&mut lsp);
    assert_eq!(
        hits(&mut lsp),
        before,
        "the pull after a layered visibility.toml came from the old report"
    );
}

/// Nothing is asked of the client before it has said `initialized`: what the
/// workspace reads is registered by the first batch after it, not by one that
/// came before.
#[test]
fn no_watcher_is_registered_before_the_client_is_initialized() {
    let scratch = workspace("workspace-watch-initialized", false);
    let moved = move_objectives(&scratch.0, "objectives-moved");
    std::fs::create_dir_all(&moved).unwrap();
    std::fs::write(moved.join("objective-1.0.yaml"), fixture(OBJECTIVE)).unwrap();
    let mut lsp = Lsp::spawn();
    let init = lsp.request(
        "initialize",
        json!({ "capabilities": watching_relative(), "rootUri": file_uri(&scratch.0) }),
    );
    assert!(init["result"]["capabilities"].is_object(), "{init}");
    // A batch before `initialized`: the workspace loads and the folders are known.
    workspace_pull_codes(&mut lsp);
    let mut early = server_messages(&mut lsp);
    early.extend(server_messages(&mut lsp));
    assert!(
        !early
            .iter()
            .any(|m| m["method"] == "client/registerCapability"),
        "a watcher was registered before `initialized`: {early:?}"
    );

    lsp.notify("initialized", json!({}));
    let mut late = server_messages(&mut lsp);
    workspace_pull_codes(&mut lsp);
    late.extend(server_messages(&mut lsp));
    let requests: Vec<Value> = late
        .iter()
        .filter(|m| m.get("id").is_some() && m.get("method").is_some())
        .cloned()
        .collect();
    let watchers = registered_watchers(&requests);
    assert!(
        watchers.iter().any(|(base, _)| *base == file_uri(&moved)),
        "the moved folder was not registered after `initialized`: {watchers:?}"
    );
}

/// A folder named with what a glob reads is watched by its own name; one with
/// a brace, which a glob cannot escape, by the folder above it.
#[test]
fn a_folder_with_a_glob_character_in_its_name_is_watched_by_its_name() {
    let scratch = workspace("workspace-watch-glob-chars", false);
    let moved = move_objectives(&scratch.0, "objectives [prod]");
    std::fs::create_dir_all(&moved).unwrap();
    let (mut lsp, _) = start(json!({ "capabilities": {
        "textDocument": { "diagnostic": { "dynamicRegistration": false } },
        "workspace": { "diagnostics": { "refreshSupport": true }, "didChangeWatchedFiles": { "dynamicRegistration": true } }
    }, "rootUri": file_uri(&scratch.0) }));
    server_requests(&mut lsp);
    workspace_pull_codes(&mut lsp);
    let watchers = own_watchers(&server_requests(&mut lsp), &scratch.0);
    let root = scratch.0.display().to_string().replace('\\', "/");
    assert_eq!(
        watchers,
        vec![(String::new(), format!("{root}/objectives [[]prod]/**"))]
    );

    move_objectives(&scratch.0, "{team}");
    lsp.notify(
        "workspace/didChangeWatchedFiles",
        json!({ "changes": [{
            "uri": file_uri(&scratch.0.join(".opentide/configurations/paths.toml")),
            "type": 2
        }] }),
    );
    workspace_pull_codes(&mut lsp);
    let watchers = own_watchers(&server_requests(&mut lsp), &scratch.0);
    assert_eq!(watchers, vec![(String::new(), format!("{root}/**"))]);
}

/// A branch switch deletes `.opentide/states/` whole, which a client reports
/// as one event for the folder: the findings are made again, and the folders
/// are watched for it.
#[test]
fn deleting_the_states_folder_makes_the_next_pull_be_made_again() {
    let scratch = workspace("workspace-watch-states-folder", true);
    let root = &scratch.0;
    let (mut lsp, _) =
        start(json!({ "capabilities": watching_relative(), "rootUri": file_uri(root) }));
    let fixed = registered_watchers(&server_requests(&mut lsp));
    for glob in ["**/.opentide/states", "**/.opentide/states/deployment"] {
        assert!(
            fixed.iter().any(|(_, g)| g == glob),
            "{glob} not watched: {fixed:?}"
        );
    }
    let objective = file_uri(&root.join("objects/objectives/objective-1.0.yaml"));
    open(&mut lsp, &objective, "opentide-yaml", &fixture(OBJECTIVE));
    let hits = |lsp: &mut Lsp| {
        lsp.request("opentide/__stats", Value::Null)["result"]["workspaceReportHits"]
            .as_u64()
            .unwrap()
    };
    let shards = root.join(".opentide/states/deployment");
    std::fs::create_dir_all(&shards).unwrap();
    std::fs::write(
        shards.join("00000000-0000-4000-8003-000000000001.json"),
        "{}",
    )
    .unwrap();
    workspace_pull_codes(&mut lsp);
    workspace_pull_codes(&mut lsp);
    let before = hits(&mut lsp);
    assert_eq!(before, 1);

    std::fs::remove_dir_all(root.join(".opentide/states")).unwrap();
    lsp.notify(
        "workspace/didChangeWatchedFiles",
        json!({ "changes": [{ "uri": file_uri(&root.join(".opentide/states")), "type": 3 }] }),
    );
    workspace_pull_codes(&mut lsp);
    assert_eq!(
        hits(&mut lsp),
        before,
        "the pull after the folder was deleted came from the old report"
    );
}

/// What nothing reports (no watcher) is never served from what was kept:
/// every pull is made again, as before.
#[test]
fn a_client_that_does_not_watch_files_is_never_served_a_kept_report() {
    let scratch = workspace("workspace-pull-no-cache", true);
    let (mut lsp, _) =
        start(json!({ "capabilities": workspace_pulling(), "rootUri": file_uri(&scratch.0) }));
    let objective = file_uri(&scratch.0.join("objects/objectives/objective-1.0.yaml"));
    open(&mut lsp, &objective, "opentide-yaml", &fixture(OBJECTIVE));
    for _ in 0..3 {
        workspace_pull_codes(&mut lsp);
    }
    let stats = lsp.request("opentide/__stats", Value::Null);
    assert_eq!(stats["result"]["workspaceReportHits"], 0, "{stats}");
    assert_eq!(stats["result"]["closedAnalyses"], 3, "{stats}");
}

/// A diagnostics request sent in the batch before `shutdown` is answered
/// as it was before diagnostics were answered last: not refused for the
/// server being shut down by then.
#[test]
fn a_diagnostics_request_before_shutdown_in_one_batch_is_answered() {
    let scratch = workspace("diagnostics-then-shutdown", true);
    let (mut lsp, _) = start(json!({
        "capabilities": workspace_pulling(),
        "rootUri": file_uri(&scratch.0)
    }));
    let uri = file_uri(&scratch.0.join("objects/rules/rule-1.0.yaml"));
    open(&mut lsp, &uri, "opentide-yaml", &fixture(RULE));
    hold(&mut lsp, 900);
    send(
        &mut lsp,
        901,
        "textDocument/diagnostic",
        json!({ "textDocument": { "uri": uri } }),
    );
    send(
        &mut lsp,
        902,
        "workspace/diagnostic",
        json!({ "previousResultIds": [] }),
    );
    send(&mut lsp, 903, "shutdown", Value::Null);
    let seen = until_response(&mut lsp, 903);
    let reply = |id: i64| {
        seen.iter()
            .find(|m| m["id"] == id && m.get("method").is_none())
    };
    for id in [901, 902] {
        let answer = reply(id).unwrap_or_else(|| panic!("no answer to {id}: {seen:#?}"));
        assert!(answer.get("error").is_none(), "{id} was refused: {answer}");
        assert!(answer["result"].is_object(), "{answer}");
    }
}

/// A diagnostics request answered last is about a document that the batch
/// closes after it: it is `ContentModified`, not a report for a document
/// that is gone.
#[test]
fn a_deferred_diagnostics_request_for_a_document_closed_later_in_the_batch_is_outdated() {
    let scratch = workspace("diagnostics-then-close", true);
    let (mut lsp, _) = start(json!({
        "capabilities": workspace_pulling(),
        "rootUri": file_uri(&scratch.0)
    }));
    let uri = file_uri(&scratch.0.join("objects/rules/rule-1.0.yaml"));
    open(&mut lsp, &uri, "opentide-yaml", &fixture(RULE));
    hold(&mut lsp, 900);
    send(
        &mut lsp,
        901,
        "textDocument/diagnostic",
        json!({ "textDocument": { "uri": uri } }),
    );
    lsp.notify(
        "textDocument/didClose",
        json!({ "textDocument": { "uri": uri } }),
    );
    send(
        &mut lsp,
        902,
        "textDocument/hover",
        json!({
            "textDocument": { "uri": uri },
            "position": { "line": 0, "character": 0 }
        }),
    );
    let seen = until_response(&mut lsp, 901);
    let answer = seen.iter().find(|m| m["id"] == 901).unwrap();
    assert_eq!(answer["error"]["code"], -32801, "{seen:#?}");
}

/// The diagnostics requests are the slow ones on a large workspace: what the
/// editor asks in the same batch (a hover, a completion) is answered first,
/// whatever the order they arrived in.
#[test]
fn a_batch_answers_diagnostics_after_hovers_and_completions() {
    let scratch = workspace("batch-order", true);
    let capabilities = json!({
        "textDocument": { "diagnostic": { "dynamicRegistration": false } },
        "workspace": { "diagnostics": { "refreshSupport": true } }
    });
    let (mut lsp, _) =
        start(json!({ "capabilities": capabilities, "rootUri": file_uri(&scratch.0) }));
    let uri = file_uri(&scratch.0.join("objects/rules/rule-1.0.yaml"));
    let text = fixture(RULE);
    open(&mut lsp, &uri, "opentide-yaml", &text);
    hold(&mut lsp, 900);
    let at = json!({ "textDocument": { "uri": uri }, "position": { "line": 0, "character": 2 } });
    send(
        &mut lsp,
        901,
        "workspace/diagnostic",
        json!({ "previousResultIds": [] }),
    );
    send(
        &mut lsp,
        902,
        "textDocument/diagnostic",
        json!({ "textDocument": { "uri": uri } }),
    );
    send(&mut lsp, 903, "textDocument/hover", at.clone());
    send(&mut lsp, 904, "textDocument/completion", at);
    // The two diagnostics requests are deferred in the order they arrived.
    let seen: Vec<Value> = until_response(&mut lsp, 902);
    let position = |id: i64| {
        seen.iter()
            .position(|m| m["id"] == id && m.get("method").is_none())
    };
    let (hover, completion) = (position(903), position(904));
    let (workspace_pull, document_pull) = (position(901), position(902));
    assert!(hover.is_some() && completion.is_some(), "{seen:#?}");
    assert!(
        workspace_pull.is_some() && document_pull.is_some(),
        "{seen:#?}"
    );
    assert!(
        hover < workspace_pull && completion < workspace_pull,
        "{seen:#?}"
    );
    assert!(workspace_pull < document_pull, "{seen:#?}");
    assert!(
        seen[workspace_pull.unwrap()]["result"]["items"].is_array(),
        "{seen:#?}"
    );
}

/// #215: a file-name finding's suggestion is a file name. A client that applies
/// `RenameFile` gets an action that renames the file; no client gets an edit
/// of the text, which is the object's name, and fixAll leaves it out.
#[test]
#[expect(
    clippy::cast_possible_truncation,
    reason = "a range in a test document of a few lines"
)]
fn a_file_name_finding_is_a_rename_never_a_text_edit() {
    let scratch = Scratch::new("filename-slug-rename");
    let path = scratch.0.join("objects/rules/not-the-slug.yaml");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let text = fixture(RULE);
    std::fs::write(&path, &text).unwrap();
    let uri = file_uri(&path);
    let whole =
        json!({ "start": { "line": 0, "character": 0 }, "end": { "line": 200, "character": 0 } });
    let renaming = json!({ "workspace": { "workspaceEdit": {
        "documentChanges": true, "resourceOperations": ["create", "rename"]
    } } });
    for (capabilities, renames) in [(json!({}), false), (renaming, true)] {
        let (mut lsp, _) =
            start(json!({ "capabilities": capabilities, "rootUri": file_uri(&scratch.0) }));
        open(&mut lsp, &uri, "opentide-yaml", &text);
        published_for(&mut lsp, &uri);
        let slug = &file_name_finding(&text, "process-creation.yaml");
        // The range is the name the file should be named after.
        let line = text
            .lines()
            .nth(slug["range"]["start"]["line"].as_u64().unwrap() as usize)
            .unwrap();
        let (start, end) = (
            slug["range"]["start"]["character"].as_u64().unwrap() as usize,
            slug["range"]["end"]["character"].as_u64().unwrap() as usize,
        );
        assert!(line.starts_with("name:"), "{line}");
        assert_eq!(&line[start..end], line["name: ".len()..].trim(), "{line}");

        let found = lsp.request(
            "textDocument/codeAction",
            json!({ "textDocument": { "uri": uri }, "range": whole, "context": { "diagnostics": [slug] } }),
        )["result"]
            .as_array()
            .unwrap()
            .clone();
        if renames {
            let [action] = found.as_slice() else {
                panic!("{found:#?}")
            };
            let operation = &action["edit"]["documentChanges"][0];
            assert_eq!(operation["kind"], "rename", "{action:#}");
            assert_eq!(operation["oldUri"], uri.as_str());
            let suggestion = slug["data"]["suggestion"].as_str().unwrap();
            assert!(
                operation["newUri"]
                    .as_str()
                    .unwrap()
                    .ends_with(&format!("/{suggestion}")),
                "{action:#}"
            );
            assert!(action["edit"]["changes"].is_null(), "{action:#}");
        } else {
            assert!(found.is_empty(), "{found:#?}");
        }
        let fix_all = lsp.request(
            "textDocument/codeAction",
            json!({ "textDocument": { "uri": uri }, "range": whole, "context": { "diagnostics": [], "only": ["source.fixAll"] } }),
        )["result"]
            .clone();
        let edits = fix_all.to_string();
        assert!(!edits.contains(".yaml\""), "{fix_all:#}");
    }
}

/// A client that pulls diagnostics, with `extra` capabilities.
fn pulling(extra: Value) -> Value {
    let mut caps = json!({ "textDocument": { "diagnostic": { "dynamicRegistration": false } } });
    if let (Some(caps), Some(extra)) = (caps.as_object_mut(), extra.as_object()) {
        for (key, value) in extra {
            caps.insert(key.clone(), value.clone());
        }
    }
    caps
}

/// The codes of the document's diagnostics, pulled now.
fn pulled(lsp: &mut Lsp, uri: &str) -> Vec<String> {
    let reply = lsp.request(
        "textDocument/diagnostic",
        json!({ "textDocument": { "uri": uri } }),
    );
    let items = reply["result"]["items"]
        .as_array()
        .unwrap_or_else(|| panic!("{reply}"));
    codes_of(items)
}

/// `[[statuses]]` without `STAGING`, the status the rule's block has: what
/// `validate` reports as `config_enum_unknown` on it.
const DESIGN_ONLY: &str =
    "[[statuses]]\nname = \"DESIGN\"\ndescription = \"d\"\nstrategy = \"INERT\"\n";

/// UC-2.6: an open configuration buffer is the configuration `validate`
/// resolves for the objects, saved or not; closed, the disk is again.
#[test]
fn an_unsaved_configuration_buffer_changes_the_objects_findings() {
    let scratch = workspace("config-buffer", true);
    let root = &scratch.0;
    let rule_uri = file_uri(&root.join("objects/rules/rule-1.0.yaml"));
    let deployment = root.join(".opentide/configurations/deployment.toml");
    let deployment_uri = file_uri(&deployment);
    let (mut lsp, _) =
        start(json!({ "capabilities": pulling(json!({})), "rootUri": file_uri(root) }));
    open(&mut lsp, &rule_uri, "opentide-yaml", &fixture(RULE));
    let unknown = "config_enum_unknown".to_string();
    assert!(!pulled(&mut lsp, &rule_uri).contains(&unknown));

    // Not on disk: the buffer alone declares the statuses.
    open(&mut lsp, &deployment_uri, "toml", DESIGN_ONLY);
    let codes = pulled(&mut lsp, &rule_uri);
    assert!(codes.contains(&unknown), "{codes:?}");
    assert!(!deployment.exists());

    // An unsaved edit that declares STAGING clears it.
    lsp.notify(
        "textDocument/didChange",
        json!({ "textDocument": { "uri": deployment_uri },
                "contentChanges": [{ "text": format!(
                    "{DESIGN_ONLY}\n[[statuses]]\nname = \"STAGING\"\ndescription = \"s\"\nstrategy = \"PREVIEW\"\n"
                ) }] }),
    );
    let codes = pulled(&mut lsp, &rule_uri);
    assert!(!codes.contains(&unknown), "{codes:?}");

    // Back to DESIGN alone, then closed: the bundled statuses again.
    lsp.notify(
        "textDocument/didChange",
        json!({ "textDocument": { "uri": deployment_uri },
                "contentChanges": [{ "text": DESIGN_ONLY }] }),
    );
    assert!(pulled(&mut lsp, &rule_uri).contains(&unknown));
    lsp.notify(
        "textDocument/didClose",
        json!({ "textDocument": { "uri": deployment_uri } }),
    );
    let codes = pulled(&mut lsp, &rule_uri);
    assert!(!codes.contains(&unknown), "{codes:?}");
}

/// #914: a folder the editor names by another spelling than the one the
/// workspace resolves it to (a symbolic link here; macOS's `/var` for
/// `/private/var`, Windows' `RUNNER~1` for the long name) still has its
/// unsaved buffers and its edits checked: the server names each file as
/// the workspace does.
#[cfg(unix)]
#[test]
fn a_folder_opened_through_a_link_has_its_buffers_checked() {
    let scratch = workspace("linked-root", true);
    let link = scratch.0.with_file_name(format!(
        "{}-link",
        scratch.0.file_name().unwrap().to_string_lossy()
    ));
    let _ = std::fs::remove_file(&link);
    std::os::unix::fs::symlink(&scratch.0, &link).unwrap();
    let rule_uri = file_uri(&link.join("objects/rules/rule-1.0.yaml"));
    let deployment_uri = file_uri(&link.join(".opentide/configurations/deployment.toml"));
    let (mut lsp, _) =
        start(json!({ "capabilities": pulling(json!({})), "rootUri": file_uri(&link) }));
    let rule = fixture(RULE);
    open(&mut lsp, &rule_uri, "opentide-yaml", &rule);
    let unknown = "config_enum_unknown".to_string();
    assert!(!pulled(&mut lsp, &rule_uri).contains(&unknown));

    // An unsaved configuration buffer is the configuration.
    open(&mut lsp, &deployment_uri, "toml", DESIGN_ONLY);
    let codes = pulled(&mut lsp, &rule_uri);
    assert!(codes.contains(&unknown), "{codes:?}");

    // An edit of the rule is what is checked.
    lsp.notify(
        "textDocument/didChange",
        json!({ "textDocument": { "uri": rule_uri, "version": 2 },
                "contentChanges": [{ "text": rule.replacen("tlp: clear", "tlp: clearr", 1) }] }),
    );
    let codes = pulled(&mut lsp, &rule_uri);
    assert!(codes.contains(&"vocab_unknown".to_string()), "{codes:?}");
    std::fs::remove_file(&link).unwrap();
}

/// UC-2.6: a client with no file watcher has the disk read again on each
/// request, and the configuration resolved again with it.
#[test]
fn without_a_watcher_a_configuration_changed_on_disk_is_read_again() {
    let scratch = workspace("config-poll", true);
    let root = &scratch.0;
    let rule_uri = file_uri(&root.join("objects/rules/rule-1.0.yaml"));
    let (mut lsp, _) =
        start(json!({ "capabilities": pulling(json!({})), "rootUri": file_uri(root) }));
    open(&mut lsp, &rule_uri, "opentide-yaml", &fixture(RULE));
    let unknown = "config_enum_unknown".to_string();
    assert!(!pulled(&mut lsp, &rule_uri).contains(&unknown));

    let configurations = root.join(".opentide/configurations");
    std::fs::create_dir_all(&configurations).unwrap();
    std::fs::write(configurations.join("deployment.toml"), DESIGN_ONLY).unwrap();
    let codes = pulled(&mut lsp, &rule_uri);
    assert!(codes.contains(&unknown), "{codes:?}");

    std::fs::remove_file(configurations.join("deployment.toml")).unwrap();
    let codes = pulled(&mut lsp, &rule_uri);
    assert!(!codes.contains(&unknown), "{codes:?}");
}

/// UC-2.6: a folder under `objects/` deleted or created, which a watcher
/// reports as one event, reaches `validate`: the rule's objective goes and
/// comes back with its folder.
#[test]
fn a_folder_event_under_objects_reaches_the_findings() {
    let scratch = workspace("folder-event", true);
    let root = &scratch.0;
    let rule_uri = file_uri(&root.join("objects/rules/rule-1.0.yaml"));
    let (mut lsp, _) =
        start(json!({ "capabilities": pulling(watch()), "rootUri": file_uri(root) }));
    let register = lsp.read();
    assert_eq!(
        register["method"], "client/registerCapability",
        "{register}"
    );
    lsp.write(&json!({ "jsonrpc": "2.0", "id": register["id"], "result": null }));
    open(&mut lsp, &rule_uri, "opentide-yaml", &fixture(RULE));
    let invalid = "invalid_ref".to_string();
    let codes = pulled(&mut lsp, &rule_uri);
    assert!(!codes.contains(&invalid), "{codes:?}");

    let objectives = root.join("objects/objectives");
    std::fs::remove_dir_all(&objectives).unwrap();
    lsp.notify(
        "workspace/didChangeWatchedFiles",
        json!({ "changes": [{ "uri": file_uri(&objectives), "type": 3 }] }),
    );
    let codes = pulled(&mut lsp, &rule_uri);
    assert!(codes.contains(&invalid), "{codes:?}");

    std::fs::create_dir_all(&objectives).unwrap();
    std::fs::write(objectives.join("objective-1.0.yaml"), fixture(OBJECTIVE)).unwrap();
    lsp.notify(
        "workspace/didChangeWatchedFiles",
        json!({ "changes": [{ "uri": file_uri(&objectives), "type": 1 }] }),
    );
    let codes = pulled(&mut lsp, &rule_uri);
    assert!(!codes.contains(&invalid), "{codes:?}");
}

/// What a pull answers for a document, as the client reads it: the report's
/// kind, its id and the codes of its items. A report `unchanged` has no items.
fn pulled_report(lsp: &mut Lsp, uri: &str) -> (String, Option<String>, Vec<String>) {
    let reply = lsp.request(
        "textDocument/diagnostic",
        json!({ "textDocument": { "uri": uri } }),
    );
    assert!(reply.get("error").is_none(), "{reply}");
    let result = &reply["result"];
    let kind = result["kind"].as_str().unwrap_or_default().to_string();
    let id = result["resultId"].as_str().map(str::to_string);
    let items = result["items"].as_array().cloned().unwrap_or_default();
    (kind, id, codes_of(&items))
}

/// The server's next request, and nothing else in front of it.
fn next_server_request(lsp: &mut Lsp) -> Value {
    let message = lsp.read();
    assert!(
        message.get("method").is_some() && message.get("id").is_some(),
        "expected a request from the server: {message}"
    );
    message
}

/// A pull that overtook its `didOpen` (a client that restarts replays its
/// open documents, and the pull is sent first) is for a file the server has
/// not seen opened: it is answered from the closed file, as the workspace pull
/// answers it, and not with an empty `full` report that the client keeps.
#[test]
fn a_pull_before_the_didopen_is_answered_from_the_file_on_disk() {
    let scratch = workspace("pull-before-open", false);
    let root = &scratch.0;
    let rule = file_uri(&root.join("objects/rules/rule-1.0.yaml"));
    let deployment = file_uri(&root.join(".opentide/configurations/deployment.toml"));
    let (mut lsp, _) =
        start(json!({ "capabilities": workspace_pulling(), "rootUri": file_uri(root) }));
    // The workspace pull's answer for the closed rule is what the document
    // pull must give: the finding is the missing objective.
    open(&mut lsp, &deployment, "toml", DESIGN_ONLY);
    let workspace_codes = workspace_pull_codes(&mut lsp);
    let invalid = "invalid_ref".to_string();
    assert!(workspace_codes.contains(&invalid), "{workspace_codes:?}");

    // initialize, initialized, didOpen(A), pull(B), didOpen(B): B is not open
    // when it is pulled.
    let (kind, id, codes) = pulled_report(&mut lsp, &rule);
    assert_eq!(kind, "full");
    assert!(id.is_some());
    assert_eq!(codes, workspace_codes, "a pull of a closed file is empty");

    // Its id is the workspace pull's for the file: a client that pulls again
    // with it is told `unchanged`.
    let again = lsp.request(
        "textDocument/diagnostic",
        json!({ "textDocument": { "uri": rule }, "previousResultId": id }),
    );
    assert_eq!(again["result"]["kind"], "unchanged", "{again}");
}

/// The bug as the extension's trace has it, from the first message: a pull
/// of a rule on disk before its `didOpen` shows the rule's finding, and the
/// `didOpen` that follows (the same text) leaves the client holding a report
/// that is right, and the server asking for a pull of what it answered
/// without the open text.
#[test]
fn the_extensions_pull_before_open_sequence_shows_the_finding() {
    let scratch = workspace("pull-before-open-sequence", false);
    let root = &scratch.0;
    let rule = file_uri(&root.join("objects/rules/rule-1.0.yaml"));
    let notes = file_uri(&root.join(".opentide/configurations/deployment.toml"));
    let (mut lsp, _) =
        start(json!({ "capabilities": workspace_pulling(), "rootUri": file_uri(root) }));
    open(&mut lsp, &notes, "toml", DESIGN_ONLY);
    let (_, _, codes) = pulled_report(&mut lsp, &rule);
    let invalid = "invalid_ref".to_string();
    assert!(
        codes.contains(&invalid),
        "the finding was not shown: {codes:?}"
    );

    open(&mut lsp, &rule, "opentide-yaml", &fixture(RULE));
    let refresh = next_server_request(&mut lsp);
    assert_eq!(
        refresh["method"], "workspace/diagnostic/refresh",
        "{refresh}"
    );
    let (_, _, opened) = pulled_report(&mut lsp, &rule);
    assert_eq!(opened, codes, "the open document's findings are the file's");
}

/// The text the editor opens is not the file's: the report the server gave
/// for the closed file is stale, the server asks for a pull, and the pull is
/// of the open text.
#[test]
fn a_didopen_with_other_text_than_the_pulled_file_is_followed_by_a_refresh() {
    let scratch = workspace("pull-before-open-other-text", true);
    let root = &scratch.0;
    let rule = file_uri(&root.join("objects/rules/rule-1.0.yaml"));
    let objective = file_uri(&root.join("objects/objectives/objective-1.0.yaml"));
    let (mut lsp, _) =
        start(json!({ "capabilities": workspace_pulling(), "rootUri": file_uri(root) }));
    open(&mut lsp, &objective, "opentide-yaml", &fixture(OBJECTIVE));
    let (_, _, closed) = pulled_report(&mut lsp, &rule);
    // The unsaved text is not the rule on disk: it is not an object at all.
    open(&mut lsp, &rule, "opentide-yaml", "not: a rule\n");
    let refresh = next_server_request(&mut lsp);
    assert_eq!(
        refresh["method"], "workspace/diagnostic/refresh",
        "{refresh}"
    );
    let (_, _, opened) = pulled_report(&mut lsp, &rule);
    assert_ne!(opened, closed, "the pull still answered the file on disk");
}

/// A document opened without having been pulled needs no refresh, and one
/// that was pulled is refreshed once: a second `didOpen` of it (a close and a
/// reopen) asks for nothing.
#[test]
fn only_a_document_pulled_before_it_was_opened_is_refreshed_and_once() {
    let scratch = workspace("pull-before-open-once", true);
    let root = &scratch.0;
    let rule = file_uri(&root.join("objects/rules/rule-1.0.yaml"));
    let objective = file_uri(&root.join("objects/objectives/objective-1.0.yaml"));
    let (mut lsp, _) =
        start(json!({ "capabilities": workspace_pulling(), "rootUri": file_uri(root) }));
    // Never pulled while closed: opening it asks for no refresh.
    open(&mut lsp, &objective, "opentide-yaml", &fixture(OBJECTIVE));
    let _ = pulled_report(&mut lsp, &objective);
    let stats = lsp.request("opentide/__stats", Value::Null);
    assert!(stats.get("error").is_none(), "{stats}");

    let _ = pulled_report(&mut lsp, &rule);
    open(&mut lsp, &rule, "opentide-yaml", &fixture(RULE));
    let refresh = next_server_request(&mut lsp);
    assert_eq!(
        refresh["method"], "workspace/diagnostic/refresh",
        "{refresh}"
    );
    lsp.notify(
        "textDocument/didClose",
        json!({ "textDocument": { "uri": rule } }),
    );
    open(&mut lsp, &rule, "opentide-yaml", &fixture(RULE));
    // The next thing the server says is the answer to this request: a second
    // refresh would come first.
    let id = lsp.next_id;
    lsp.write(&json!({ "jsonrpc": "2.0", "id": id, "method": "opentide/__stats" }));
    lsp.next_id += 1;
    let next = lsp.read();
    assert_eq!(next["id"], id, "an unexpected message: {next}");
    assert!(next.get("method").is_none(), "{next}");
}

/// A pull the server cannot answer is `ServerCancelled` with
/// `retriggerRequest`, so that the client asks again, and not an empty report
/// that it keeps. It is refused once: `vscode-languageclient` asks again at
/// once, with no delay, for as long as it is refused, and a document that
/// never opens (another YAML, which `didOpen` leaves alone) would be a loop.
/// The second pull is answered, and a `didOpen` that comes after still has the
/// client pull again.
#[test]
fn a_pull_the_server_cannot_answer_is_refused_once_for_the_client_to_retry() {
    let scratch = workspace("pull-cancelled", true);
    let root = &scratch.0;
    let (mut lsp, _) =
        start(json!({ "capabilities": workspace_pulling(), "rootUri": file_uri(root) }));
    let outside = file_uri(
        &std::env::temp_dir().join("opentide-pull-cancelled-elsewhere/objects/rules/rule.yaml"),
    );
    // A file under the root that the workspace does not know (yet).
    let unknown = file_uri(&root.join("objects/rules/rule-9.9.yaml"));
    for uri in [&outside, &unknown] {
        let reply = lsp.request(
            "textDocument/diagnostic",
            json!({ "textDocument": { "uri": uri } }),
        );
        assert_eq!(reply["error"]["code"], -32802, "{uri}: {reply}");
        assert_eq!(reply["error"]["data"]["retriggerRequest"], true, "{reply}");
        assert!(reply.get("result").is_none(), "{reply}");
        // Asked again, at once: answered, not refused in a loop.
        let (kind, id, codes) = pulled_report(&mut lsp, uri);
        assert_eq!(kind, "full", "{uri}");
        assert!(id.is_some(), "{uri}");
        assert!(codes.is_empty(), "{uri}: {codes:?}");
        // And not refused again, however often it is asked.
        let (kind, _, _) = pulled_report(&mut lsp, uri);
        assert!(kind == "full" || kind == "unchanged", "{uri}: {kind}");
    }
    // The document that was answered empty opens after all: the client is
    // asked to pull again, and the pull is of the open text.
    open(&mut lsp, &unknown, "opentide-yaml", &fixture(RULE));
    let refresh = next_server_request(&mut lsp);
    assert_eq!(
        refresh["method"], "workspace/diagnostic/refresh",
        "{refresh}"
    );
    let (_, _, codes) = pulled_report(&mut lsp, &unknown);
    assert!(
        !codes.is_empty(),
        "the open document shows nothing: {codes:?}"
    );
}

/// A workspace of `count` rules (the fixture's, each with its own UUID).
fn rules_workspace(name: &str, count: usize) -> Scratch {
    let scratch = workspace(name, false);
    let rule = fixture(RULE);
    let first_uuid = "00000000-0000-4000-8003-000000000001";
    assert!(rule.contains(first_uuid));
    for i in 2..=count {
        let text = rule.replacen(first_uuid, &format!("00000000-0000-4000-8003-{i:012}"), 1);
        std::fs::write(
            scratch.0.join(format!("objects/rules/rule-{i:04}.yaml")),
            text,
        )
        .unwrap();
    }
    scratch
}

/// The capabilities of a client that pulls diagnostics and watches files.
fn pulling_and_watching() -> Value {
    pulling(json!({ "workspace": {
        "diagnostics": { "refreshSupport": true },
        "didChangeWatchedFiles": { "dynamicRegistration": true },
    } }))
}

/// A workspace pull the client cancels while it yields to the messages
/// behind it is answered `RequestCanceled`, after them.
#[test]
fn a_workspace_pull_cancelled_while_it_yields_is_answered_cancelled() {
    let scratch = rules_workspace("pull-yields-cancelled", 1000);
    let root = &scratch.0;
    let (mut lsp, _) =
        start(json!({ "capabilities": pulling_and_watching(), "rootUri": file_uri(root) }));
    let register = lsp.read();
    lsp.write(&json!({ "jsonrpc": "2.0", "id": register["id"], "result": null }));
    let uri = file_uri(&root.join("objects/rules/rule-1.0.yaml"));
    open(&mut lsp, &uri, "opentide-yaml", &fixture(RULE));
    send(
        &mut lsp,
        1,
        "textDocument/diagnostic",
        json!({ "textDocument": { "uri": uri } }),
    );
    send(
        &mut lsp,
        2,
        "workspace/diagnostic",
        json!({ "previousResultIds": [] }),
    );
    until_response(&mut lsp, 1);
    send(
        &mut lsp,
        3,
        "textDocument/foldingRange",
        json!({ "textDocument": { "uri": uri } }),
    );
    lsp.notify("$/cancelRequest", json!({ "id": 2 }));
    let seen = until_response(&mut lsp, 2);
    let answered: Vec<i64> = seen
        .iter()
        .filter(|message| message.get("method").is_none())
        .filter_map(|message| message["id"].as_i64())
        .collect();
    assert_eq!(answered, [3, 2], "{seen:#?}");
    assert_eq!(seen.last().unwrap()["error"]["code"], -32800, "{seen:#?}");
}

/// #1767: what VS Code sends after it opens a rule (QA's trace): the
/// document's diagnostics, the workspace's, then `documentSymbol`,
/// `codeAction`, `documentLink`, `inlayHint`, `foldingRange` and
/// `semanticTokens/full`. The four after the workspace pull arrive while the
/// server makes it, on a workspace of 1,000 rules; each is answered before
/// the workspace pull, which yields to them and is answered after, with every
/// rule's report.
#[test]
fn document_requests_sent_during_a_workspace_pull_are_answered_first() {
    let scratch = rules_workspace("pull-yields", 1000);
    let root = &scratch.0;
    let rule = fixture(RULE);
    let (mut lsp, _) =
        start(json!({ "capabilities": pulling_and_watching(), "rootUri": file_uri(root) }));
    let register = lsp.read();
    lsp.write(&json!({ "jsonrpc": "2.0", "id": register["id"], "result": null }));
    let uri = file_uri(&root.join("objects/rules/rule-1.0.yaml"));
    open(&mut lsp, &uri, "opentide-yaml", &rule);
    let document = json!({ "textDocument": { "uri": uri } });
    let range =
        json!({ "start": { "line": 0, "character": 0 }, "end": { "line": 5, "character": 0 } });
    send(&mut lsp, 1, "textDocument/diagnostic", document.clone());
    send(
        &mut lsp,
        2,
        "workspace/diagnostic",
        json!({ "previousResultIds": [] }),
    );
    // The document's diagnostics are answered first (the batch's rule); the
    // workspace pull starts after them, and the rest arrive while it runs.
    let mut seen = until_response(&mut lsp, 1);
    let requests = [
        (3, "textDocument/documentSymbol", document.clone()),
        (
            4,
            "textDocument/codeAction",
            json!({ "textDocument": { "uri": uri }, "range": range, "context": { "diagnostics": [] } }),
        ),
        (5, "textDocument/documentLink", document.clone()),
        (
            6,
            "textDocument/inlayHint",
            json!({ "textDocument": { "uri": uri }, "range": range }),
        ),
        (7, "textDocument/foldingRange", document.clone()),
        (8, "textDocument/semanticTokens/full", document.clone()),
    ];
    for (id, method, params) in requests {
        send(&mut lsp, id, method, params);
    }
    seen.extend(until_response(&mut lsp, 2));
    let answered: Vec<i64> = seen
        .iter()
        .filter(|message| message.get("method").is_none())
        .filter_map(|message| message["id"].as_i64())
        .collect();
    let at = |id: i64| answered.iter().position(|seen| *seen == id);
    let pull = at(2).unwrap_or_else(|| panic!("{answered:?}"));
    for id in 3..=8 {
        let answer = at(id).unwrap_or_else(|| panic!("no answer to {id}: {answered:?}"));
        assert!(
            answer < pull,
            "request {id} waited for the workspace pull: {answered:?}"
        );
    }
    let report = seen.last().unwrap();
    let items = report["result"]["items"]
        .as_array()
        .unwrap_or_else(|| panic!("{report}"));
    // Every closed rule is reported: 999 (the opened one is the document's).
    assert_eq!(items.len(), 999, "{report}");
    let yields = lsp.request("opentide/__stats", Value::Null)["result"]["pullYields"]
        .as_u64()
        .unwrap();
    assert!(yields >= 1, "{yields}");
    // The first validation of every object ran once, to its end. Whether it
    // also stopped for these messages depends on timing (a many-core host can
    // finish its first batch before they wait), so that is not asserted here:
    // `checks.rs` and `opentide-workspace`'s tests hold stopping and resuming
    // deterministically.
    let stats = lsp.request("opentide/__stats", Value::Null);
    assert_eq!(stats["result"]["validations"]["full"], 1, "{stats}");
}

/// #1767: the server reads each folder and file of the disk once between
/// two messages that may say it changed, and a watcher's event is one: an
/// object file read earlier in a batch, then changed on disk, is read again
/// for the event that reports it later in the same batch, and the
/// workspace's diagnostics are the new text's.
#[test]
fn a_file_changed_on_disk_within_a_batch_is_read_again_for_its_event() {
    let scratch = workspace("disk-within-a-batch", true);
    let root = &scratch.0;
    let caps = pulling(json!({ "workspace": {
        "diagnostics": { "refreshSupport": true },
        "didChangeWatchedFiles": { "dynamicRegistration": true },
    } }));
    let (mut lsp, _) = start(json!({ "capabilities": caps, "rootUri": file_uri(root) }));
    let register = lsp.read();
    lsp.write(&json!({ "jsonrpc": "2.0", "id": register["id"], "result": null }));
    let rule = root.join("objects/rules/rule-1.0.yaml");
    // One batch: a request that reads every object file (the editor's index,
    // from the workspace it loads), a pause in which the rule changes on
    // disk, the watcher's event for it, and the workspace's diagnostics.
    hold(&mut lsp, 1);
    send(&mut lsp, 2, "workspace/symbol", json!({ "query": "" }));
    send(&mut lsp, 3, "opentide/__sleep", json!({ "ms": 400 }));
    lsp.notify(
        "workspace/didChangeWatchedFiles",
        json!({ "changes": [{ "uri": file_uri(&rule), "type": 2 }] }),
    );
    send(
        &mut lsp,
        4,
        "workspace/diagnostic",
        json!({ "previousResultIds": [] }),
    );
    until_response(&mut lsp, 2);
    let text = std::fs::read_to_string(&rule).unwrap();
    let changed = text.replacen("tlp: clear", "tlp: clearr", 1);
    assert_ne!(changed, text);
    std::fs::write(&rule, changed).unwrap();
    let report = until_response(&mut lsp, 4).pop().unwrap();
    let items = report["result"]["items"]
        .as_array()
        .unwrap_or_else(|| panic!("{report}"));
    let rule_item = items
        .iter()
        .find(|item| {
            item["uri"]
                .as_str()
                .is_some_and(|uri| uri.ends_with("rule-1.0.yaml"))
        })
        .unwrap_or_else(|| panic!("no report for the rule: {report}"));
    let codes = codes_of(rule_item["items"].as_array().unwrap_or(&Vec::new()));
    assert!(codes.contains(&"vocab_unknown".to_string()), "{codes:?}");
}

/// A client that shows `labelDetails` and resolves documentation, as VS Code is.
fn vocabulary_client() -> Lsp {
    let capabilities = json!({ "textDocument": { "completion": {
        "completionItem": {
            "labelDetailsSupport": true,
            "resolveSupport": { "properties": ["documentation", "detail"] }
        },
        "completionList": { "itemDefaults": ["commitCharacters", "editRange", "data"] }
    } } });
    start(json!({ "capabilities": capabilities })).0
}

/// The items completion offers at the end of `text`, opened as `uri`, and the
/// `data` the list says once for them all (`null` when each says its own).
fn complete_at_end(lsp: &mut Lsp, uri: &str, text: &str) -> (Vec<Value>, Value) {
    open(lsp, uri, "opentide-yaml", text);
    let line = text.lines().count() - 1;
    let character = text.lines().last().unwrap().len();
    let list = lsp.request(
        "textDocument/completion",
        json!({
            "textDocument": { "uri": uri },
            "position": { "line": line, "character": character }
        }),
    );
    let result = list["result"].clone();
    let items = result
        .as_array()
        .or_else(|| result["items"].as_array())
        .unwrap_or_else(|| panic!("{result}"))
        .clone();
    (items, result["itemDefaults"]["data"].clone())
}

/// Each item's label, asserting that no value is offered twice, and none as
/// a schema search hint (`T1548 #Abuse Elevation Control Mechanism`).
fn labels_offered_once(items: &[Value]) -> std::collections::BTreeSet<&str> {
    let labels: std::collections::BTreeSet<&str> = items
        .iter()
        .filter_map(|item| item["label"].as_str())
        .collect();
    assert_eq!(labels.len(), items.len(), "a value is offered twice");
    assert!(
        labels.iter().all(|label| !label.contains(" #")),
        "a search hint is offered: {:?}",
        labels.iter().find(|label| label.contains(" #"))
    );
    labels
}

const THREAT_HEAD: &str = "name: Simulated actor
metadata:
  uuid: 00000000-0000-4000-8003-000000000099
  schema: threat::1.0
  version: 1
threat:
";

/// Completion of a vocabulary value (#1745 item 2): under `threat.mitre_attack`
/// each ATT&CK technique is one item, never also its schema search hint; its
/// name is shown beside it (`labelDetails.description`), the client finds it
/// by that name too (`filterText`), it inserts the bare value, and
/// `completionItem/resolve` documents it from the vocabulary, which the list
/// leaves to it.
#[test]
fn an_attack_technique_is_offered_once_named_and_documented_on_resolve() {
    let mut lsp = vocabulary_client();
    let head = format!("{THREAT_HEAD}  mitre_attack:\n    - T1059\n    - ");
    let (items, data) = complete_at_end(
        &mut lsp,
        "file:///tmp/objects/threats/techniques.yaml",
        &head,
    );
    let labels = labels_offered_once(&items);
    assert!(items.len() > 900, "{} items", items.len());
    let uac = items
        .iter()
        .find(|item| item["label"] == "T1548.002")
        .unwrap_or_else(|| panic!("no T1548.002 among {labels:?}"));
    assert_eq!(
        uac["labelDetails"]["description"],
        "Abuse Elevation Control Mechanism: Bypass User Account Control",
        "{uac}"
    );
    let filter = uac["filterText"].as_str().unwrap_or_default();
    assert!(
        filter.starts_with("T1548.002 ") && filter.contains("Bypass User Account Control"),
        "{uac}"
    );
    // The bare value is inserted, and the list carries no documentation.
    assert!(
        uac.get("textEditText").is_none()
            && uac
                .get("insertText")
                .is_none_or(|text| *text == "T1548.002"),
        "{uac}"
    );
    assert!(uac.get("documentation").is_none_or(Value::is_null), "{uac}");
    let mut sent = uac.clone();
    if sent.get("data").is_none() {
        sent["data"] = data;
    }
    let resolved = lsp.request("completionItem/resolve", sent)["result"].clone();
    let docs = resolved["documentation"]["value"]
        .as_str()
        .unwrap_or_default();
    assert_eq!(resolved["documentation"]["kind"], "markdown", "{resolved}");
    for said in [
        "Abuse Elevation Control Mechanism: Bypass User Account Control",
        "`T1548.002`",
        "Adversaries may bypass UAC mechanisms",
    ] {
        assert!(docs.contains(said), "resolve does not say {said:?}: {docs}");
    }
    // Typing a word of the name finds the technique.
    let (typed, _) = complete_at_end(
        &mut lsp,
        "file:///tmp/objects/threats/typed.yaml",
        &format!("{head}bypass"),
    );
    assert!(
        typed.iter().any(|item| item["label"] == "T1548.002"),
        "`bypass` does not find T1548.002: {typed:?}"
    );
}

/// An actor's `name` offers each actor once, named, and found by its aliases.
#[test]
fn a_threat_actor_is_offered_once_and_named() {
    let mut lsp = vocabulary_client();
    let actors = format!("{THREAT_HEAD}  actors:\n    - name: ");
    let (items, _) = complete_at_end(&mut lsp, "file:///tmp/objects/threats/actors.yaml", &actors);
    let labels = labels_offered_once(&items);
    assert!(items.len() > 1000, "{} items", items.len());
    let apt1 = items
        .iter()
        .find(|item| item["label"] == "att&ck::G0006")
        .unwrap_or_else(|| panic!("no att&ck::G0006 among {labels:?}"));
    assert_eq!(
        apt1["labelDetails"]["description"], "[Enterprise] APT1",
        "{apt1}"
    );
    assert!(
        apt1["filterText"]
            .as_str()
            .unwrap_or_default()
            .contains("Comment Crew"),
        "{apt1}"
    );
}

/// A client that neither shows `labelDetails` nor resolves an item (a bare
/// LSP client) reads a technique's name as the item's detail, and finds it by
/// the name as well.
#[test]
fn a_client_without_label_details_reads_the_name_as_the_detail() {
    let (mut lsp, _) = start(json!({ "capabilities": {} }));
    let head = format!("{THREAT_HEAD}  mitre_attack:\n    - ");
    let (items, _) = complete_at_end(&mut lsp, "file:///tmp/objects/threats/bare.yaml", &head);
    labels_offered_once(&items);
    let uac = items
        .iter()
        .find(|item| item["label"] == "T1548.002")
        .expect("T1548.002");
    assert!(uac.get("labelDetails").is_none_or(Value::is_null), "{uac}");
    assert_eq!(
        uac["detail"], "Abuse Elevation Control Mechanism: Bypass User Account Control",
        "{uac}"
    );
    assert!(
        uac["filterText"]
            .as_str()
            .is_some_and(|text| text.contains("Bypass User Account Control")),
        "{uac}"
    );
    // Resolving it, as a client may still do, keeps the detail and documents it.
    let resolved = lsp.request("completionItem/resolve", uac.clone())["result"].clone();
    assert_eq!(resolved["detail"], uac["detail"], "{resolved}");
    assert!(
        resolved["documentation"]["value"]
            .as_str()
            .is_some_and(|docs| docs.contains("Adversaries may bypass UAC mechanisms")),
        "{resolved}"
    );
}

/// The frames of `out`, a server's whole output.
fn frames_of(out: &[u8]) -> Vec<Value> {
    let mut frames = Vec::new();
    let mut rest = out;
    while let Some(end) = rest.windows(4).position(|w| w == b"\r\n\r\n") {
        let header = std::str::from_utf8(&rest[..end]).unwrap();
        let length: usize = header
            .lines()
            .find_map(|line| line.strip_prefix("Content-Length:"))
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        let body = &rest[end + 4..end + 4 + length];
        frames.push(serde_json::from_slice(body).unwrap());
        rest = &rest[end + 4 + length..];
    }
    frames
}

/// A client that sends a workspace pull and closes its output without
/// `shutdown` (a script, a pipe) still gets the pull's answer: the end of
/// input is no message for the pull to yield to, and a pull a batch carried
/// is answered when the input ends (review of #1819).
#[test]
fn a_workspace_pull_is_answered_when_the_input_ends_while_it_runs() {
    use std::io::{Read as _, Write as _};
    let scratch = rules_workspace("pull-input-ends", 1000);
    let root = &scratch.0;
    let mut child = std::process::Command::new(common::bin())
        .arg("--stdio")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let reader = std::thread::spawn(move || {
        let mut out = Vec::new();
        stdout.read_to_end(&mut out).unwrap();
        out
    });
    let messages = [
        json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": { "capabilities": pulling_and_watching(), "rootUri": file_uri(root) } }),
        json!({ "jsonrpc": "2.0", "method": "initialized", "params": {} }),
        json!({ "jsonrpc": "2.0", "id": 2, "method": "workspace/diagnostic",
                "params": { "previousResultIds": [] } }),
    ];
    for message in messages {
        let body = serde_json::to_vec(&message).unwrap();
        write!(stdin, "Content-Length: {}\r\n\r\n", body.len()).unwrap();
        stdin.write_all(&body).unwrap();
    }
    stdin.flush().unwrap();
    // The end of input arrives while the pull runs.
    std::thread::sleep(std::time::Duration::from_millis(50));
    drop(stdin);
    let frames = frames_of(&reader.join().unwrap());
    let _ = child.wait();
    let pull = frames
        .iter()
        .find(|frame| frame["id"] == 2 && frame.get("method").is_none())
        .unwrap_or_else(|| panic!("the pull was never answered: {frames:#?}"));
    let items = pull["result"]["items"]
        .as_array()
        .unwrap_or_else(|| panic!("{pull}"));
    assert_eq!(items.len(), 1000, "{pull}");
}

/// A workspace pull from a client that watches no files never yields:
/// nothing it finds is kept from one batch to the next for that client, so
/// an attempt that yields is lost, and a client that keeps sending would
/// starve it (review of #1819). The requests behind it wait, as before.
#[test]
fn a_workspace_pull_without_a_file_watcher_never_yields() {
    let scratch = rules_workspace("pull-no-watcher", 1000);
    let root = &scratch.0;
    let caps = pulling(json!({ "workspace": { "diagnostics": { "refreshSupport": true } } }));
    let (mut lsp, _) = start(json!({ "capabilities": caps, "rootUri": file_uri(root) }));
    let uri = file_uri(&root.join("objects/rules/rule-1.0.yaml"));
    open(&mut lsp, &uri, "opentide-yaml", &fixture(RULE));
    send(
        &mut lsp,
        2,
        "workspace/diagnostic",
        json!({ "previousResultIds": [] }),
    );
    std::thread::sleep(std::time::Duration::from_millis(50));
    send(
        &mut lsp,
        3,
        "textDocument/foldingRange",
        json!({ "textDocument": { "uri": uri } }),
    );
    let seen = until_response(&mut lsp, 3);
    assert!(
        seen.iter()
            .any(|message| message["id"] == 2 && message.get("method").is_none()),
        "the pull yielded: {seen:#?}"
    );
    let yields = lsp.request("opentide/__stats", Value::Null)["result"]["pullYields"]
        .as_u64()
        .unwrap();
    assert_eq!(yields, 0);
}

/// A client that edits, while a workspace pull runs, a field the checks
/// across objects read (the rule's `name`, every 30 ms until the pull is
/// answered) makes each attempt check every object again before it reports
/// any file: the pull yields for at most a second after its first attempt,
/// then runs to its end, so it is answered while the edits go on (review of
/// #1819).
#[test]
fn a_workspace_pull_is_answered_while_the_client_keeps_editing() {
    use std::io::{BufRead as _, Read as _, Write as _};
    let scratch = rules_workspace("pull-keeps-editing", 1000);
    let root = &scratch.0;
    let rule = fixture(RULE);
    assert!(rule.starts_with("name: "), "{rule}");
    let (mut lsp, _) =
        start(json!({ "capabilities": pulling_and_watching(), "rootUri": file_uri(root) }));
    let register = lsp.read();
    lsp.write(&json!({ "jsonrpc": "2.0", "id": register["id"], "result": null }));
    let uri = file_uri(&root.join("objects/rules/rule-1.0.yaml"));
    open(&mut lsp, &uri, "opentide-yaml", &rule);
    send(
        &mut lsp,
        2,
        "workspace/diagnostic",
        json!({ "previousResultIds": [] }),
    );
    let answered = std::sync::atomic::AtomicBool::new(false);
    let Lsp { stdin, reader, .. } = &mut lsp;
    let in_time = std::thread::scope(|scope| {
        // The edits go out from a thread of their own, so they keep coming
        // whatever the server answers; the pull's answer stops them.
        let editor = scope.spawn(|| {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
            let mut version = 1;
            while !answered.load(std::sync::atomic::Ordering::SeqCst) {
                if std::time::Instant::now() >= deadline {
                    return false;
                }
                version += 1;
                let text = rule.replacen("name: ", &format!("name: Edit {version} "), 1);
                let body = serde_json::to_vec(&json!({ "jsonrpc": "2.0",
                    "method": "textDocument/didChange",
                    "params": { "textDocument": { "uri": uri, "version": version },
                                "contentChanges": [{ "text": text }] } }))
                .unwrap();
                write!(stdin, "Content-Length: {}\r\n\r\n", body.len()).unwrap();
                stdin.write_all(&body).unwrap();
                stdin.flush().unwrap();
                std::thread::sleep(std::time::Duration::from_millis(30));
            }
            true
        });
        loop {
            let mut length = 0;
            loop {
                let mut header = String::new();
                reader.read_line(&mut header).unwrap();
                let header = header.trim_end();
                if header.is_empty() {
                    break;
                }
                if let Some(value) = header.strip_prefix("Content-Length:") {
                    length = value.trim().parse().unwrap();
                }
            }
            let mut body = vec![0; length];
            reader.read_exact(&mut body).unwrap();
            let message: Value = serde_json::from_slice(&body).unwrap();
            if message["id"] == 2 && message.get("method").is_none() {
                assert!(message["result"]["items"].is_array(), "{message}");
                answered.store(true, std::sync::atomic::Ordering::SeqCst);
                break;
            }
        }
        editor.join().unwrap()
    });
    assert!(in_time, "the pull was not answered within 60 s of edits");
}

/// #1943: a keystroke in one open object runs the engine on that object
/// alone. The analysis of every open object is made again (what `validate`
/// says of one may change with another), but the engine's analysis of an
/// object reads no other object, and is kept per text. What each document
/// is told is what a server that opens the same texts tells it.
#[test]
fn a_keystroke_runs_the_engine_on_the_object_it_changed_alone() {
    const OPEN: usize = 10;
    let scratch = workspace("engine-analysis-per-text", true);
    let rules = scratch.0.join("objects/rules");
    let mut texts: Vec<(String, String)> = (0..OPEN)
        .map(|n| {
            let path = rules.join(format!("rule-{n}.yaml"));
            let text = fixture(RULE)
                .replace("8003-000000000001", &format!("8003-0000000001{n:02}"))
                .replace("name: Sentinel KQL Rule", &format!("name: Rule é😀 {n}"));
            std::fs::write(&path, &text).unwrap();
            (file_uri(&path), text)
        })
        .collect();
    let session = |texts: &[(String, String)]| {
        let (mut lsp, _) = start(json!({
            "capabilities": watching_relative(),
            "rootUri": file_uri(&scratch.0)
        }));
        for (uri, text) in texts {
            open(&mut lsp, uri, "opentide-yaml", text);
        }
        lsp
    };
    let pull_all = |lsp: &mut Lsp, texts: &[(String, String)]| -> Vec<Value> {
        texts
            .iter()
            .map(|(uri, _)| {
                let report = lsp.request(
                    "textDocument/diagnostic",
                    json!({ "textDocument": { "uri": uri } }),
                );
                report["result"]["items"].clone()
            })
            .collect()
    };
    let engine = |lsp: &mut Lsp| {
        lsp.request("opentide/__stats", Value::Null)["result"]["engineAnalyses"]
            .as_u64()
            .unwrap()
    };

    let mut lsp = session(&texts);
    pull_all(&mut lsp, &texts);
    assert_eq!(engine(&mut lsp), OPEN as u64, "each object once");
    let analyses = stats(&mut lsp);

    let typed = format!("{}\n# typé 😀\n", texts[0].1);
    lsp.notify(
        "textDocument/didChange",
        json!({ "textDocument": { "uri": texts[0].0, "version": 2 },
                "contentChanges": [{ "text": typed }] }),
    );
    texts[0].1 = typed;
    let after = pull_all(&mut lsp, &texts);
    assert_eq!(
        engine(&mut lsp),
        OPEN as u64 + 1,
        "a keystroke ran the engine on every open object again"
    );
    assert_eq!(
        stats(&mut lsp),
        analyses + OPEN as u64,
        "the findings across objects are made again for each"
    );

    let mut fresh = session(&texts);
    assert_eq!(after, pull_all(&mut fresh, &texts));
    assert!(
        after
            .iter()
            .any(|items| !items.as_array().unwrap().is_empty()),
        "the comparison compares diagnostics: {after:?}"
    );
}
