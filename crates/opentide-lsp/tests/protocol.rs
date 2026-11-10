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
    // #172: the binary alone has no host or schemas; it checks configuration
    // natively (UC-2.6).
    let opentide = &caps["experimental"]["opentide"];
    assert!(opentide["host"].is_null(), "{opentide}");
    assert_eq!(opentide["catalog"], "bundled");
    assert_eq!(opentide["configurationChecks"], true);
    assert_eq!(opentide["configurationSchemas"], false);
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
    assert_eq!(info["catalog"], "bundled");
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
            "**/.opentide/lsp/catalogs/generated/*"
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

    // A configuration file and a catalog changed on disk re-check it too.
    for changed in [
        root.join(".opentide/configurations/platforms/sentinel.toml"),
        root.join(".opentide/lsp/catalogs/generated/fields.json"),
    ] {
        lsp.notify(
            "workspace/didChangeWatchedFiles",
            json!({ "changes": [{ "uri": file_uri(&changed), "type": 2 }] }),
        );
        published_for(&mut lsp, &rule_uri);
    }
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
/// root: it is built on the first request that reads it, every file then.
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
}

/// #914: an Elastic rule's advisories still read the objects on disk: a
/// technique it inherits through `detection_model` that is not Enterprise
/// ATT&CK is reported on its first diagnostics.
#[test]
fn an_elastic_rule_reads_the_techniques_it_inherits() {
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
    let inherited = diagnostics
        .iter()
        .find(|d| d["code"] == "technique_not_enterprise")
        .unwrap_or_else(|| panic!("{diagnostics:#?}"));
    assert!(
        inherited["message"].as_str().unwrap().contains("T1626"),
        "{inherited}"
    );
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

/// P0.9: a value two fields share is documented from the field it was
/// completed for, through the item's `data`.
#[test]
fn resolve_documents_a_value_from_its_own_field() {
    let scratch = Scratch::new("enum-docs");
    let catalogs = scratch.0.join(".opentide/lsp/catalogs/generated");
    std::fs::create_dir_all(&catalogs).unwrap();
    std::fs::write(
        catalogs.join("fields.json"),
        r#"{"opentide": "0.19.0", "fields": [
            {"schema": "rule", "path": "metadata", "name": "metadata", "type": "object"},
            {"schema": "rule", "path": "metadata.tlp", "name": "tlp", "type": "string",
             "enum": ["clear"], "enum_docs": ["TLP clear: anyone."]},
            {"schema": "rule", "path": "metadata.status", "name": "status", "type": "string",
             "enum": ["clear"], "enum_docs": ["Status clear: no finding."]}]}"#,
    )
    .unwrap();
    let (mut lsp, _) = start(json!({ "capabilities": {}, "rootUri": file_uri(&scratch.0) }));
    let uri = file_uri(&scratch.0.join("objects/rules/r.yaml"));
    let text = "name: R\nmetadata:\n  schema: rule::1.0\n  status: \n";
    open(&mut lsp, &uri, "opentide-yaml", text);
    let items = lsp.request(
        "textDocument/completion",
        json!({ "textDocument": { "uri": uri }, "position": { "line": 3, "character": 10 } }),
    );
    let mut item = items["result"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["label"] == "clear")
        .unwrap_or_else(|| panic!("{items}"))
        .clone();
    assert_eq!(item["data"]["field_path"], "metadata.status", "{item}");
    // A client that resolves documentation lazily sends the item without it.
    item.as_object_mut().unwrap().remove("documentation");
    let resolved = lsp.request("completionItem/resolve", item);
    let docs = resolved["result"]["documentation"]["value"]
        .as_str()
        .unwrap();
    assert!(docs.contains("Status clear"), "{resolved}");
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
