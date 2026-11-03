//! `opentide/catalog` and `opentide/catalogChanged` over stdio (#198): the
//! workspace index with each object's references, and the notification that
//! follows it.

mod common;

use common::*;
use serde_json::{Value, json};

const RULE: &str = "testdata/objects/rules/rule-1.0.yaml";
const OBJECTIVE: &str = "testdata/objects/objective-1.0.yaml";
const MODEL: &str = "00000000-0000-4000-8002-000000000001";
const DANGLING: &str = "00000000-0000-4000-8002-0000000000ff";

fn fixture(path: &str) -> String {
    std::fs::read_to_string(repo_root().join(path)).unwrap()
}

/// The fixture rule, whose `detection_model` names `model`.
fn rule(model: &str) -> String {
    fixture(RULE).replace(MODEL, model)
}

/// A workspace with the objective and a rule whose `detection_model` names
/// no object.
fn workspace(name: &str) -> Scratch {
    let scratch = Scratch::new(name);
    let objects = scratch.0.join("objects");
    std::fs::create_dir_all(objects.join("rules")).unwrap();
    std::fs::create_dir_all(objects.join("objectives")).unwrap();
    std::fs::write(objects.join("rules/rule-1.0.yaml"), rule(DANGLING)).unwrap();
    std::fs::write(
        objects.join("objectives/objective-1.0.yaml"),
        fixture(OBJECTIVE),
    )
    .unwrap();
    scratch
}

fn start(params: Value) -> Lsp {
    let mut lsp = Lsp::spawn();
    lsp.request("initialize", params);
    lsp.notify("initialized", json!({}));
    lsp
}

/// Every message the server sends for what was sent so far. A batch's
/// notifications follow its answers, so a second request, sent once the
/// first is answered, is in a later batch: its answer comes after them.
fn settle(lsp: &mut Lsp) -> Vec<Value> {
    let mut seen = Vec::new();
    for _ in 0..2 {
        let id = lsp.next_id;
        lsp.next_id += 1;
        lsp.write(&json!({ "jsonrpc": "2.0", "id": id, "method": "opentide/__stats" }));
        loop {
            let message = lsp.read();
            let done = message["id"] == id && message.get("method").is_none();
            seen.push(message);
            if done {
                break;
            }
        }
    }
    seen
}

fn catalog_changes(messages: &[Value]) -> Vec<&Value> {
    messages
        .iter()
        .filter(|m| m["method"] == "opentide/catalogChanged")
        .collect()
}

fn object<'a>(catalog: &'a Value, uuid: &str) -> Option<&'a Value> {
    catalog["roots"][0]["objects"]
        .as_array()
        .unwrap()
        .iter()
        .find(|o| o["uuid"] == uuid)
}

fn range(line: u64, start: u64, end: u64) -> Value {
    json!({
        "start": { "line": line, "character": start },
        "end": { "line": line, "character": end },
    })
}

fn did_change(lsp: &mut Lsp, uri: &str, text: &str) {
    lsp.notify(
        "textDocument/didChange",
        json!({ "textDocument": { "uri": uri }, "contentChanges": [{ "text": text }] }),
    );
}

#[test]
fn the_catalog_holds_a_dangling_ref_with_its_range_and_follows_the_edit_that_fixes_it() {
    let scratch = workspace("catalog-edit");
    let root = &scratch.0;
    let rule_uri = file_uri(&root.join("objects/rules/rule-1.0.yaml"));
    let objective_uri = file_uri(&root.join("objects/objectives/objective-1.0.yaml"));
    let mut lsp = start(json!({ "capabilities": {}, "rootUri": file_uri(root) }));

    let catalog = lsp.request("opentide/catalog", json!({}))["result"].clone();
    let roots = catalog["roots"].as_array().unwrap();
    assert_eq!(roots.len(), 1, "{catalog}");
    assert_eq!(roots[0]["root"], file_uri(root).as_str());
    let found = object(&catalog, "00000000-0000-4000-8003-000000000001").expect("the rule");
    assert_eq!(found["object_type"], "rule");
    assert_eq!(found["schema"], "rule::1.0");
    assert_eq!(found["name"], "Sentinel KQL Rule");
    assert_eq!(found["uri"], rule_uri.as_str());
    // `name: Sentinel KQL Rule`: the name's range.
    assert_eq!(found["range"], range(0, 6, 23));
    let refs = found["refs"].as_array().unwrap();
    let model = refs
        .iter()
        .find(|r| r["field_path"] == "detection_model")
        .unwrap_or_else(|| panic!("{refs:?}"));
    assert_eq!(model["uuid"], DANGLING);
    // `detection_model: <uuid>` is the fixture's 17th line.
    assert_eq!(model["range"], range(16, 17, 53));
    assert!(object(&catalog, DANGLING).is_none(), "the ref dangles");
    let objective = object(&catalog, MODEL).expect("the objective");
    assert_eq!(objective["uri"], objective_uri.as_str());
    assert_eq!(objective["object_type"], "objective");

    // Opening the rule as saved changes nothing the catalog says.
    lsp.notify(
        "textDocument/didOpen",
        json!({ "textDocument": { "uri": rule_uri, "languageId": "opentide-yaml", "version": 1, "text": rule(DANGLING) } }),
    );
    let seen = settle(&mut lsp);
    assert!(catalog_changes(&seen).is_empty(), "{seen:?}");

    // Nor does an edit of the description.
    did_change(
        &mut lsp,
        &rule_uri,
        &rule(DANGLING).replace("Minimal valid", "A minimal"),
    );
    let seen = settle(&mut lsp);
    assert!(catalog_changes(&seen).is_empty(), "{seen:?}");

    // The edit that fixes the ref is announced, once, before the next answer.
    did_change(&mut lsp, &rule_uri, &rule(MODEL));
    let seen = settle(&mut lsp);
    let changes = catalog_changes(&seen);
    assert_eq!(changes.len(), 1, "{seen:?}");
    assert_eq!(changes[0]["params"]["root"], file_uri(root).as_str());

    let catalog =
        lsp.request("opentide/catalog", json!({ "root": file_uri(root) }))["result"].clone();
    let found = object(&catalog, "00000000-0000-4000-8003-000000000001").unwrap();
    let model = found["refs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["field_path"] == "detection_model")
        .unwrap();
    assert_eq!(model["uuid"], MODEL);
    assert!(object(&catalog, MODEL).is_some(), "the ref resolves");

    // A root the server does not have has no catalog.
    let other = lsp.request(
        "opentide/catalog",
        json!({ "root": file_uri(&root.join("elsewhere")) }),
    );
    assert_eq!(other["result"], json!({ "roots": [] }));
}

#[test]
fn a_file_deleted_on_disk_is_announced_to_a_client_that_asked_for_the_catalog() {
    let scratch = workspace("catalog-watch");
    let root = &scratch.0;
    let mut lsp = start(json!({
        "capabilities": { "workspace": { "didChangeWatchedFiles": { "dynamicRegistration": true } } },
        "rootUri": file_uri(root),
    }));
    let register = lsp.read();
    assert_eq!(register["method"], "client/registerCapability");
    lsp.write(&json!({ "jsonrpc": "2.0", "id": register["id"], "result": null }));

    // Before the client asks for the catalog, nothing is announced.
    let objective = root.join("objects/objectives/objective-1.0.yaml");
    std::fs::write(
        &objective,
        fixture(OBJECTIVE).replace("Credential Access Objective", "Renamed"),
    )
    .unwrap();
    lsp.notify(
        "workspace/didChangeWatchedFiles",
        json!({ "changes": [{ "uri": file_uri(&objective), "type": 2 }] }),
    );
    let seen = settle(&mut lsp);
    assert!(catalog_changes(&seen).is_empty(), "{seen:?}");

    let catalog = lsp.request("opentide/catalog", json!({}))["result"].clone();
    assert_eq!(object(&catalog, MODEL).unwrap()["name"], "Renamed");

    std::fs::remove_file(&objective).unwrap();
    lsp.notify(
        "workspace/didChangeWatchedFiles",
        json!({ "changes": [{ "uri": file_uri(&objective), "type": 3 }] }),
    );
    let seen = settle(&mut lsp);
    let changes = catalog_changes(&seen);
    assert_eq!(changes.len(), 1, "{seen:?}");
    assert_eq!(changes[0]["params"]["root"], file_uri(root).as_str());
    let catalog = lsp.request("opentide/catalog", json!({}))["result"].clone();
    assert!(object(&catalog, MODEL).is_none(), "{catalog}");
}

fn roots_of(catalog: &Value) -> Vec<Value> {
    catalog["roots"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["root"].clone())
        .collect()
}

fn folder(path: &std::path::Path) -> Value {
    json!({ "uri": file_uri(path), "name": path.file_name().unwrap().to_str().unwrap() })
}

#[test]
fn a_root_found_around_an_opened_document_is_announced_with_the_loose_root_it_replaces() {
    let scratch = workspace("catalog-found-root");
    let root = &scratch.0;
    let rule_uri = file_uri(&root.join("objects/rules/rule-1.0.yaml"));
    // No folder: what @opentide/lsp-client sends by default.
    let mut lsp = start(json!({ "capabilities": {}, "rootUri": null }));
    let catalog = lsp.request("opentide/catalog", json!({}))["result"].clone();
    assert_eq!(
        catalog,
        json!({ "roots": [{ "root": null, "objects": [] }] }),
        "{catalog}"
    );

    lsp.notify(
        "textDocument/didOpen",
        json!({ "textDocument": { "uri": rule_uri, "languageId": "opentide-yaml", "version": 1, "text": rule(DANGLING) } }),
    );
    let seen = settle(&mut lsp);
    let mut announced: Vec<Value> = catalog_changes(&seen)
        .iter()
        .map(|m| m["params"]["root"].clone())
        .collect();
    announced.sort_by_key(|root| root.to_string());
    assert_eq!(announced, [json!(file_uri(root)), Value::Null], "{seen:?}");
    let catalog = lsp.request("opentide/catalog", json!({}))["result"].clone();
    assert_eq!(roots_of(&catalog), [json!(file_uri(root))], "{catalog}");
    assert!(object(&catalog, MODEL).is_some(), "{catalog}");

    // The found root is followed from then on.
    did_change(&mut lsp, &rule_uri, &rule(MODEL));
    let seen = settle(&mut lsp);
    let changes = catalog_changes(&seen);
    assert_eq!(changes.len(), 1, "{seen:?}");
    assert_eq!(changes[0]["params"]["root"], file_uri(root).as_str());
}

#[test]
fn a_workspace_folder_added_or_removed_is_announced_and_a_removed_one_leaves_the_catalog() {
    let a = workspace("catalog-folder-a");
    let b = workspace("catalog-folder-b");
    let mut lsp = start(json!({
        "capabilities": { "workspace": { "workspaceFolders": true } },
        "workspaceFolders": [folder(&a.0)],
    }));
    let catalog = lsp.request("opentide/catalog", json!({}))["result"].clone();
    assert_eq!(roots_of(&catalog), [json!(file_uri(&a.0))], "{catalog}");

    lsp.notify(
        "workspace/didChangeWorkspaceFolders",
        json!({ "event": { "added": [folder(&b.0)], "removed": [] } }),
    );
    let seen = settle(&mut lsp);
    let changes = catalog_changes(&seen);
    assert_eq!(changes.len(), 1, "{seen:?}");
    assert_eq!(changes[0]["params"]["root"], file_uri(&b.0).as_str());
    let catalog = lsp.request("opentide/catalog", json!({}))["result"].clone();
    assert_eq!(
        roots_of(&catalog),
        [json!(file_uri(&a.0)), json!(file_uri(&b.0))],
        "{catalog}"
    );

    lsp.notify(
        "workspace/didChangeWorkspaceFolders",
        json!({ "event": { "added": [], "removed": [folder(&a.0)] } }),
    );
    let seen = settle(&mut lsp);
    let changes = catalog_changes(&seen);
    assert_eq!(changes.len(), 1, "{seen:?}");
    assert_eq!(changes[0]["params"]["root"], file_uri(&a.0).as_str());
    let catalog = lsp.request("opentide/catalog", json!({}))["result"].clone();
    assert_eq!(roots_of(&catalog), [json!(file_uri(&b.0))], "{catalog}");
}

#[test]
fn a_removed_folder_with_an_open_document_stays_as_the_root_found_around_it() {
    let a = workspace("catalog-folder-open-a");
    let b = workspace("catalog-folder-open-b");
    let rule_uri = file_uri(&a.0.join("objects/rules/rule-1.0.yaml"));
    let mut lsp = start(json!({
        "capabilities": { "workspace": { "workspaceFolders": true } },
        "workspaceFolders": [folder(&a.0), folder(&b.0)],
    }));
    lsp.notify(
        "textDocument/didOpen",
        json!({ "textDocument": { "uri": rule_uri, "languageId": "opentide-yaml", "version": 1, "text": rule(DANGLING) } }),
    );
    lsp.request("opentide/catalog", json!({}));
    lsp.notify(
        "workspace/didChangeWorkspaceFolders",
        json!({ "event": { "added": [], "removed": [folder(&a.0)] } }),
    );
    // The open rule still reads its own workspace, not the other folder's.
    let seen = settle(&mut lsp);
    assert!(catalog_changes(&seen).is_empty(), "{seen:?}");
    let catalog = lsp.request("opentide/catalog", json!({}))["result"].clone();
    assert_eq!(
        roots_of(&catalog),
        [json!(file_uri(&b.0)), json!(file_uri(&a.0))],
        "{catalog}"
    );
}

#[test]
fn a_root_sent_with_a_trailing_slash_is_found_by_the_uri_the_catalog_reports() {
    let scratch = workspace("catalog-slash");
    let root = &scratch.0;
    let plain = file_uri(root);
    let slashed = format!("{plain}/");
    let mut lsp = start(json!({ "capabilities": {}, "rootUri": slashed }));
    let catalog = lsp.request("opentide/catalog", json!({}))["result"].clone();
    let reported = catalog["roots"][0]["root"].as_str().unwrap().to_string();
    assert_eq!(reported, plain, "{catalog}");
    for uri in [&reported, &plain, &slashed] {
        let catalog = lsp.request("opentide/catalog", json!({ "root": uri }))["result"].clone();
        assert_eq!(
            catalog["roots"].as_array().unwrap().len(),
            1,
            "{uri}: {catalog}"
        );
        assert!(object(&catalog, MODEL).is_some(), "{uri}: {catalog}");
    }
}

#[test]
fn a_web_workspace_root_is_reported_as_its_own_uri() {
    let folder_uri = "vscode-vfs://github/org/repo";
    let rule_uri = format!("{folder_uri}/objects/rules/rule-1.0.yaml");
    let mut lsp = start(json!({
        "capabilities": { "workspace": { "workspaceFolders": true } },
        "workspaceFolders": [{ "uri": folder_uri, "name": "repo" }],
    }));
    let catalog = lsp.request("opentide/catalog", json!({}))["result"].clone();
    assert_eq!(roots_of(&catalog), [json!(folder_uri)], "{catalog}");

    lsp.notify(
        "textDocument/didOpen",
        json!({ "textDocument": { "uri": rule_uri, "languageId": "opentide-yaml", "version": 1, "text": rule(DANGLING) } }),
    );
    let seen = settle(&mut lsp);
    let changes = catalog_changes(&seen);
    assert_eq!(changes.len(), 1, "{seen:?}");
    assert_eq!(changes[0]["params"]["root"], folder_uri);

    let catalog = lsp.request("opentide/catalog", json!({ "root": folder_uri }))["result"].clone();
    assert_eq!(roots_of(&catalog), [json!(folder_uri)], "{catalog}");
    let found = object(&catalog, "00000000-0000-4000-8003-000000000001").expect("the rule");
    assert_eq!(found["uri"], rule_uri.as_str());
}

#[test]
fn an_organisation_or_a_template_uuid_is_not_a_ref() {
    let org = "5f3c2a10-7b6e-4c1d-9a8f-2e4b6d0c1a73";
    let template = "f0c3a1b2-9d8e-4f7a-8b6c-5d4e3f2a1b0c";
    let scratch = workspace("catalog-not-refs");
    let root = &scratch.0;
    let text = rule(MODEL)
        .replace(
            "  tlp: clear\n",
            &format!("  tlp: clear\n  organisation:\n    uuid: {org}\n    name: ACME\n"),
        )
        .replace(
            "    enabled: true\n",
            &format!("    enabled: true\n    template:\n      uuid: {template}\n"),
        );
    assert!(text.contains(org) && text.contains(template));
    std::fs::write(root.join("objects/rules/rule-1.0.yaml"), text).unwrap();
    let mut lsp = start(json!({ "capabilities": {}, "rootUri": file_uri(root) }));
    let catalog = lsp.request("opentide/catalog", json!({}))["result"].clone();
    let found = object(&catalog, "00000000-0000-4000-8003-000000000001").expect("the rule");
    let refs: Vec<&str> = found["refs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["field_path"].as_str().unwrap())
        .collect();
    assert_eq!(refs, ["detection_model"], "{found}");
}

#[test]
fn a_catalog_request_without_params_or_with_null_asks_for_every_root() {
    let scratch = workspace("catalog-no-params");
    let root = &scratch.0;
    let rule_uri = file_uri(&root.join("objects/rules/rule-1.0.yaml"));
    let mut lsp = start(json!({ "capabilities": {}, "rootUri": file_uri(root) }));
    for request in [
        json!({ "jsonrpc": "2.0", "id": 900, "method": "opentide/catalog" }),
        json!({ "jsonrpc": "2.0", "id": 901, "method": "opentide/catalog", "params": null }),
    ] {
        lsp.write(&request);
        let response = lsp.read();
        assert_eq!(response["id"], request["id"], "{response}");
        assert_eq!(
            roots_of(&response["result"]),
            [json!(file_uri(root))],
            "{response}"
        );
    }
    // And the client is told when the catalog changes.
    lsp.notify(
        "textDocument/didOpen",
        json!({ "textDocument": { "uri": rule_uri, "languageId": "opentide-yaml", "version": 1, "text": rule(MODEL) } }),
    );
    let seen = settle(&mut lsp);
    let changes = catalog_changes(&seen);
    assert_eq!(changes.len(), 1, "{seen:?}");
    assert_eq!(changes[0]["params"]["root"], file_uri(root).as_str());
}
