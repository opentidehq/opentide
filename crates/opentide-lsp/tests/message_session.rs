//! The language server one message at a time ([`MessageSession`]), as the
//! browser build drives it: no stdio, no filesystem, and the workspace
//! supplied on `initialize`.

#![expect(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers outside #[test] functions: a panic fails the test"
)]

use opentide_lsp::MessageSession;
use serde_json::{Value, json};

fn send(session: &mut MessageSession, mut message: Value) -> Vec<Value> {
    message["jsonrpc"] = json!("2.0");
    session
        .handle(&message.to_string())
        .iter()
        .map(|text| serde_json::from_str(text).expect("each reply is one JSON message"))
        .collect()
}

fn start(options: Value) -> MessageSession {
    let mut session = MessageSession::new();
    let replies = send(
        &mut session,
        json!({
            "id": 1,
            "method": "initialize",
            "params": { "processId": null, "rootUri": null, "capabilities": {}, "initializationOptions": options },
        }),
    );
    assert_eq!(replies.len(), 1, "{replies:?}");
    assert_eq!(replies[0]["id"], 1);
    assert_eq!(replies[0]["result"]["serverInfo"]["name"], "opentide-lsp");
    assert!(
        send(
            &mut session,
            json!({ "method": "initialized", "params": {} })
        )
        .is_empty()
    );
    session
}

/// Open a document and return the diagnostics the server publishes for it.
fn open(session: &mut MessageSession, uri: &str, language: &str, text: &str) -> Vec<Value> {
    let replies = send(
        session,
        json!({
            "method": "textDocument/didOpen",
            "params": { "textDocument": { "uri": uri, "languageId": language, "version": 1, "text": text } },
        }),
    );
    let published = replies
        .iter()
        .find(|m| m["method"] == "textDocument/publishDiagnostics")
        .expect("didOpen publishes diagnostics");
    assert_eq!(published["params"]["uri"], uri);
    published["params"]["diagnostics"]
        .as_array()
        .expect("diagnostics")
        .clone()
}

fn codes(diagnostics: &[Value]) -> Vec<&str> {
    diagnostics
        .iter()
        .filter_map(|d| d["code"].as_str())
        .collect()
}

fn request(session: &mut MessageSession, id: u64, method: &str, params: Value) -> Value {
    let replies = send(
        session,
        json!({ "id": id, "method": method, "params": params }),
    );
    let reply = replies
        .into_iter()
        .find(|m| m["id"] == id)
        .expect("a response with the request's id");
    assert!(reply.get("error").is_none(), "{reply}");
    reply["result"].clone()
}

const OBJECTIVE: &str = "00000000-0000-4000-8002-000000000001";

const RULE: &str = "name: Process creation
metadata:
  uuid: 00000000-0000-4000-8003-000000000099
  schema: rule::1.0
  version: 1
  created: 2026-01-01
  modified: 2026-01-02
  tlp: clear
description: Process creation on a server.
status: STAGING
detection_model: 00000000-0000-4000-8002-000000000001
configurations:
  sentinel:
    query: |
      SecurityEvent
      | where EventID == 4688
";

#[test]
fn a_query_is_checked_hovered_and_completed() {
    let mut session = start(Value::Null);
    let broken = open(
        &mut session,
        "untitled:broken.kql",
        "kql",
        "SecurityEvent\n| wher EventID == 4688\n",
    );
    assert!(
        codes(&broken).iter().any(|c| c.starts_with("kql_")),
        "{broken:?}"
    );

    let text = "SecurityEvent\n| where EventID == 4688\n";
    assert!(open(&mut session, "untitled:q.kql", "kql", text).is_empty());
    let hover = request(
        &mut session,
        2,
        "textDocument/hover",
        json!({ "textDocument": { "uri": "untitled:q.kql" }, "position": { "line": 1, "character": 3 } }),
    );
    assert_eq!(hover["contents"]["kind"], "markdown");
    assert!(
        hover["contents"]["value"]
            .as_str()
            .unwrap()
            .contains("where"),
        "{hover}"
    );
    let items = request(
        &mut session,
        3,
        "textDocument/completion",
        json!({ "textDocument": { "uri": "untitled:q.kql" }, "position": { "line": 1, "character": 2 } }),
    );
    assert!(
        items
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["label"] == "where"),
        "{items}"
    );
}

#[test]
fn references_resolve_against_the_workspace_the_host_supplies() {
    let uri = "objects/rules/process-creation.yaml";

    // Alone, the rule's detection model is nothing the session has indexed.
    let mut alone = start(Value::Null);
    assert!(codes(&open(&mut alone, uri, "opentide-yaml", RULE)).contains(&"invalid_ref"));

    // An object the host knows by its metadata alone resolves, and hover names it.
    let mut known = start(json!({ "workspace": { "objects": [
        { "uuid": OBJECTIVE, "schema": "objective::1.0", "name": "Suspicious process creation" }
    ] } }));
    let diagnostics = open(&mut known, uri, "opentide-yaml", RULE);
    assert!(
        !codes(&diagnostics).contains(&"invalid_ref"),
        "{diagnostics:?}"
    );
    let line = RULE
        .lines()
        .position(|l| l.starts_with("detection_model:"))
        .unwrap();
    let hover = request(
        &mut known,
        2,
        "textDocument/hover",
        json!({ "textDocument": { "uri": uri }, "position": { "line": line, "character": 20 } }),
    );
    assert!(
        hover.to_string().contains("Suspicious process creation"),
        "{hover}"
    );

    // So does a whole document the host supplies.
    let objective = format!(
        "name: Suspicious process creation\nmetadata:\n  uuid: {OBJECTIVE}\n  schema: objective::1.0\n"
    );
    let mut documents = start(json!({ "workspace": { "documents": [
        { "uri": "objects/objectives/suspicious-process-creation.yaml", "text": objective }
    ] } }));
    assert!(!codes(&open(&mut documents, uri, "opentide-yaml", RULE)).contains(&"invalid_ref"));
}

#[test]
fn malformed_messages_unknown_methods_and_exit() {
    let mut session = MessageSession::new();
    let replies: Vec<Value> = session
        .handle("{ not json")
        .iter()
        .map(|t| serde_json::from_str(t).unwrap())
        .collect();
    assert_eq!(replies.len(), 1);
    assert_eq!(replies[0]["error"]["code"], -32700);

    // The lifecycle is the stdio server's: nothing before `initialize`.
    let replies = send(&mut session, json!({ "id": 6, "method": "shutdown" }));
    assert_eq!(replies[0]["id"], 6);
    assert_eq!(replies[0]["error"]["code"], -32002);

    let mut session = start(Value::Null);
    let replies = send(
        &mut session,
        json!({ "id": 7, "method": "opentide/nothing", "params": {} }),
    );
    assert_eq!(replies[0]["id"], 7);
    assert_eq!(replies[0]["error"]["code"], -32601);

    // A body that is a message but not a valid one is answered, and the
    // session goes on.
    let replies = session.handle("[1, 2]");
    let reply: Value = serde_json::from_str(&replies[0]).unwrap();
    assert_eq!(reply["error"]["code"], -32600);

    assert_eq!(
        request(&mut session, 8, "shutdown", Value::Null),
        Value::Null
    );
    assert!(!session.is_closed());
    assert!(send(&mut session, json!({ "method": "exit" })).is_empty());
    assert!(session.is_closed());
    assert!(session.shut_down());
    assert!(
        session
            .handle(r#"{"jsonrpc":"2.0","id":9,"method":"shutdown"}"#)
            .is_empty()
    );
}

/// A host that knows every object by its metadata and opens one of them:
/// the open file is that object, not a second one with its UUID.
#[test]
fn an_open_object_is_not_a_duplicate_of_its_own_metadata() {
    let objective = format!(
        "name: Suspicious process creation\nmetadata:\n  uuid: {OBJECTIVE}\n  schema: objective::1.0\n  version: 1\n  created: 2026-01-01\n  modified: 2026-01-02\n  tlp: clear\ndescription: Process creation.\n"
    );
    let mut session = start(json!({ "workspace": { "objects": [
        { "uuid": OBJECTIVE, "schema": "objective::1.0", "name": "Suspicious process creation" }
    ] } }));
    let diagnostics = open(
        &mut session,
        "objects/objectives/suspicious-process-creation.yaml",
        "opentide-yaml",
        &objective,
    );
    assert!(
        !codes(&diagnostics).contains(&"duplicate_id"),
        "{diagnostics:?}"
    );
}

/// What `send` returned: the diagnostic codes published for `uri`, if any.
fn published_codes(replies: &[Value], uri: &str) -> Option<Vec<String>> {
    replies
        .iter()
        .find(|m| m["method"] == "textDocument/publishDiagnostics" && m["params"]["uri"] == uri)
        .map(|m| {
            m["params"]["diagnostics"]
                .as_array()
                .unwrap()
                .iter()
                .filter_map(|d| d["code"].as_str().map(str::to_string))
                .collect()
        })
}

/// A host with no filesystem tells the server when the files it supplied
/// change: references follow, open documents are checked again, and the
/// catalog the client got is announced as changed.
#[test]
fn the_supplied_workspace_follows_did_change_workspace() {
    let rule = "objects/rules/process-creation.yaml";
    let objective_uri = "objects/objectives/suspicious-process-creation.yaml";
    let objective = |name: &str| {
        format!("name: {name}\nmetadata:\n  uuid: {OBJECTIVE}\n  schema: objective::1.0\n")
    };
    let mut session = start(json!({ "workspace": { "documents": [] } }));
    assert!(codes(&open(&mut session, rule, "opentide-yaml", RULE)).contains(&"invalid_ref"));
    let catalog = request(&mut session, 2, "opentide/catalog", json!({}));
    assert_eq!(catalog["roots"][0]["objects"].as_array().unwrap().len(), 1);

    // The objective appears: the rule's reference resolves.
    let replies = send(
        &mut session,
        json!({ "method": "opentide/didChangeWorkspace", "params": {
            "documents": [{ "uri": objective_uri, "text": objective("Suspicious process creation") }]
        } }),
    );
    let after = published_codes(&replies, rule).expect("the open rule is checked again");
    assert!(!after.contains(&"invalid_ref".to_string()), "{after:?}");
    assert!(
        replies
            .iter()
            .any(|m| m["method"] == "opentide/catalogChanged"),
        "{replies:?}"
    );
    let catalog = request(&mut session, 3, "opentide/catalog", json!({}));
    let names: Vec<&str> = catalog["roots"][0]["objects"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|o| o["name"].as_str())
        .collect();
    assert!(names.contains(&"Suspicious process creation"), "{names:?}");

    // The same text again changes nothing, and says nothing.
    let replies = send(
        &mut session,
        json!({ "method": "opentide/didChangeWorkspace", "params": {
            "documents": [{ "uri": objective_uri, "text": objective("Suspicious process creation") }]
        } }),
    );
    assert!(replies.is_empty(), "{replies:?}");

    // A new name is a catalog change; the reference still resolves.
    let replies = send(
        &mut session,
        json!({ "method": "opentide/didChangeWorkspace", "params": {
            "documents": [{ "uri": objective_uri, "text": objective("Renamed objective") }]
        } }),
    );
    assert!(
        replies
            .iter()
            .any(|m| m["method"] == "opentide/catalogChanged")
    );
    let line = RULE
        .lines()
        .position(|l| l.starts_with("detection_model:"))
        .unwrap();
    let hover = request(
        &mut session,
        4,
        "textDocument/hover",
        json!({ "textDocument": { "uri": rule }, "position": { "line": line, "character": 20 } }),
    );
    assert!(hover.to_string().contains("Renamed objective"), "{hover}");

    // Removed, the objective is gone again.
    let replies = send(
        &mut session,
        json!({ "method": "opentide/didChangeWorkspace", "params": { "removed": [objective_uri] } }),
    );
    let gone = published_codes(&replies, rule).expect("the open rule is checked again");
    assert!(gone.contains(&"invalid_ref".to_string()), "{gone:?}");

    // An object known by its metadata alone, and its removal by `opentide-object:<uuid>`.
    send(
        &mut session,
        json!({ "method": "opentide/didChangeWorkspace", "params": {
            "objects": [{ "uuid": OBJECTIVE, "schema": "objective::1.0", "name": "Known by metadata" }]
        } }),
    );
    let replies = send(
        &mut session,
        json!({ "method": "opentide/didChangeWorkspace", "params": {
            "removed": [format!("opentide-object:{OBJECTIVE}")]
        } }),
    );
    assert!(
        published_codes(&replies, rule)
            .expect("checked again")
            .contains(&"invalid_ref".to_string())
    );

    // Params that are not an object are logged, and the session goes on.
    let replies = send(
        &mut session,
        json!({ "method": "opentide/didChangeWorkspace", "params": [1] }),
    );
    assert!(
        replies.iter().all(|m| m["method"] == "window/logMessage"),
        "{replies:?}"
    );
}

#[test]
fn initialize_says_the_server_takes_workspace_updates() {
    let mut session = MessageSession::new();
    let replies = send(
        &mut session,
        json!({ "id": 1, "method": "initialize", "params": { "processId": null, "rootUri": null, "capabilities": {} } }),
    );
    assert_eq!(
        replies[0]["result"]["capabilities"]["experimental"]["opentide"]["workspaceUpdates"],
        true
    );
}

/// An object known by its metadata, supplied with a `uri`: a change by that
/// URI replaces it, and a removal by that URI drops it.
#[test]
fn an_object_supplied_with_a_uri_is_changed_and_removed_by_it() {
    let rule = "objects/rules/process-creation.yaml";
    let uri = "objects/objectives/known.yaml";
    let object = |name: &str| json!({ "uuid": OBJECTIVE, "schema": "objective::1.0", "name": name, "uri": uri });
    let mut session = start(json!({ "workspace": { "objects": [object("First name")] } }));
    assert!(!codes(&open(&mut session, rule, "opentide-yaml", RULE)).contains(&"invalid_ref"));
    let names = |session: &mut MessageSession, id: u64| -> Vec<String> {
        request(session, id, "opentide/catalog", json!({}))["roots"][0]["objects"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|o| o["uri"].as_str().is_some_and(|u| u.ends_with("known.yaml")))
            .map(|o| o["name"].as_str().unwrap().to_string())
            .collect()
    };
    assert_eq!(names(&mut session, 2), ["First name"]);

    send(
        &mut session,
        json!({ "method": "opentide/didChangeWorkspace", "params": { "objects": [object("Second name")] } }),
    );
    assert_eq!(
        names(&mut session, 3),
        ["Second name"],
        "replaced, not added"
    );

    let replies = send(
        &mut session,
        json!({ "method": "opentide/didChangeWorkspace", "params": { "removed": [uri] } }),
    );
    assert!(
        published_codes(&replies, rule)
            .expect("checked again")
            .contains(&"invalid_ref".to_string())
    );
    assert!(names(&mut session, 4).is_empty());
}

/// One notification that removes a URI and adds it again: the removal goes
/// first, so the file is there, with the new text.
#[test]
fn a_uri_removed_and_added_in_one_change_is_there_with_its_new_text() {
    let rule = "objects/rules/process-creation.yaml";
    let uri = "objects/objectives/moved.yaml";
    let objective = |name: &str| {
        format!("name: {name}\nmetadata:\n  uuid: {OBJECTIVE}\n  schema: objective::1.0\n")
    };
    let mut session = start(
        json!({ "workspace": { "documents": [{ "uri": uri, "text": objective("Before") }] } }),
    );
    open(&mut session, rule, "opentide-yaml", RULE);
    let replies = send(
        &mut session,
        json!({ "method": "opentide/didChangeWorkspace", "params": {
            "removed": [uri],
            "documents": [{ "uri": uri, "text": objective("After") }],
        } }),
    );
    let after = published_codes(&replies, rule).expect("checked again");
    assert!(!after.contains(&"invalid_ref".to_string()), "{after:?}");
    let line = RULE
        .lines()
        .position(|l| l.starts_with("detection_model:"))
        .unwrap();
    let hover = request(
        &mut session,
        2,
        "textDocument/hover",
        json!({ "textDocument": { "uri": rule }, "position": { "line": line, "character": 20 } }),
    );
    assert!(hover.to_string().contains("After"), "{hover}");
}
