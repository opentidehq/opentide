//! The language server one message at a time ([`MessageSession`]), as the
//! browser build drives it: no stdio, no filesystem, and the workspace
//! supplied on `initialize`.

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

    let replies = send(
        &mut session,
        json!({ "id": 7, "method": "opentide/nothing", "params": {} }),
    );
    assert_eq!(replies[0]["id"], 7);
    assert_eq!(replies[0]["error"]["code"], -32601);

    assert_eq!(
        request(&mut session, 8, "shutdown", Value::Null),
        Value::Null
    );
    assert!(!session.is_closed());
    assert!(send(&mut session, json!({ "method": "exit" })).is_empty());
    assert!(session.is_closed());
    assert!(
        session
            .handle(r#"{"jsonrpc":"2.0","id":9,"method":"shutdown"}"#)
            .is_empty()
    );
}
