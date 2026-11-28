//! A host that supplies the Tide field catalogs keeps them: the server does
//! not install the ones it generates from the models (#926). The catalogs
//! and the flag are process-wide, so this test has a binary of its own, and
//! drives the server in this process ([`MessageSession`]).

#![expect(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers outside #[test] functions: a panic fails the test"
)]

use opentide_analysis::{Catalog, set_default_catalog};
use opentide_lsp::{MessageSession, use_host_catalogs};
use serde_json::{Value, json};
use std::sync::Once;

/// The host's catalog: a TLP the models do not know, and a value two fields
/// share, documented differently for each.
const FIELDS: &str = r#"{"opentide": "host", "fields": [
    {"schema": "rule", "path": "metadata", "name": "metadata", "type": "object"},
    {"schema": "rule", "path": "metadata.tlp", "name": "tlp", "type": "string",
     "enum": ["clear", "house"], "enum_docs": ["TLP clear: anyone.", "TLP house: us."]},
    {"schema": "rule", "path": "metadata.status", "name": "status", "type": "string",
     "enum": ["clear"], "enum_docs": ["Status clear: no finding."]}]}"#;

fn supply_the_host_catalogs() {
    static SUPPLIED: Once = Once::new();
    SUPPLIED.call_once(|| {
        set_default_catalog(&Catalog {
            fields: Some(FIELDS.to_owned()),
            deprecations: None,
            visibility: None,
        })
        .expect("the host's catalog installs");
        use_host_catalogs();
    });
}

fn send(session: &mut MessageSession, mut message: Value) -> Vec<Value> {
    message["jsonrpc"] = json!("2.0");
    session
        .handle(&message.to_string())
        .iter()
        .map(|text| serde_json::from_str(text).unwrap())
        .collect()
}

fn request(session: &mut MessageSession, id: u64, method: &str, params: Value) -> Value {
    send(
        session,
        json!({ "id": id, "method": method, "params": params }),
    )
    .into_iter()
    .find(|m| m["id"] == id)
    .expect("an answer")
}

/// A session with `text` open as a rule outside every workspace.
fn session_with(uri: &str, text: &str) -> MessageSession {
    let mut session = MessageSession::new();
    let init = request(
        &mut session,
        1,
        "initialize",
        json!({ "processId": null, "rootUri": null, "capabilities": {} }),
    );
    assert_eq!(
        init["result"]["capabilities"]["experimental"]["opentide"]["catalog"], "host",
        "{init}"
    );
    send(
        &mut session,
        json!({ "method": "initialized", "params": {} }),
    );
    send(
        &mut session,
        json!({ "method": "textDocument/didOpen", "params": { "textDocument": {
            "uri": uri, "languageId": "opentide-yaml", "version": 1, "text": text } } }),
    );
    session
}

fn completion(session: &mut MessageSession, uri: &str, line: u32, character: u32) -> Vec<Value> {
    let reply = request(
        session,
        2,
        "textDocument/completion",
        json!({ "textDocument": { "uri": uri }, "position": { "line": line, "character": character } }),
    );
    reply["result"]
        .as_array()
        .cloned()
        .or_else(|| reply["result"]["items"].as_array().cloned())
        .unwrap_or_default()
}

#[test]
fn a_host_that_supplies_the_catalogs_keeps_them() {
    supply_the_host_catalogs();
    let uri = "file:///opentide-host-catalogs/objects/rules/house-rule.yaml";
    let text = "name: House Rule\nmetadata:\n  uuid: 00000000-0000-4000-8003-000000000001\n  schema: rule::1.0\n  tlp: \n";
    let mut session = session_with(uri, text);
    let labels: Vec<String> = completion(&mut session, uri, 4, 7)
        .iter()
        .filter_map(|item| item["label"].as_str().map(str::to_owned))
        .collect();
    assert!(labels.contains(&"house".to_owned()), "{labels:?}");
    assert!(!labels.contains(&"amber+strict".to_owned()), "{labels:?}");
}

/// P0.9: a value two fields share is documented from the field it was
/// completed for, through the item's `data`.
#[test]
fn resolve_documents_a_value_from_its_own_field() {
    supply_the_host_catalogs();
    let uri = "file:///opentide-host-catalogs/objects/rules/r.yaml";
    let text = "name: R\nmetadata:\n  schema: rule::1.0\n  status: \n";
    let mut session = session_with(uri, text);
    let mut item = completion(&mut session, uri, 3, 10)
        .into_iter()
        .find(|i| i["label"] == "clear")
        .expect("`clear` is offered");
    assert_eq!(item["data"]["field_path"], "metadata.status", "{item}");
    // A client that resolves documentation lazily sends the item without it.
    item.as_object_mut().unwrap().remove("documentation");
    let resolved = request(&mut session, 3, "completionItem/resolve", item);
    let docs = resolved["result"]["documentation"]["value"]
        .as_str()
        .unwrap();
    assert!(docs.contains("Status clear"), "{resolved}");
}
