//! `visibility.toml` changed by a host with no filesystem
//! (`opentide/didChangeWorkspace`).
//!
//! Declared datasets are process-wide, so this is its own test binary: no
//! other test runs beside it.

use opentide_lsp::MessageSession;
use serde_json::{Value, json};

fn send(session: &mut MessageSession, message: Value) -> Vec<Value> {
    session
        .handle(&message.to_string())
        .iter()
        .map(|text| serde_json::from_str(text).unwrap())
        .collect()
}

fn codes(replies: &[Value]) -> Vec<String> {
    let published = replies
        .iter()
        .find(|m| m["method"] == "textDocument/publishDiagnostics")
        .expect("the query is checked again");
    published["params"]["diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|d| d["code"].as_str().map(str::to_string))
        .collect()
}

#[test]
fn a_changed_visibility_toml_declares_its_tables_and_a_removed_one_none() {
    let mut session = MessageSession::new();
    let initialize = json!({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": { "processId": null, "rootUri": null, "capabilities": {},
            "initializationOptions": { "workspace": {} } },
    });
    assert_eq!(session.handle(&initialize.to_string()).len(), 1);
    let open = json!({
        "jsonrpc": "2.0", "method": "textDocument/didOpen",
        "params": { "textDocument": { "uri": "untitled:q.kql", "languageId": "kql", "version": 1,
            "text": "Contoso_Audit_CL\n| take 1\n" } },
    });
    assert!(codes(&send(&mut session, open)).contains(&"kql_unknown_table".to_string()));

    let visibility = "[[logsources]]\nname = \"Contoso_Audit_CL\"\ndescription = \"Audit\"\nsystem = \"sentinel\"\n";
    let declared = codes(&send(
        &mut session,
        json!({ "jsonrpc": "2.0", "method": "opentide/didChangeWorkspace",
            "params": { "visibility": visibility } }),
    ));
    assert!(
        !declared.contains(&"kql_unknown_table".to_string()),
        "{declared:?}"
    );

    let removed = codes(&send(
        &mut session,
        json!({ "jsonrpc": "2.0", "method": "opentide/didChangeWorkspace",
            "params": { "visibility": null } }),
    ));
    assert!(
        removed.contains(&"kql_unknown_table".to_string()),
        "{removed:?}"
    );
}
