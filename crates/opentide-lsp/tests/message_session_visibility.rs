//! `visibility.toml` supplied on `initialize` by a host with no filesystem.
//!
//! Declared datasets are process-wide, so this is its own test binary: no
//! other test runs beside it.

use opentide_lsp::MessageSession;
use serde_json::{Value, json};

fn diagnostics_for(options: Value, text: &str) -> Vec<String> {
    let mut session = MessageSession::new();
    let initialize = json!({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": { "processId": null, "rootUri": null, "capabilities": {}, "initializationOptions": options },
    });
    assert_eq!(session.handle(&initialize.to_string()).len(), 1);
    let open = json!({
        "jsonrpc": "2.0", "method": "textDocument/didOpen",
        "params": { "textDocument": { "uri": "untitled:q.kql", "languageId": "kql", "version": 1, "text": text } },
    });
    let replies = session.handle(&open.to_string());
    let published: Value = serde_json::from_str(&replies[0]).unwrap();
    published["params"]["diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|d| d["code"].as_str().map(str::to_string))
        .collect()
}

#[test]
fn a_supplied_visibility_toml_declares_its_tables() {
    let query = "Contoso_Audit_CL\n| take 1\n";
    assert!(diagnostics_for(Value::Null, query).contains(&"kql_unknown_table".to_string()));

    // A log source's name is its dataset (visibility::1.0).
    let visibility = r#"
[[logsources]]
name = "Contoso_Audit_CL"
description = "Administrative audit events"
system = "sentinel"
"#;
    let declared = diagnostics_for(json!({ "workspace": { "visibility": visibility } }), query);
    assert!(
        !declared.contains(&"kql_unknown_table".to_string()),
        "{declared:?}"
    );
}
