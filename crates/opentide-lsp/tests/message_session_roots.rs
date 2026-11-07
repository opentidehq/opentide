//! Several workspace folders on a host with no filesystem: each supplied file
//! is its own root's, as a file on disk would be, and each root reads its own
//! supplied `visibility.toml`.
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

fn opened(session: &mut MessageSession, uri: &str, language: &str, text: &str) -> Vec<String> {
    let replies = send(
        session,
        json!({ "jsonrpc": "2.0", "method": "textDocument/didOpen",
            "params": { "textDocument": { "uri": uri, "languageId": language, "version": 1, "text": text } } }),
    );
    let published = replies
        .iter()
        .find(|m| m["method"] == "textDocument/publishDiagnostics" && m["params"]["uri"] == uri)
        .expect("published");
    published["params"]["diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|d| d["code"].as_str().map(str::to_string))
        .collect()
}

const OBJECTIVE: &str = "00000000-0000-4000-8002-000000000001";

fn rule(uuid: &str) -> String {
    format!(
        "name: Process creation\nmetadata:\n  uuid: {uuid}\n  schema: rule::1.0\n  version: 1\n  created: 2026-01-01\n  modified: 2026-01-02\n  tlp: clear\ndescription: Process creation.\nstatus: STAGING\ndetection_model: {OBJECTIVE}\nconfigurations:\n  sentinel:\n    query: |\n      SecurityEvent\n      | where EventID == 4688\n"
    )
}

#[test]
fn each_root_has_its_own_supplied_files_and_visibility() {
    let objective =
        format!("name: In folder a\nmetadata:\n  uuid: {OBJECTIVE}\n  schema: objective::1.0\n");
    let visibility = "[[logsources]]\nname = \"Contoso_Audit_CL\"\ndescription = \"Audit\"\nsystem = \"sentinel\"\n";
    let mut session = MessageSession::new();
    let init = send(
        &mut session,
        json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "processId": null, "capabilities": {},
            "workspaceFolders": [{ "uri": "file:///a", "name": "a" }, { "uri": "file:///b", "name": "b" }],
            "initializationOptions": { "workspace": { "documents": [
                { "uri": "file:///a/objects/objectives/o.yaml", "text": objective },
                { "uri": "file:///a/.opentide/configurations/visibility.toml", "text": visibility },
            ] } },
        } }),
    );
    assert_eq!(init[0]["id"], 1);
    send(
        &mut session,
        json!({ "jsonrpc": "2.0", "method": "initialized", "params": {} }),
    );

    // A rule of folder a resolves the objective a supplied; one of folder b does not, as the CLI says.
    let in_a = opened(
        &mut session,
        "file:///a/objects/rules/r.yaml",
        "opentide-yaml",
        &rule("00000000-0000-4000-8003-00000000000a"),
    );
    assert!(!in_a.contains(&"invalid_ref".to_string()), "{in_a:?}");
    let in_b = opened(
        &mut session,
        "file:///b/objects/rules/r.yaml",
        "opentide-yaml",
        &rule("00000000-0000-4000-8003-00000000000b"),
    );
    assert!(in_b.contains(&"invalid_ref".to_string()), "{in_b:?}");

    // Folder a declares the table in its own visibility.toml; folder b declares none.
    let query = "Contoso_Audit_CL\n| take 1\n";
    let declared = opened(&mut session, "file:///a/queries/q.kql", "kql", query);
    assert!(
        !declared.contains(&"kql_unknown_table".to_string()),
        "{declared:?}"
    );
    let undeclared = opened(&mut session, "file:///b/queries/q.kql", "kql", query);
    assert!(
        undeclared.contains(&"kql_unknown_table".to_string()),
        "{undeclared:?}"
    );

    // Each object is listed under its own root, and visibility.toml is no object.
    let catalog = send(
        &mut session,
        json!({ "jsonrpc": "2.0", "id": 2, "method": "opentide/catalog", "params": {} }),
    );
    let roots = catalog[0]["result"]["roots"].as_array().unwrap();
    let uris = |root: &str| -> Vec<String> {
        roots.iter().find(|r| r["root"] == root).unwrap()["objects"]
            .as_array()
            .unwrap()
            .iter()
            .map(|o| o["uri"].as_str().unwrap().to_string())
            .collect()
    };
    assert_eq!(
        uris("file:///a"),
        [
            "file:///a/objects/objectives/o.yaml",
            "file:///a/objects/rules/r.yaml"
        ]
    );
    assert_eq!(uris("file:///b"), ["file:///b/objects/rules/r.yaml"]);
}
