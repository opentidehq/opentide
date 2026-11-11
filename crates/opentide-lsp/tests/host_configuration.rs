//! Configuration TOML: the server checks it with opentide-schema's models
//! (UC-2.6, #821), publishes the findings at their places, re-checks the
//! other configuration buffers when one changes, and answers hover and
//! completion from the schemas opentide-schema generates, with no host
//! supplying any (#926). The host info is process-wide, so this test has a
//! binary of its own.

#![expect(
    clippy::unwrap_used,
    reason = "test helpers outside #[test] functions: a panic fails the test"
)]

use serde_json::{Value, json};

const SHARING: &str = "file:///w/.opentide/configurations/sharing.toml";
const DEPLOYMENT: &str = "file:///w/.opentide/configurations/deployment.toml";

fn frame(body: &Value) -> Vec<u8> {
    let payload = serde_json::to_vec(body).unwrap();
    let mut out = format!("Content-Length: {}\r\n\r\n", payload.len()).into_bytes();
    out.extend(payload);
    out
}

fn frames(output: &[u8]) -> Vec<Value> {
    let text = String::from_utf8_lossy(output);
    let mut out = Vec::new();
    let mut rest: &str = &text;
    while let Some(start) = rest.find("\r\n\r\n") {
        let header = &rest[..start];
        let length: usize = header
            .trim()
            .strip_prefix("Content-Length:")
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        let body = &rest[start + 4..start + 4 + length];
        out.push(serde_json::from_str(body).unwrap());
        rest = &rest[start + 4 + length..];
    }
    out
}

fn published(messages: &[Value], uri: &str) -> Vec<Vec<(String, u64)>> {
    messages
        .iter()
        .filter(|m| m["method"] == "textDocument/publishDiagnostics" && m["params"]["uri"] == uri)
        .map(|m| {
            m["params"]["diagnostics"]
                .as_array()
                .unwrap()
                .iter()
                .map(|d| {
                    (
                        d["code"].as_str().unwrap().to_string(),
                        d["range"]["start"]["line"].as_u64().unwrap(),
                    )
                })
                .collect()
        })
        .collect()
}

#[test]
fn the_server_checks_configuration_and_answers_from_the_models_schemas() {
    let sharing = "[[misp]]\nname = \"misp-internal\"\ndistribution = \"this-community\"\nrule_statuses = [\"STAGING\"]\nmax_tlp = \"red\"\n";
    let opens = [
        json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"capabilities": {}}}),
        json!({"jsonrpc": "2.0", "method": "initialized", "params": {}}),
        json!({"jsonrpc": "2.0", "method": "textDocument/didOpen", "params": {"textDocument": {
        "uri": SHARING, "languageId": "toml", "version": 1, "text": sharing}}}),
        json!({"jsonrpc": "2.0", "method": "textDocument/didOpen", "params": {"textDocument": {
        "uri": DEPLOYMENT, "languageId": "toml", "version": 1, "text": "[[statuses]]\nname = \"PRODUCTION\"\n"}}}),
    ];
    let session = |bodies: &[Value]| {
        let mut input = Vec::new();
        for body in bodies {
            input.extend(frame(body));
        }
        input.extend(frame(
            &json!({"jsonrpc": "2.0", "id": 99, "method": "shutdown"}),
        ));
        input.extend(frame(&json!({"jsonrpc": "2.0", "method": "exit"})));
        let mut output = Vec::new();
        opentide_lsp::serve(std::io::Cursor::new(input), &mut output).unwrap();
        frames(&output)
    };

    // #172: the host says who it is; the native checks and the models'
    // schemas and catalogs are reported.
    opentide_lsp::set_host_info("opentide", "9.9.9");
    // STAGING is not a status of the open deployment.toml.
    let messages = session(&opens);
    let init = messages.iter().find(|m| m["id"] == 1).unwrap();
    let info = &init["result"]["capabilities"]["experimental"]["opentide"];
    assert_eq!(
        info["host"],
        json!({ "name": "opentide", "version": "9.9.9" })
    );
    assert_eq!(info["configurationChecks"], true);
    assert_eq!(info["configurationSchemas"], true);
    assert_eq!(info["catalog"], "models");
    assert_eq!(
        published(&messages, SHARING),
        [[
            // `url` and `api_key` are missing: on the block's header.
            ("missing_field".to_string(), 0),
            ("missing_field".to_string(), 0),
            ("unknown_key".to_string(), 2),
            ("rule_status_unknown".to_string(), 3)
        ]],
        "{messages:#?}"
    );

    // Declaring STAGING in the open deployment.toml clears sharing.toml. The
    // frames arrive as one batch: sharing.toml is published once, as it ends.
    let mut bodies = opens.to_vec();
    bodies.extend([
        json!({"jsonrpc": "2.0", "method": "textDocument/didChange", "params": {
        "textDocument": {"uri": DEPLOYMENT, "version": 2},
        "contentChanges": [{"text": "[[statuses]]\nname = \"PRODUCTION\"\n\n[[statuses]]\nname = \"STAGING\"\n"}]}}),
        json!({"jsonrpc": "2.0", "method": "textDocument/didOpen", "params": {"textDocument": {
        "uri": "file:///w/Cargo.toml", "languageId": "toml", "version": 1, "text": "[package]\nname = \"x\"\n"}}}),
        json!({"jsonrpc": "2.0", "id": 2, "method": "textDocument/completion", "params": {
        "textDocument": {"uri": SHARING}, "position": {"line": 4, "character": 10}}}),
        json!({"jsonrpc": "2.0", "id": 3, "method": "textDocument/hover", "params": {
        "textDocument": {"uri": SHARING}, "position": {"line": 4, "character": 2}}}),
        json!({"jsonrpc": "2.0", "id": 4, "method": "textDocument/semanticTokens/full", "params": {
        "textDocument": {"uri": SHARING}}}),
    ]);
    let messages = session(&bodies);
    assert_eq!(
        published(&messages, SHARING),
        [[
            ("missing_field".to_string(), 0),
            ("missing_field".to_string(), 0),
            ("unknown_key".to_string(), 2)
        ]],
        "editing deployment.toml re-checks sharing.toml"
    );
    assert!(
        published(&messages, "file:///w/Cargo.toml").is_empty(),
        "Cargo.toml is not read"
    );

    let reply = |id: i64| messages.iter().find(|m| m["id"] == id).unwrap().clone();
    let labels: Vec<String> = reply(2)["result"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["label"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(
        labels,
        [
            "\"clear\"",
            "\"green\"",
            "\"amber\"",
            "\"amber+strict\"",
            "\"red\""
        ]
    );
    let hover = reply(3)["result"]["contents"]["value"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(hover.contains("max_tlp"), "{hover}");
    assert!(hover.contains("`tlp` vocabulary"), "{hover}");
    assert_eq!(reply(4)["result"]["data"], json!([]));
}
