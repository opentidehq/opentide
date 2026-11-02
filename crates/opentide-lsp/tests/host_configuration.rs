//! A host that checks configuration TOML (`opentide lsp start`): the server
//! publishes the checker's findings at their places, re-checks the other
//! configuration buffers when one changes, and answers hover and completion
//! from the host's schemas. The checker is process-wide, so this test has a
//! binary of its own.

use opentide_analysis::{
    ConfigIssue, ConfigRequest, Severity, install_configuration_schemas, set_configuration_checker,
};
use serde_json::{Value, json};
use std::path::PathBuf;

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

fn install_schemas() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/config/schemas");
    let mut router = None;
    let mut schemas = Vec::new();
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        let text = std::fs::read_to_string(&path).unwrap();
        if name == "configurations.router.json" {
            router = Some(text);
        } else {
            schemas.push((name, text));
        }
    }
    install_configuration_schemas(router.as_deref(), &schemas).unwrap();
}

/// Like opentide's check: `distribution` is an unknown key, and a
/// `rule_statuses` entry must be a status the open `deployment.toml` names.
fn checker(request: &ConfigRequest<'_>) -> Result<Vec<ConfigIssue>, String> {
    let mut issues = Vec::new();
    if !request.path.ends_with("sharing.toml") {
        return Ok(issues);
    }
    if request.text.contains("distribution") {
        issues.push(ConfigIssue {
            code: "unknown_key".into(),
            field_path: vec!["misp".into(), "0".into(), "distribution".into()],
            severity: Severity::Error,
            message: "unknown key".into(),
        });
    }
    let staging_declared = request
        .open
        .iter()
        .any(|(path, text)| path.ends_with("deployment.toml") && text.contains("STAGING"));
    if request.text.contains("STAGING") && !staging_declared {
        issues.push(ConfigIssue {
            code: "rule_status_unknown".into(),
            field_path: vec!["misp".into(), "0".into(), "rule_statuses".into()],
            severity: Severity::Error,
            message: "STAGING is not a deployment status".into(),
        });
    }
    Ok(issues)
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
fn the_host_checks_configuration_and_the_server_places_it() {
    set_configuration_checker(Some(Box::new(checker)));
    install_schemas();

    let sharing = "[[misp]]\nname = \"misp-internal\"\ndistribution = \"this-community\"\nrule_statuses = [\"STAGING\"]\nmax_tlp = \"red\"\n";
    let mut input = Vec::new();
    let mut send = |body: Value| input.extend(frame(&body));
    send(
        json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"capabilities": {}}}),
    );
    send(json!({"jsonrpc": "2.0", "method": "initialized", "params": {}}));
    send(
        json!({"jsonrpc": "2.0", "method": "textDocument/didOpen", "params": {"textDocument": {
        "uri": SHARING, "languageId": "toml", "version": 1, "text": sharing}}}),
    );
    send(
        json!({"jsonrpc": "2.0", "method": "textDocument/didOpen", "params": {"textDocument": {
        "uri": DEPLOYMENT, "languageId": "toml", "version": 1, "text": "[[statuses]]\nname = \"PRODUCTION\"\n"}}}),
    );
    // Declaring STAGING in the open deployment.toml clears sharing.toml.
    send(
        json!({"jsonrpc": "2.0", "method": "textDocument/didChange", "params": {
        "textDocument": {"uri": DEPLOYMENT, "version": 2},
        "contentChanges": [{"text": "[[statuses]]\nname = \"PRODUCTION\"\n\n[[statuses]]\nname = \"STAGING\"\n"}]}}),
    );
    send(
        json!({"jsonrpc": "2.0", "method": "textDocument/didOpen", "params": {"textDocument": {
        "uri": "file:///w/Cargo.toml", "languageId": "toml", "version": 1, "text": "[package]\nname = \"x\"\n"}}}),
    );
    send(
        json!({"jsonrpc": "2.0", "id": 2, "method": "textDocument/completion", "params": {
        "textDocument": {"uri": SHARING}, "position": {"line": 4, "character": 10}}}),
    );
    send(
        json!({"jsonrpc": "2.0", "id": 3, "method": "textDocument/hover", "params": {
        "textDocument": {"uri": SHARING}, "position": {"line": 4, "character": 2}}}),
    );
    send(
        json!({"jsonrpc": "2.0", "id": 4, "method": "textDocument/semanticTokens/full", "params": {
        "textDocument": {"uri": SHARING}}}),
    );
    send(json!({"jsonrpc": "2.0", "id": 5, "method": "shutdown"}));
    send(json!({"jsonrpc": "2.0", "method": "exit"}));

    let mut output = Vec::new();
    opentide_lsp::serve(std::io::Cursor::new(input), &mut output).unwrap();
    set_configuration_checker(None);
    install_configuration_schemas(None, &[]).unwrap();
    let messages = frames(&output);

    let sharing_rounds = published(&messages, SHARING);
    assert_eq!(
        sharing_rounds[0],
        [
            ("unknown_key".to_string(), 2),
            ("rule_status_unknown".to_string(), 3)
        ],
        "{messages:#?}"
    );
    assert_eq!(
        sharing_rounds.last().unwrap(),
        &[("unknown_key".to_string(), 2)],
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
    assert!(hover.contains("Max Tlp"), "{hover}");
    assert_eq!(reply(4)["result"]["data"], json!([]));
}
