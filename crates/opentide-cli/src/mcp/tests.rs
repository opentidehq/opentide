//! The server over the CLI end-to-end corpus (`tests/fixtures/tide_corpus`),
//! in process: every tool and resource answers, as the recorded sessions
//! (`tests/golden/mcp/`) hold in full against the Python server.

use std::path::{Path, PathBuf};

use serde_json::{Map, Value, json};

use super::server::{Answer, Server};
use crate::env::Env;

const SENTINEL_RULE: &str = "00000000-0000-4000-8003-000000000001";
const THREAT: &str = "00000000-0000-4000-8001-000000000001";
const OBJECTIVE: &str = "00000000-0000-4000-8002-000000000001";

fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), &target).unwrap();
        }
    }
}

/// The corpus in the `.opentide/` layout, its objects in the default folders.
fn corpus(root: &Path) -> PathBuf {
    let source =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/tide_corpus/current");
    let ws = root.join("ws");
    copy_tree(
        &source.join("Configurations"),
        &ws.join(".opentide/configurations"),
    );
    for (family, folder) in [
        ("threats", "Threat Vectors"),
        ("objectives", "Detection Objectives"),
        ("rules", "Detection Rules"),
    ] {
        copy_tree(
            &source.join("Objects").join(folder),
            &ws.join("objects").join(family),
        );
    }
    ws
}

fn server(ws: &Path) -> Server {
    let shown = ws.to_string_lossy().into_owned();
    let env = Env::from_pairs([
        ("OPENTIDE_REPO_ROOT", shown.clone()),
        ("OPENTIDE_TIDE_WORKSPACE", shown),
    ]);
    Server::new(env, Some(ws.to_path_buf()), None, "1.0.0", None)
}

fn arguments(value: Value) -> Map<String, Value> {
    match value {
        Value::Object(map) => map,
        _ => Map::new(),
    }
}

/// The payload of a tool call that answered.
fn call(server: &Server, name: &str, args: Value) -> Value {
    let Answer::Result(result) = server.call(name, &arguments(args)) else {
        panic!("{name}: not a result");
    };
    assert_eq!(result["isError"], false, "{name}: {result}");
    if let Some(structured) = result.get("structuredContent") {
        return structured["result"].clone();
    }
    serde_json::from_str(result["content"][0]["text"].as_str().unwrap()).unwrap()
}

/// The document of a resource that answered.
fn read(server: &Server, uri: &str) -> Value {
    let Answer::Result(result) = server.read(uri) else {
        panic!("{uri}: not a result");
    };
    assert_eq!(result["contents"][0]["uri"], uri);
    serde_json::from_str(result["contents"][0]["text"].as_str().unwrap()).unwrap()
}

#[test]
fn every_catalogue_tool_answers_on_the_corpus() {
    let scratch = tempfile::tempdir().unwrap();
    let ws = corpus(scratch.path());
    let server = server(&ws);
    let hits = call(
        &server,
        "search",
        json!({"query": "Rule", "platform": "sentinel"}),
    );
    assert!(
        hits.as_array()
            .unwrap()
            .iter()
            .any(|hit| hit["uuid"] == SENTINEL_RULE),
        "{hits}"
    );
    let chaining = call(&server, "get_chaining", json!({"uuid": THREAT}));
    assert_eq!(chaining["graph"]["objectives"][0], OBJECTIVE);
    let coverage = call(&server, "coverage", json!({"technique": "T1059"}));
    assert_eq!(coverage["covered"], true);
    let status = call(&server, "deployment_status", json!({"uuid": SENTINEL_RULE}));
    assert_eq!(status["platforms"]["sentinel"]["deployed"], false);
    let report = call(&server, "validate_rule", json!({"uuid": SENTINEL_RULE}));
    assert_eq!(report["valid"], true, "{report}");
    assert_eq!(report["next_actions"][0]["tool"], "deploy_rule");
    let dry_run = call(
        &server,
        "deploy_rule",
        json!({"uuid": SENTINEL_RULE, "platform": "sentinel"}),
    );
    assert_eq!(dry_run["action"], "dry-run");
    assert_eq!(dry_run["status"], "STAGING");
    let unknown = call(
        &server,
        "deploy_rule",
        json!({"uuid": SENTINEL_RULE, "platform": "nowhere"}),
    );
    assert_eq!(unknown["status"], "unknown_platform");
    let live = call(
        &server,
        "deploy_rule",
        json!({"uuid": SENTINEL_RULE, "platform": "sentinel", "dry_run": false}),
    );
    assert_eq!(live["status"], "failed", "{live}");
    assert!(live["missing_tenants"]["sentinel"].is_string(), "{live}");
    let query = call(
        &server,
        "validate_query",
        json!({"query": "SecurityEvent | take 1", "platform": "sentinel"}),
    );
    assert_eq!(query["valid"], true, "{query}");
    let refused = call(
        &server,
        "run_query",
        json!({"query": "x", "platform": "splunk"}),
    );
    assert_eq!(refused["supported"], true);
    assert_eq!(refused["status"], "failed");
}

#[test]
fn every_resource_answers_on_the_corpus() {
    let scratch = tempfile::tempdir().unwrap();
    let ws = corpus(scratch.path());
    let server = server(&ws);
    let index = read(&server, "opentide://index");
    for key in [
        "paths",
        "configurations",
        "vocabs",
        "objects",
        "files",
        "file_paths",
        "indexes",
        "templates",
    ] {
        assert!(index.get(key).is_some(), "index has no {key}");
    }
    assert!(index["objects"]["rule"][SENTINEL_RULE].is_object());
    assert_eq!(
        read(&server, "opentide://rules")[SENTINEL_RULE]["name"],
        "Sentinel KQL Rule"
    );
    assert!(read(&server, "opentide://threats")[THREAT].is_object());
    assert!(read(&server, "opentide://objectives")[OBJECTIVE].is_object());
    assert_eq!(
        read(&server, &format!("opentide://rules/{SENTINEL_RULE}"))["metadata"]["uuid"],
        SENTINEL_RULE
    );
    assert!(read(&server, &format!("opentide://threats/{SENTINEL_RULE}"))["error"].is_string());
    assert!(read(&server, &format!("opentide://objectives/{OBJECTIVE}"))["name"].is_string());
    assert!(read(&server, "opentide://schemas/rule")["error"].is_string());
    assert!(read(&server, "opentide://templates/systems")["sentinel"].is_string());
    assert!(read(&server, "opentide://templates/rule::1.0")["error"].is_string());
    let vocabularies = read(&server, "opentide://vocabularies");
    assert_eq!(vocabularies["threat"]["entry_count"], 1);
    assert_eq!(
        read(&server, "opentide://vocabularies/att%26ck.groups")["metadata"]["field"],
        "att&ck.groups"
    );
    assert!(read(&server, "opentide://vocabularies/nope")["available"].is_array());
    let platforms = read(&server, "opentide://platforms");
    assert_eq!(
        platforms.as_array().unwrap().len(),
        opentide_schema::platforms::COUNT
    );
    let Answer::Error(error) = server.read("opentide://nothing") else {
        panic!("an unknown resource is an error");
    };
    assert_eq!(error["code"], -32602);
}

#[test]
fn generated_schemas_and_templates_are_served() {
    let scratch = tempfile::tempdir().unwrap();
    let ws = corpus(scratch.path());
    let schemas = ws.join(".opentide/schemas");
    let templates = ws.join(".opentide/templates");
    std::fs::create_dir_all(&schemas).unwrap();
    std::fs::create_dir_all(&templates).unwrap();
    std::fs::write(schemas.join("rule.1.0.schema.json"), r#"{"title": "one"}"#).unwrap();
    std::fs::write(
        schemas.join("rule.1.1.schema.json"),
        r#"{"title": "eleven"}"#,
    )
    .unwrap();
    std::fs::write(schemas.join("opentide.schema.json"), "{}").unwrap();
    std::fs::write(templates.join("rule.1.0.template.yaml"), "name: x\n").unwrap();
    let server = server(&ws);
    assert_eq!(read(&server, "opentide://schemas/rules")["title"], "eleven");
    assert_eq!(read(&server, "opentide://schemas/rule.1.0")["title"], "one");
    let Answer::Result(result) = server.read("opentide://templates/rule") else {
        panic!("not a result");
    };
    assert_eq!(result["contents"][0]["text"], "\"name: x\\n\"");
    let index = read(&server, "opentide://index");
    assert_eq!(index["json_schemas"]["rule::1.1"]["title"], "eleven");
    assert!(index["framework_schemas"]["rule::1.0"].is_string());
}

/// `deployment_status` reads the platform blocks from `configurations`, else
/// from the legacy `platforms`: a `configurations` that is not a table, such
/// as the string "false", holds no block and does not hide `platforms`,
/// though it is a non-empty string (a truthiness check would count it as
/// holding blocks).
#[test]
fn deployment_status_reads_platforms_past_a_configurations_that_is_not_a_table() {
    let scratch = tempfile::tempdir().unwrap();
    let ws = corpus(scratch.path());
    let path = ws.join("objects/rules/rule-0001-sentinel-kql.yaml");
    let text = std::fs::read_to_string(&path).unwrap();
    let text = text.replacen(
        "configurations:\n",
        "configurations: 'false'\nplatforms:\n",
        1,
    );
    std::fs::write(&path, text).unwrap();
    let status = call(
        &server(&ws),
        "deployment_status",
        json!({"uuid": SENTINEL_RULE}),
    );
    assert_eq!(status["found"], true, "{status}");
    assert_eq!(
        status["platforms"]["sentinel"]["deployed"], false,
        "{status}"
    );
}

/// A client that sends its next message only once every request it sent is
/// answered: reading on before that is the hang an interactive client sees
/// under WASI, where a read blocks the one thread.
struct PatientClient {
    lines: std::collections::VecDeque<Vec<u8>>,
    current: Vec<u8>,
    at: usize,
    unanswered: Vec<Value>,
    out: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
}

impl PatientClient {
    fn answered(&self, id: &Value) -> bool {
        String::from_utf8_lossy(&self.out.lock().unwrap())
            .lines()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .any(|message| message.get("method").is_none() && message.get("id") == Some(id))
    }
}

impl std::io::Read for PatientClient {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let available = std::io::BufRead::fill_buf(self)?;
        let n = available.len().min(buf.len());
        buf[..n].copy_from_slice(&available[..n]);
        std::io::BufRead::consume(self, n);
        Ok(n)
    }
}

impl std::io::BufRead for PatientClient {
    fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
        if self.at == self.current.len() {
            if let Some(waiting) = self.unanswered.iter().find(|id| !self.answered(id)) {
                return Err(std::io::Error::other(format!(
                    "the server reads on with request {waiting} unanswered"
                )));
            }
            let Some(next) = self.lines.pop_front() else {
                return Ok(&[]);
            };
            if let Ok(message) = serde_json::from_slice::<Value>(&next)
                && message.get("method").is_some()
                && let Some(id) = message.get("id")
            {
                self.unanswered.push(id.clone());
            }
            self.current = next;
            self.at = 0;
        }
        Ok(&self.current[self.at..])
    }

    fn consume(&mut self, amount: usize) {
        self.at += amount;
    }
}

/// The output the server writes, shared with the client that reads it.
struct Shared(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for Shared {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn a_blocking_client_gets_each_answer_before_its_next_read() {
    let scratch = tempfile::tempdir().unwrap();
    let ws = corpus(scratch.path());
    let out = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let messages = [
        json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "test", "version": "0"}}}),
        json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}),
        json!({"jsonrpc": "2.0", "id": "three", "method": "ping"}),
        json!({"jsonrpc": "2.0", "id": 4, "method": "no/such/method"}),
    ];
    let client = PatientClient {
        lines: messages
            .iter()
            .map(|message| format!("{message}\n").into_bytes())
            .collect(),
        current: Vec::new(),
        at: 0,
        unanswered: Vec::new(),
        out: std::sync::Arc::clone(&out),
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime
        .block_on(super::interactive::serve(
            server(&ws),
            client,
            Shared(std::sync::Arc::clone(&out)),
        ))
        .unwrap();
    let written = String::from_utf8(out.lock().unwrap().clone()).unwrap();
    let answers: Vec<Value> = written
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap()["id"].clone())
        .collect();
    assert_eq!(
        answers,
        [json!(1), json!(2), json!("three"), json!(4)],
        "{written}"
    );
}
