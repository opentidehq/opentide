//! The server over the CLI end-to-end corpus (`tests/fixtures/tide_corpus`),
//! in process: every tool and resource answers (the Python server's recorded
//! sessions, which the server was replayed against, were retired in #1142).

use std::path::{Path, PathBuf};

use serde_json::{Map, Value, json};

use super::server::{Answer, Server};
use crate::env::Env;

const SENTINEL_RULE: &str = "00000000-0000-4000-8003-000000000001";
const THREAT: &str = "00000000-0000-4000-8001-000000000001";
const OBJECTIVE: &str = "00000000-0000-4000-8002-000000000001";
const SIGNAL: &str = "00000000-0000-4000-8099-000000000001";

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

/// The payload of a tool call that failed: the same JSON as an answer, with
/// `isError` true (MCP's tool-level error).
fn failed_call(server: &Server, name: &str, args: Value) -> Value {
    let Answer::Result(result) = server.call(name, &arguments(args)) else {
        panic!("{name}: not a result");
    };
    assert_eq!(result["isError"], true, "{name}: {result}");
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
    // A signal's UUID names its objective, and the answer holds only the
    // returned graph's part of the chaining index.
    let signal = call(&server, "get_chaining", json!({"uuid": SIGNAL}));
    assert_eq!(signal["uuid"], OBJECTIVE, "{signal}");
    assert_eq!(signal["type"], "objective");
    assert_eq!(signal["resolved_from"]["uuid"], SIGNAL);
    assert!(
        !signal["graph"]["rules"].as_array().unwrap().is_empty(),
        "{signal}"
    );
    let index = signal["chaining_index"].as_object().unwrap();
    let members = signal["graph"]
        .as_object()
        .unwrap()
        .values()
        .flat_map(|ids| ids.as_array().unwrap())
        .map(|id| id.as_str().unwrap().to_owned())
        .collect::<Vec<_>>();
    assert!(
        index.keys().all(|key| members.contains(key)),
        "{index:?} vs {members:?}"
    );
    let coverage = call(&server, "coverage", json!({"technique": "T1059"}));
    assert_eq!(coverage["covered"], true);
    let status = call(&server, "deployment_status", json!({"uuid": SENTINEL_RULE}));
    assert_eq!(status["platforms"]["sentinel"]["deployed"], false);
    // Sentinel addresses its rules without a vendor id: no state is kept, and
    // the answer says why `deployed` cannot say more.
    let note = status["platforms"]["sentinel"]["note"].as_str().unwrap();
    assert!(
        note.contains("records no deployment state for sentinel"),
        "{note}"
    );
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
    // The preview carries the deploy command's plan, and the platform may be
    // left out: the rule has one block.
    assert_eq!(dry_run["plan"]["sentinel"][0], SENTINEL_RULE, "{dry_run}");
    assert_eq!(dry_run["changes"][0]["uuid"], SENTINEL_RULE, "{dry_run}");
    assert!(dry_run["payloads"]["sentinel"][0]["api_request"].is_object());
    assert_eq!(dry_run["would_deploy"], true, "{dry_run}");
    let implied = call(&server, "deploy_rule", json!({"uuid": SENTINEL_RULE}));
    assert_eq!(implied["platform"], "sentinel", "{implied}");
    assert_eq!(implied["plan"], dry_run["plan"], "{implied}");
    let unknown = failed_call(
        &server,
        "deploy_rule",
        json!({"uuid": SENTINEL_RULE, "platform": "nowhere"}),
    );
    assert_eq!(unknown["status"], "unknown_platform");
    let live = failed_call(
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
    let refused = failed_call(
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
    assert_eq!(result["contents"][0]["text"], "name: x\n");
    assert_eq!(result["contents"][0]["mimeType"], "application/yaml");
    let Answer::Result(systems) = server.read("opentide://templates/systems") else {
        panic!("not a result");
    };
    assert_eq!(systems["contents"][0]["mimeType"], "application/json");
    let Answer::Result(index) = server.read("opentide://index") else {
        panic!("not a result");
    };
    assert_eq!(index["contents"][0]["mimeType"], "application/json");
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

/// `opentide://templates/rule` is the newest revision's template, the one
/// `opentide new rule` starts from, and each revision `generate` wrote is
/// served by its id (smoke C3); the configured file stays the fallback.
#[test]
fn the_rule_template_is_the_newest_revision_and_each_revision_is_served() {
    let scratch = tempfile::tempdir().unwrap();
    let ws = corpus(scratch.path());
    let templates = ws.join(".opentide/templates");
    std::fs::create_dir_all(&templates).unwrap();
    std::fs::write(
        templates.join("rule.1.0.template.yaml"),
        "schema: rule::1.0\n",
    )
    .unwrap();
    std::fs::write(
        templates.join("rule.1.1.template.yaml"),
        "schema: rule::1.1\n",
    )
    .unwrap();
    let server = server(&ws);
    let text = |uri: &str| {
        let Answer::Result(result) = server.read(uri) else {
            panic!("{uri}: not a result");
        };
        result["contents"][0]["text"].as_str().unwrap().to_owned()
    };
    for uri in [
        "opentide://templates/rule",
        "opentide://templates/rules",
        "opentide://templates/rule::1.1",
        "opentide://templates/rule.1.1",
    ] {
        assert_eq!(text(uri), "schema: rule::1.1\n", "{uri}");
    }
    assert_eq!(
        text("opentide://templates/rule::1.0"),
        "schema: rule::1.0\n"
    );
    let unknown = read(&server, "opentide://templates/rule::9.9");
    assert!(unknown["error"].is_string(), "{unknown}");
    assert_eq!(
        read(&server, "opentide://index")["templates"]["rule"],
        "schema: rule::1.1\n"
    );
}

/// An unknown `stack` or search `type` is refused, naming what is known,
/// rather than read as no filter at all (smoke C9).
#[test]
fn an_unknown_stack_or_object_type_is_refused() {
    let scratch = tempfile::tempdir().unwrap();
    let ws = corpus(scratch.path());
    let server = server(&ws);
    let check = |stack: &str| {
        call(
            &server,
            "validate_query",
            json!({"query": "FROM logs-* | LIMIT 10", "platform": "elastic",
                   "language": "esql", "stack": stack}),
        )
    };
    // Refused, so nothing was checked: a tool error with the same payload.
    let refused = failed_call(
        &server,
        "validate_query",
        json!({"query": "FROM logs-* | LIMIT 10", "platform": "elastic",
               "language": "esql", "stack": "bogus"}),
    );
    assert_eq!(refused["status"], "failed", "{refused}");
    assert_eq!(refused["valid"], Value::Null, "{refused}");
    assert!(
        refused["message"]
            .as_str()
            .unwrap()
            .contains("not \"bogus\""),
        "{refused}"
    );
    for known in ["9.5", "8.19", "Serverless", ""] {
        assert_eq!(check(known)["valid"], true, "{known}");
    }
    let Answer::Result(result) =
        server.call("search", &arguments(json!({"query": "", "type": "bogus"})))
    else {
        panic!("not a result");
    };
    assert_eq!(result["isError"], true, "{result}");
    assert_eq!(
        result["content"][0]["text"],
        "Error executing tool search: argument type must be one of rule, threat, objective, \
         not \"bogus\""
    );
}

/// A live `validate_query` answers the command's document: `status` says it
/// failed, and no `_exit_code` is added (smoke C7).
#[test]
fn a_failed_live_query_check_carries_no_exit_code() {
    let scratch = tempfile::tempdir().unwrap();
    let ws = corpus(scratch.path());
    let live = failed_call(
        &server(&ws),
        "validate_query",
        json!({"query": "index=main", "platform": "splunk", "live": true}),
    );
    assert_eq!(live["status"], "failed", "{live}");
    assert!(live.get("_exit_code").is_none(), "{live}");
}

/// A real `deploy_rule` that fails says why, as `opentide --json deploy`
/// does in its `error`, not only the run's tally (smoke C2). The tenant's
/// secret names an environment variable that is unset, so nothing is sent:
/// the failure is the tenant's, before any rule (#1701).
#[test]
fn a_failed_deploy_names_its_cause() {
    let scratch = tempfile::tempdir().unwrap();
    let ws = corpus(scratch.path());
    let config = ws.join(".opentide/configurations/platforms/sentinel.toml");
    let mut text = std::fs::read_to_string(&config).unwrap();
    text.push_str(
        "\n[[tenants]]\nname = \"lab\"\n[tenants.setup]\nresource_group = \"rg\"\n\
         workspace_name = \"soc\"\nworkspace_id = \"11111111-2222-4333-8444-555555555555\"\n\
         azure_tenant_id = \"t\"\nazure_subscription_id = \"s\"\nazure_client_id = \"c\"\n\
         azure_client_secret = \"$OPENTIDE_TEST_UNSET_SECRET\"\n",
    );
    std::fs::write(&config, text).unwrap();
    let failed = failed_call(
        &server(&ws),
        "deploy_rule",
        json!({"uuid": SENTINEL_RULE, "platform": "sentinel", "dry_run": false}),
    );
    assert_eq!(failed["status"], "failed", "{failed}");
    assert_eq!(failed["error"], "deployment_failed", "{failed}");
    let message = failed["message"].as_str().unwrap();
    assert!(
        message.starts_with("sentinel tenant 'lab' setup: ")
            && message.contains("OPENTIDE_TEST_UNSET_SECRET"),
        "{message}"
    );
}

/// The dry run of a rule with no block for the platform says what the real
/// call says, not `dry-run` (smoke C16).
#[test]
fn a_dry_run_without_the_platforms_block_is_refused_as_the_deploy_is() {
    let scratch = tempfile::tempdir().unwrap();
    let ws = corpus(scratch.path());
    let server = server(&ws);
    let preview = failed_call(
        &server,
        "deploy_rule",
        json!({"uuid": SENTINEL_RULE, "platform": "splunk"}),
    );
    assert_eq!(preview["action"], "error", "{preview}");
    assert_eq!(preview["dry_run"], true, "{preview}");
    assert_eq!(
        preview["message"], "Rule \"Sentinel KQL Rule\" has no splunk status to deploy",
        "{preview}"
    );
}

/// A status the deployment configuration does not define is refused by the
/// dry run as by the real call, not previewed as `dry-run` (smoke C16).
#[test]
fn a_dry_run_of_a_status_that_is_not_defined_is_refused() {
    let scratch = tempfile::tempdir().unwrap();
    let ws = corpus(scratch.path());
    let path = ws.join("objects/rules/rule-0001-sentinel-kql.yaml");
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(text.contains("status: STAGING"), "{text}");
    std::fs::write(&path, text.replace("status: STAGING", "status: NOWHERE")).unwrap();
    let Answer::Result(result) = server(&ws).call(
        "deploy_rule",
        &arguments(json!({"uuid": SENTINEL_RULE, "platform": "sentinel"})),
    ) else {
        panic!("not a result");
    };
    assert_eq!(result["isError"], true, "{result}");
    let text = result["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("NOWHERE"), "{text}");
}

/// `validation_report` with an `object_type` that is no family is refused,
/// as `validate --type` refuses it, not answered with an empty report.
#[test]
fn a_validation_report_of_an_unknown_object_type_is_refused() {
    let scratch = tempfile::tempdir().unwrap();
    let ws = corpus(scratch.path());
    let Answer::Result(result) = server(&ws).call(
        "validation_report",
        &arguments(json!({"object_type": "bogus"})),
    ) else {
        panic!("not a result");
    };
    assert_eq!(result["isError"], true, "{result}");
    let text = result["content"][0]["text"].as_str().unwrap();
    assert!(
        text.contains("usage_invalid_choice: Unknown object type(s): bogus."),
        "{text}"
    );
}

/// A client that sends its next message only once the answer it waits for
/// has been written: reading on before that is the hang an interactive
/// client sees under WASI, where a read blocks the one thread.
struct PatientClient {
    /// Each message, and the id of the answer the client waits for before
    /// its next one (`null` for a refusal without an id).
    lines: std::collections::VecDeque<(Vec<u8>, Option<Value>)>,
    current: Vec<u8>,
    at: usize,
    waiting: Vec<Value>,
    out: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
}

impl PatientClient {
    /// How many answers with *id* are written.
    fn answers(&self, id: &Value) -> usize {
        String::from_utf8_lossy(&self.out.lock().unwrap())
            .lines()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            // A refusal leaves the id out: it answers `null`.
            .filter(|message| {
                message.get("method").is_none() && message.get("id").unwrap_or(&Value::Null) == id
            })
            .count()
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
        // Before the next message (not before closing: the last one, sent
        // without its newline, is framed only at end of input).
        if self.at == self.current.len() && !self.lines.is_empty() {
            for id in &self.waiting {
                let expected = self.waiting.iter().filter(|other| *other == id).count();
                if self.answers(id) < expected {
                    return Err(std::io::Error::other(format!(
                        "the server reads on before answering {id}"
                    )));
                }
            }
            if let Some((next, answer)) = self.lines.pop_front() {
                self.waiting.extend(answer);
                self.current = next;
                self.at = 0;
            }
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
    let line = |message: Value| format!("{message}\n").into_bytes();
    let lines: Vec<(Vec<u8>, Option<Value>)> = vec![
        (
            line(
                json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
                "protocolVersion": "2025-06-18", "capabilities": {},
                "clientInfo": {"name": "test", "version": "0"}}}),
            ),
            Some(json!(1)),
        ),
        (
            line(json!({"jsonrpc": "2.0", "method": "notifications/initialized"})),
            None,
        ),
        (
            line(json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})),
            Some(json!(2)),
        ),
        (
            line(json!({"jsonrpc": "2.0", "id": "three", "method": "ping"})),
            Some(json!("three")),
        ),
        // An error answer, by its id.
        (
            line(json!({"jsonrpc": "2.0", "id": 4, "method": "no/such/method"})),
            Some(json!(4)),
        ),
        // An integer in float form: answered as `5`.
        (
            b"{\"jsonrpc\":\"2.0\",\"id\":5.0,\"method\":\"ping\"}\n".to_vec(),
            Some(json!(5)),
        ),
        // Requests rmcp cannot read as one: refused without an id.
        (
            b"{\"jsonrpc\":\"2.0\",\"id\":99999999999999999999,\"method\":\"ping\"}\n".to_vec(),
            Some(Value::Null),
        ),
        (
            line(json!({"jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": 5})),
            Some(Value::Null),
        ),
        // A byte-order mark, which the transport skips.
        (
            [
                b"\xEF\xBB\xBF".as_slice(),
                &line(json!({"jsonrpc": "2.0", "id": 7, "method": "ping"})),
            ]
            .concat(),
            Some(json!(7)),
        ),
        // An id on a notification's method: rmcp answers it when it reads it,
        // and drops it when it cannot, so the client does not wait for it.
        (
            line(json!({"jsonrpc": "2.0", "id": 8, "method": "notifications/nothing"})),
            None,
        ),
        // The last message, without its newline.
        (
            format!("{}", json!({"jsonrpc": "2.0", "id": 9, "method": "ping"})).into_bytes(),
            Some(json!(9)),
        ),
    ];
    let client = PatientClient {
        lines: lines.into_iter().collect(),
        current: Vec::new(),
        at: 0,
        waiting: Vec::new(),
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
        .map(|line| {
            let message = serde_json::from_str::<Value>(line).unwrap();
            message.get("id").cloned().unwrap_or_default()
        })
        .collect();
    assert_eq!(
        answers,
        [
            json!(1),
            json!(2),
            json!("three"),
            json!(4),
            json!(5),
            Value::Null,
            Value::Null,
            json!(7),
            json!(8),
            json!(9)
        ],
        "{written}"
    );
}

/// Held by the tests that reach a tenant: the transport a bridge installs is the
/// process's, so under `cargo test` (one process, many threads) another test's
/// network call must not run while it is installed.
static NETWORK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Network tool calls, each on a `spawn_blocking` thread of the process's
/// runtime as the server dispatches them, block on that runtime: they reach
/// the tenant (refused here: nothing listens) and no call starts a runtime
/// of its own (#1558).
#[cfg(not(target_os = "wasi"))]
#[test]
fn network_tool_calls_run_on_the_one_runtime() {
    let _network = NETWORK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let closed = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        format!("http://{}", listener.local_addr().unwrap())
    };
    let scratch = tempfile::tempdir().unwrap();
    let ws = corpus(scratch.path());
    let platforms = ws.join(".opentide/configurations/platforms");
    std::fs::create_dir_all(&platforms).unwrap();
    std::fs::write(
        platforms.join("elastic.toml"),
        format!(
            "[platform]\nenabled = true\nname = \"Elastic Security\"\n\n\
             [[tenants]]\nname = \"closed\"\nstrategies = [\"PREVIEW\"]\n[tenants.setup]\n\
             url = \"{closed}\"\nelasticsearch_url = \"{closed}\"\napi_key = \"key\"\n"
        ),
    )
    .unwrap();
    let server = std::sync::Arc::new(server(&ws));
    let answers = opentide_connectors::runtime::block_on(async {
        let mut answers = Vec::new();
        for _ in 0..3 {
            let server = std::sync::Arc::clone(&server);
            let answer = tokio::task::spawn_blocking(move || {
                // A tool's thread is one of the process's runtime's.
                assert_eq!(
                    tokio::runtime::Handle::current().id(),
                    opentide_connectors::runtime::shared()
                        .unwrap()
                        .handle()
                        .id()
                );
                let args = json!({"query": "FROM x", "platform": "elastic", "live": true});
                match server.call("run_query", &arguments(args)) {
                    Answer::Result(result) => result.to_string(),
                    Answer::Error(error) => format!("{error:?}"),
                }
            })
            .await
            .unwrap();
            answers.push(answer);
        }
        answers
    })
    .unwrap();
    for answer in &answers {
        assert!(answer.contains("closed"), "the tenant was tried: {answer}");
        for refused in [
            opentide_connectors::runtime::INSIDE_THE_RUNTIME,
            "stopped unexpectedly",
        ] {
            assert!(!answer.contains(refused), "{answer}");
        }
    }
    assert_eq!(opentide_connectors::runtime::started(), 1);
}

/// A call still running when the client leaves is interrupted, and the
/// server returns once it has stopped: the process's runtime is never
/// dropped, so nothing else would stop it before the process exits (#1558).
#[cfg(not(target_os = "wasi"))]
#[test]
fn the_session_ending_stops_the_running_call_and_waits_for_it() {
    let _network = NETWORK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    use std::io::Read;
    use tokio::io::AsyncWriteExt;

    // A stand-in Elasticsearch that never answers; it reports the request,
    // then the connection closing.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = format!("http://{}", listener.local_addr().unwrap());
    let (seen, events) = std::sync::mpsc::channel::<&str>();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let seen = seen.clone();
            std::thread::spawn(move || {
                let mut chunk = [0_u8; 1024];
                if stream.read(&mut chunk).unwrap_or(0) > 0 {
                    let _ = seen.send("request");
                }
                while stream.read(&mut chunk).unwrap_or(0) > 0 {}
                let _ = seen.send("closed");
            });
        }
    });
    let scratch = tempfile::tempdir().unwrap();
    let ws = corpus(scratch.path());
    let platforms = ws.join(".opentide/configurations/platforms");
    std::fs::create_dir_all(&platforms).unwrap();
    std::fs::write(
        platforms.join("elastic.toml"),
        format!(
            "[platform]\nenabled = true\nname = \"Elastic Security\"\n\n\
             [[tenants]]\nname = \"stalls\"\nstrategies = [\"PREVIEW\"]\n[tenants.setup]\n\
             url = \"{address}\"\nelasticsearch_url = \"{address}\"\napi_key = \"key\"\n"
        ),
    )
    .unwrap();
    let server = server(&ws);
    let turn = server.turn();
    let (mut client, input) = tokio::io::duplex(1 << 16);
    let patience = std::time::Duration::from_secs(60);
    let finished = opentide_connectors::runtime::block_on(async move {
        let serving = tokio::spawn(server.run(input, tokio::io::sink()));
        for message in [
            json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "test", "version": "0"},
            }}),
            json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
            json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
                "name": "run_query",
                "arguments": {"query": "FROM x", "platform": "elastic", "live": true},
            }}),
        ] {
            client
                .write_all(format!("{message}\n").as_bytes())
                .await
                .unwrap();
        }
        let reached = tokio::task::spawn_blocking(move || {
            let reached = events.recv_timeout(patience);
            (reached, events)
        })
        .await
        .unwrap();
        assert_eq!(reached.0, Ok("request"), "the call reached the tenant");
        // The client leaves while the call runs.
        drop(client);
        tokio::time::timeout(patience, serving)
            .await
            .expect("the server returned")
            .unwrap()
            .unwrap();
        // The server returned once the call had stopped: the call's work has
        // returned and given its turn back (else the process would exit with
        // it mid-work).
        assert!(
            turn.try_lock().is_ok(),
            "the server returned while the call was still running"
        );
        reached.1
    })
    .unwrap();
    // The call was interrupted: its request to the tenant is dropped, which
    // the stand-in sees once the closed socket reaches it. Without the
    // interrupt the request stays open past the bound (the query's own
    // timeout is 120 s).
    assert_eq!(finished.recv_timeout(patience), Ok("closed"));
}

/// A client that answers the server's `opentide/fetch` requests over the same
/// two streams (`OPENTIDE_FETCH=stdio`): it sends its opening messages one
/// at a time, then, for each tenant request the server has written and not
/// yet had answered, first some MCP messages of its own and then the answer.
struct FetchingClient {
    out: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
    opening: std::collections::VecDeque<Vec<u8>>,
    /// Sent while the first request waits, before its answer.
    meanwhile: std::collections::VecDeque<Vec<u8>>,
    answered: usize,
    /// How each request is answered: a result or an error, by its params.
    answer: Box<dyn Fn(&Value) -> Value + Send>,
    /// Ends the input instead of answering the request with this number.
    hang_up_at: Option<usize>,
    current: Vec<u8>,
    at: usize,
    /// The requests seen, in the order they were written.
    requests: std::sync::Arc<std::sync::Mutex<Vec<Value>>>,
}

impl FetchingClient {
    fn new(out: &std::sync::Arc<std::sync::Mutex<Vec<u8>>>) -> Self {
        FetchingClient {
            out: std::sync::Arc::clone(out),
            opening: std::collections::VecDeque::new(),
            meanwhile: std::collections::VecDeque::new(),
            answered: 0,
            answer: Box::new(|_| json!({"status": 200, "headers": [], "body": null})),
            hang_up_at: None,
            current: Vec::new(),
            at: 0,
            requests: std::sync::Arc::default(),
        }
    }

    fn requests_written(&self) -> Vec<Value> {
        String::from_utf8_lossy(&self.out.lock().unwrap())
            .lines()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .filter(|message| message["method"] == "opentide/fetch")
            .collect()
    }
}

impl std::io::Read for FetchingClient {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let available = std::io::BufRead::fill_buf(self)?;
        let n = available.len().min(buf.len());
        buf[..n].copy_from_slice(&available[..n]);
        std::io::BufRead::consume(self, n);
        Ok(n)
    }
}

impl std::io::BufRead for FetchingClient {
    fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
        if self.at == self.current.len() {
            self.at = 0;
            self.current.clear();
            if let Some(next) = self.opening.pop_front() {
                self.current = next;
            } else {
                let written = self.requests_written();
                if let Some(request) = written.get(self.answered) {
                    if let Some(next) = self.meanwhile.pop_front() {
                        self.current = next;
                    } else if self.hang_up_at == Some(self.answered + 1) {
                        return Ok(&[]);
                    } else {
                        let result = (self.answer)(request);
                        let message =
                            json!({"jsonrpc": "2.0", "id": request["id"], "result": result});
                        self.requests.lock().unwrap().push(request.clone());
                        self.answered += 1;
                        self.current = format!("{message}\n").into_bytes();
                    }
                }
            }
        }
        Ok(&self.current[self.at..])
    }

    fn consume(&mut self, amount: usize) {
        self.at += amount;
    }
}

/// An ES|QL answer's body, base64: one column, one row.
fn esql_body(host: &str) -> String {
    use base64::Engine as _;
    let body = json!({"columns": [{"name": "host", "type": "keyword"}], "values": [[host]]});
    base64::engine::general_purpose::STANDARD.encode(body.to_string())
}

fn elastic_workspace(root: &Path) -> PathBuf {
    let ws = corpus(root);
    let platforms = ws.join(".opentide/configurations/platforms");
    std::fs::create_dir_all(&platforms).unwrap();
    std::fs::write(
        platforms.join("elastic.toml"),
        "[platform]\nenabled = true\nname = \"Elastic Security\"\n\n\
         [[tenants]]\nname = \"lab\"\nstrategies = [\"PREVIEW\"]\n[tenants.setup]\n\
         url = \"https://lab.invalid\"\nelasticsearch_url = \"https://lab.invalid\"\n\
         api_key = \"key\"\n",
    )
    .unwrap();
    ws
}

fn mcp_line(message: &Value) -> Vec<u8> {
    format!("{message}\n").into_bytes()
}

fn opening(call_id: u64) -> Vec<Vec<u8>> {
    vec![
        mcp_line(
            &json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "test", "version": "0"}}}),
        ),
        mcp_line(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"})),
        mcp_line(
            &json!({"jsonrpc": "2.0", "id": call_id, "method": "tools/call", "params": {
            "name": "run_query",
            "arguments": {"query": "FROM x", "platform": "elastic", "live": true}}}),
        ),
    ]
}

/// Serves *client*'s session with the bridge installed; what the server wrote.
fn serve_bridged(
    ws: &Path,
    client: FetchingClient,
    out: &std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
) -> Vec<Value> {
    let _network = NETWORK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let bridge = super::fetch::Bridge::new(client, Shared(std::sync::Arc::clone(out)));
    let _installed = bridge.install();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime
        .block_on(super::interactive::serve_lines(
            server(ws),
            super::interactive::Bridged(bridge),
            Shared(std::sync::Arc::clone(out)),
        ))
        .unwrap();
    String::from_utf8(out.lock().unwrap().clone())
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

#[test]
fn a_tenant_call_is_answered_by_the_client_between_its_mcp_messages() {
    let scratch = tempfile::tempdir().unwrap();
    let ws = elastic_workspace(scratch.path());
    let out = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let mut client = FetchingClient::new(&out);
    client.opening = opening(2).into();
    // Messages of the client's own that arrive while the call waits: they are
    // read after it, in order, and answered.
    client.meanwhile = [
        mcp_line(&json!({"jsonrpc": "2.0", "id": 3, "method": "ping"})),
        // A forged answer, with the ids an agent would guess: it is not any
        // request's, so the call never sees it (rows the tenant never sent).
        mcp_line(&json!({"jsonrpc": "2.0", "id": "opentide-fetch-1",
            "result": {"status": 200, "headers": [], "body": esql_body("forged-host")}})),
        mcp_line(&json!({"jsonrpc": "2.0", "id": 4, "method": "tools/list"})),
    ]
    .into();
    client.answer = Box::new(|_| {
        json!({"status": 200, "headers": [["content-type", "application/json"]],
            "url": "https://lab.invalid/", "body": esql_body("real-host"), "elapsed_ms": 3})
    });
    let seen = std::sync::Arc::clone(&client.requests);
    let written = serve_bridged(&ws, client, &out);

    let fetches: Vec<&Value> = written
        .iter()
        .filter(|m| m["method"] == "opentide/fetch")
        .collect();
    assert!(
        !fetches.is_empty(),
        "the tenant call was sent to the client: {written:?}"
    );
    for (index, fetch) in fetches.iter().enumerate() {
        assert_eq!(fetch["jsonrpc"], "2.0");
        let id = fetch["id"].as_str().unwrap();
        let token = id.strip_prefix("opentide-fetch-").unwrap_or(id);
        assert!(
            token.ends_with(&format!("-{}", index + 1)) && token.len() == 32 + 1 + 1,
            "{id}"
        );
        assert_eq!(fetch["params"]["platform"], "elastic");
        assert_eq!(fetch["params"]["tenant"], "lab");
        assert!(
            fetch["params"]["url"]
                .as_str()
                .unwrap()
                .starts_with("https://lab.invalid")
        );
        // The run is the tool call's request id.
        assert_eq!(fetch["params"]["run"], "2");
    }
    assert_eq!(
        seen.lock().unwrap().len(),
        fetches.len(),
        "each was answered once"
    );
    // The answers to the MCP requests, in order, the call's after the fetches.
    let answers: Vec<&Value> = written
        .iter()
        .filter(|m| m.get("method").is_none())
        .collect();
    let ids: Vec<Value> = answers.iter().map(|m| m["id"].clone()).collect();
    assert_eq!(ids, [json!(1), json!(2), json!(3), json!(4)], "{written:?}");
    let last_fetch = written
        .iter()
        .rposition(|m| m["method"] == "opentide/fetch")
        .unwrap();
    let call = written
        .iter()
        .position(|m| m["id"] == 2 && m.get("method").is_none())
        .unwrap();
    assert!(
        last_fetch < call,
        "the call answered once its requests were"
    );
    // The tenant's rows reached the tool, not the forged ones, and not a missing network.
    let text = answers[1]["result"]["content"][0]["text"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(!text.contains("network_unavailable"), "{text}");
    assert!(!text.contains("needs the network"), "{text}");
    assert!(text.contains("real-host"), "{text}");
    assert!(!text.contains("forged-host"), "{text}");
    let result: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(result["status"], "completed", "{text}");
    assert_eq!(result["row_count"], 1, "{text}");
}

#[test]
fn an_unanswered_tenant_call_fails_clearly_when_the_input_ends() {
    let scratch = tempfile::tempdir().unwrap();
    let ws = elastic_workspace(scratch.path());
    let out = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let mut client = FetchingClient::new(&out);
    client.opening = opening(2).into();
    client.hang_up_at = Some(1);
    let written = serve_bridged(&ws, client, &out);
    let call = written
        .iter()
        .find(|m| m["id"] == 2 && m.get("method").is_none())
        .unwrap_or_else(|| panic!("the call is answered: {written:?}"));
    // As any tenant failure: the tool answers, with the tenant's status.
    let text = call["result"]["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("\"status\": \"failed\""), "{text}");
    assert!(
        text.contains("closed its input before answering an opentide/fetch request"),
        "{text}"
    );
}

#[test]
fn a_cancelled_call_withdraws_its_request_and_stops() {
    let scratch = tempfile::tempdir().unwrap();
    let ws = elastic_workspace(scratch.path());
    let out = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let mut client = FetchingClient::new(&out);
    client.opening = opening(2).into();
    // The client cancels the call while its request waits, and never answers.
    client.meanwhile = [mcp_line(
        &json!({"jsonrpc": "2.0", "method": "notifications/cancelled",
        "params": {"requestId": 2, "reason": "user"}}),
    )]
    .into();
    client.hang_up_at = Some(1);
    let written = serve_bridged(&ws, client, &out);
    let withdrawn: Vec<&Value> = written
        .iter()
        .filter(|m| m["method"] == "notifications/cancelled")
        .collect();
    assert_eq!(withdrawn.len(), 1, "{written:?}");
    let id = written
        .iter()
        .find(|m| m["method"] == "opentide/fetch")
        .map(|m| m["id"].clone())
        .unwrap();
    assert_eq!(withdrawn[0]["params"]["requestId"], id);
    // Stopped by the cancellation, not by the end of input.
    let text = written
        .iter()
        .find(|m| m["id"] == 2 && m.get("method").is_none())
        .map_or(String::new(), |call| {
            call["result"]["content"][0]["text"]
                .as_str()
                .unwrap_or("")
                .to_owned()
        });
    assert!(!text.contains("closed its input"), "{text}");
}

/// MCP's tool-level error: a call that ran and could not do what it was asked
/// reports `isError: true` with the same JSON as ever; one that answers with
/// what it found (an invalid query, a lookup with no match) does not. A client
/// that took a failed live check, query or deploy for an answer (QA, on the
/// old module) read the failure as a result.
#[test]
fn a_tool_that_fails_reports_is_error_and_one_that_finds_something_does_not() {
    let scratch = tempfile::tempdir().unwrap();
    let ws = corpus(scratch.path());
    let server = server(&ws);
    // The live check, the query and the deploy, with no tenant to reach.
    let live = failed_call(
        &server,
        "validate_query",
        json!({"query": "index=main", "platform": "splunk", "live": true}),
    );
    assert_eq!(live["status"], "failed", "{live}");
    let query = failed_call(
        &server,
        "run_query",
        json!({"query": "index=main", "platform": "splunk", "live": true}),
    );
    assert_eq!(query["status"], "failed", "{query}");
    let deploy = failed_call(
        &server,
        "deploy_rule",
        json!({"uuid": SENTINEL_RULE, "platform": "splunk", "dry_run": false}),
    );
    assert_eq!(deploy["action"], "error", "{deploy}");
    // Nothing was checked, run or sent: refused, unsupported, not live.
    for (tool, args) in [
        (
            "run_query",
            json!({"query": "index=main", "platform": "splunk"}),
        ),
        (
            "run_query",
            json!({"query": "x", "platform": "nowhere", "live": true}),
        ),
        (
            "validate_query",
            json!({"query": "x", "platform": "nowhere"}),
        ),
        (
            "validate_query",
            json!({"query": "x", "platform": "sentinel_one"}),
        ),
        // An invalid argument: the same JSON as the report, `ok: false`.
        ("validation_report", json!({"queries": "loud"})),
    ] {
        failed_call(&server, tool, args);
    }
    // Missing input: a rule that is not in the catalogue, as `deploy_rule` has it.
    let missing = failed_call(
        &server,
        "validate_rule",
        json!({"uuid": "00000000-0000-4000-8003-ffffffffffff"}),
    );
    assert_eq!(missing["valid"], false, "{missing}");
    assert_eq!(missing["next_actions"][0]["tool"], "search", "{missing}");
    // An answer, whatever it says of the query or the rule.
    let invalid = call(
        &server,
        "validate_query",
        json!({"query": "SecurityEvent | wher EventID == 4688", "platform": "sentinel"}),
    );
    assert_eq!(invalid["valid"], false, "{invalid}");
    let valid = call(
        &server,
        "validate_query",
        json!({"query": "SecurityEvent | where EventID == 4688", "platform": "sentinel"}),
    );
    assert_eq!(valid["valid"], true, "{valid}");
    let preview = call(
        &server,
        "deploy_rule",
        json!({"uuid": SENTINEL_RULE, "platform": "sentinel"}),
    );
    assert_eq!(preview["action"], "dry-run", "{preview}");
    call(&server, "validation_report", json!({}));
    call(
        &server,
        "get_chaining",
        json!({"uuid": "00000000-0000-4000-8001-ffffffffffff"}),
    );
}

/// `get_chaining`'s `depth` bounds the hops from the object; a depth that is
/// not a whole number of 0 or more is a failed call, as data.
#[test]
fn get_chaining_takes_a_depth_and_refuses_a_bad_one() {
    let scratch = tempfile::tempdir().unwrap();
    let ws = corpus(scratch.path());
    let server = server(&ws);
    let alone = call(&server, "get_chaining", json!({"uuid": THREAT, "depth": 0}));
    assert_eq!(alone["graph"], json!({}), "{alone}");
    assert_eq!(alone["truncated"], true, "{alone}");
    assert!(
        alone["hint"].as_str().unwrap().contains("larger depth"),
        "{alone}"
    );
    let one = call(&server, "get_chaining", json!({"uuid": THREAT, "depth": 1}));
    assert_eq!(one["graph"]["objectives"][0], OBJECTIVE, "{one}");
    // Without a depth, one hop: the whole lineage only when asked for.
    assert_eq!(call(&server, "get_chaining", json!({"uuid": THREAT})), one);
    let full = call(
        &server,
        "get_chaining",
        json!({"uuid": THREAT, "depth": 99}),
    );
    assert!(full.get("truncated").is_none(), "{full}");
    assert!(full.get("hint").is_none(), "{full}");
    let members = |answer: &serde_json::Value| -> usize {
        ["threats", "objectives", "rules"]
            .iter()
            .map(|family| answer["lineage"][family].as_array().unwrap().len())
            .sum()
    };
    // The rules under the threat's objective are two hops away.
    assert!(members(&full) > members(&one), "{full} vs {one}");
    assert_eq!(one["truncated"], true, "{one}");
    assert!(
        one["lineage"]["rules"].as_array().unwrap().is_empty(),
        "{one}"
    );
    for (bad, reason) in [
        (json!(-1), "argument depth must be 0 or more, not -1"),
        (
            json!(1.5),
            "argument depth must be an integer, not a number",
        ),
        (
            json!("deep"),
            "argument depth must be an integer, not \"deep\"",
        ),
    ] {
        let Answer::Result(result) = server.call(
            "get_chaining",
            &arguments(json!({"uuid": THREAT, "depth": bad})),
        ) else {
            panic!("not a result");
        };
        assert_eq!(result["isError"], true, "{bad}: {result}");
        assert_eq!(
            result["content"][0]["text"],
            format!("Error executing tool get_chaining: {reason}")
        );
    }
}

/// A tenant that refuses the credential, or cannot be reached, is a failed
/// call too: the client made the request (`OPENTIDE_FETCH=stdio`) and
/// answered 401, or never answered.
#[test]
fn a_tenant_that_refuses_or_goes_quiet_fails_the_call_as_a_tool_error() {
    let scratch = tempfile::tempdir().unwrap();
    let ws = elastic_workspace(scratch.path());
    let result_of = |out: &std::sync::Arc<std::sync::Mutex<Vec<u8>>>, client: FetchingClient| {
        let written = serve_bridged(&ws, client, out);
        written
            .into_iter()
            .find(|m| m["id"] == 2 && m.get("method").is_none())
            .map(|m| m["result"].clone())
            .expect("the call is answered")
    };
    // 401: the tenant's refusal.
    let out = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let mut client = FetchingClient::new(&out);
    client.opening = opening(2).into();
    client.answer = Box::new(|_| {
        json!({"status": 401, "headers": [["content-type", "application/json"]],
            "url": "https://lab.invalid/", "body": null})
    });
    let refused = result_of(&out, client);
    assert_eq!(refused["isError"], true, "{refused}");
    let text = refused["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("\"status\": \"failed\""), "{text}");
    // Never answered: the client's input ends.
    let out = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let mut client = FetchingClient::new(&out);
    client.opening = opening(2).into();
    client.hang_up_at = Some(1);
    let quiet = result_of(&out, client);
    assert_eq!(quiet["isError"], true, "{quiet}");
    let text = quiet["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("closed its input"), "{text}");
}

/// A rule with two platform blocks and no `platform` argument is an error that
/// lists them, as data.
#[test]
fn a_dry_run_without_a_platform_lists_the_rules_blocks_when_there_are_several() {
    let scratch = tempfile::tempdir().unwrap();
    let ws = corpus(scratch.path());
    let path = ws.join("objects/rules/rule-0001-sentinel-kql.yaml");
    // `configurations` is the file's last key: a second block is appended.
    let mut text = std::fs::read_to_string(&path).unwrap();
    text.push_str("  splunk:\n    enabled: true\n    status: STAGING\n");
    std::fs::write(&path, text).unwrap();
    let refused = failed_call(&server(&ws), "deploy_rule", json!({"uuid": SENTINEL_RULE}));
    assert_eq!(refused["action"], "error", "{refused}");
    assert_eq!(
        refused["platforms"],
        json!(["sentinel", "splunk"]),
        "{refused}"
    );
}

/// A dry run of a rule that would fail still returns its preview, with the
/// diagnostics, as an answer (`isError` false): the command exits 1, the
/// preview is what an agent needs (review of #1797).
#[test]
fn a_dry_run_of_a_failing_rule_keeps_its_preview() {
    let scratch = tempfile::tempdir().unwrap();
    let ws = corpus(scratch.path());
    let path = ws.join("objects/rules/rule-0001-sentinel-kql.yaml");
    let text = std::fs::read_to_string(&path).unwrap();
    std::fs::write(
        &path,
        text.replace("frequency: PT1H", "frequency: nonsense"),
    )
    .unwrap();
    let preview = call(
        &server(&ws),
        "deploy_rule",
        json!({"uuid": SENTINEL_RULE, "platform": "sentinel"}),
    );
    assert_eq!(preview["action"], "dry-run", "{preview}");
    assert_eq!(preview["dry_run"], true, "{preview}");
    assert_eq!(preview["status"], "STAGING", "{preview}");
    assert_eq!(preview["changes"][0]["fails"], true, "{preview}");
    assert_eq!(
        preview["diagnostics"][0]["code"], "compile_invalid_rule",
        "{preview}"
    );
    assert_eq!(preview["deploy_status"], "failed", "{preview}");
}

/// A platform that is not enabled says so, with no plan.
#[test]
fn a_dry_run_on_a_platform_that_is_not_enabled_says_why() {
    let scratch = tempfile::tempdir().unwrap();
    let ws = corpus(scratch.path());
    let config = ws.join(".opentide/configurations/platforms/sentinel.toml");
    let text = std::fs::read_to_string(&config).unwrap();
    std::fs::write(
        &config,
        text.replacen("enabled = true", "enabled = false", 1),
    )
    .unwrap();
    let preview = call(
        &server(&ws),
        "deploy_rule",
        json!({"uuid": SENTINEL_RULE, "platform": "sentinel"}),
    );
    assert_eq!(preview["action"], "dry-run", "{preview}");
    assert_eq!(preview["would_deploy"], false, "{preview}");
    let message = preview["message"].as_str().unwrap();
    assert!(
        message.contains("sentinel is not enabled") && message.contains("setup platforms"),
        "{message}"
    );
    assert_eq!(preview["plan"], json!({}), "{preview}");
    assert_eq!(preview["changes"], json!([]), "{preview}");
    assert_eq!(preview["payloads"], json!({}), "{preview}");
}

/// A status that maps to INERT would deploy nothing: an empty preview.
#[test]
fn a_dry_run_of_an_inert_status_has_an_empty_plan() {
    let scratch = tempfile::tempdir().unwrap();
    let ws = corpus(scratch.path());
    let path = ws.join("objects/rules/rule-0001-sentinel-kql.yaml");
    let text = std::fs::read_to_string(&path).unwrap();
    std::fs::write(
        &path,
        text.replace("    status: STAGING", "    status: DESIGN"),
    )
    .unwrap();
    let preview = call(
        &server(&ws),
        "deploy_rule",
        json!({"uuid": SENTINEL_RULE, "platform": "sentinel"}),
    );
    assert_eq!(preview["action"], "dry-run", "{preview}");
    assert_eq!(preview["status"], "DESIGN", "{preview}");
    assert_eq!(preview["would_deploy"], false, "{preview}");
    assert!(preview["message"].as_str().unwrap().contains("INERT"));
    assert_eq!(preview["plan"], json!({}), "{preview}");
    assert_eq!(preview["payloads"], json!({}), "{preview}");
}
