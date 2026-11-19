//! `opentide mcp start` over stdio (#264, #460, #1139): the binary spawned as
//! an MCP client spawns it, speaking newline-delimited JSON-RPC. The tools
//! and resources are tested in process (`src/mcp/tests.rs`); these hold the transport
//! and the launch: every line on stdout is a JSON-RPC frame until the server
//! exits, the handshake, and the workspace each way of starting finds.

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "a test: a server that does not answer as expected is a failure"
)]

use std::io::{BufRead as _, BufReader, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{Receiver, channel};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

const PATIENCE: Duration = Duration::from_secs(60);
const PROTOCOL_VERSION: &str = "2024-11-05";
const SENTINEL_RULE: &str = "00000000-0000-4000-8003-000000000001";
const SENTINEL_ONE_RULE: &str = "00000000-0000-4000-8003-000000000004";
const RULE_FILE: &str = "objects/rules/rule-0001-sentinel-kql.yaml";

/// `opentide mcp start`, a client's end of it.
struct Client {
    child: Child,
    stdin: Option<ChildStdin>,
    /// Each line of stdout, an error for one that is not UTF-8; `None` at
    /// its end.
    lines: Receiver<Option<Result<String, String>>>,
    stderr: Arc<Mutex<String>>,
    next_id: i64,
}

/// `opentide <args> mcp start` in `cwd`, with no workspace variable but
/// those in `env`, `CI` set, and a network that refuses every connection.
fn start(cwd: &Path, args: &[&str], env: &[(&str, &Path)]) -> Client {
    let mut command = Command::new(env!("CARGO_BIN_EXE_opentide-cli"));
    command.args(args).args(["mcp", "start"]).current_dir(cwd);
    for (name, _) in std::env::vars_os() {
        let text = name.to_string_lossy();
        if text.starts_with("OPENTIDE_") || text == "CLAUDE_PROJECT_DIR" {
            command.env_remove(name);
        }
    }
    command.env("CI", "true").env("PWD", cwd);
    for name in [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
    ] {
        command.env(name, "http://127.0.0.1:9");
    }
    for name in ["NO_PROXY", "no_proxy", "all_proxy"] {
        command.env_remove(name);
    }
    for (name, value) in env {
        command.env(name, value);
    }
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let (sender, lines) = channel();
    let stdout = BufReader::new(child.stdout.take().unwrap());
    std::thread::spawn(move || {
        for line in stdout.lines() {
            let line = line.map_err(|error| error.to_string());
            let _ = sender.send(Some(line));
        }
        let _ = sender.send(None);
    });
    let stderr = Arc::new(Mutex::new(String::new()));
    let (sink, pipe) = (Arc::clone(&stderr), child.stderr.take().unwrap());
    std::thread::spawn(move || {
        for line in BufReader::new(pipe).lines().map_while(Result::ok) {
            sink.lock().unwrap().push_str(&line);
            sink.lock().unwrap().push('\n');
        }
    });
    let stdin = child.stdin.take();
    Client {
        child,
        stdin,
        lines,
        stderr,
        next_id: 0,
    }
}

/// A line of stdout parsed: it must be a JSON-RPC frame.
fn frame(line: &str) -> Value {
    let frame: Value = serde_json::from_str(line)
        .unwrap_or_else(|error| panic!("not JSON-RPC on stdout ({error}): {line}"));
    assert_eq!(frame["jsonrpc"], "2.0", "not JSON-RPC on stdout: {line}");
    frame
}

/// A tool result's text blocks, each parsed as JSON.
fn blocks(result: &Value) -> Value {
    let blocks = result["content"].as_array();
    let blocks = blocks.unwrap_or_else(|| panic!("no content: {result}"));
    let text = |block: &Value| serde_json::from_str(block["text"].as_str().unwrap()).unwrap();
    Value::Array(blocks.iter().map(text).collect())
}

impl Client {
    fn send(&mut self, message: &Value) {
        let stdin = self.stdin.as_mut().expect("stdin is open");
        writeln!(stdin, "{message}").unwrap();
        stdin.flush().unwrap();
    }

    fn notify(&mut self, method: &str) {
        self.send(&json!({"jsonrpc": "2.0", "method": method}));
    }

    /// The response to `method`; every frame before it must be JSON-RPC.
    fn request(&mut self, method: &str, params: Value) -> Value {
        self.next_id += 1;
        let id = self.next_id;
        self.send(&json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}));
        loop {
            let line = self.lines.recv_timeout(PATIENCE).ok().flatten();
            let line = line.unwrap_or_else(|| panic!("no answer to {method}: {}", self.stderr()));
            let line = self.text(line);
            if line.trim().is_empty() {
                continue;
            }
            let frame = frame(&line);
            if frame["id"] == id {
                return frame;
            }
        }
    }

    /// `initialize` and `notifications/initialized`; the handshake's result.
    fn handshake(&mut self) -> Value {
        let client = json!({"name": "opentide-e2e", "version": "1"});
        let params =
            json!({"protocolVersion": PROTOCOL_VERSION, "capabilities": {}, "clientInfo": client});
        let response = self.request("initialize", params);
        self.notify("notifications/initialized");
        response["result"].clone()
    }

    /// The `tools/call` result, which must not be an error.
    fn raw_call(&mut self, name: &str, arguments: Value) -> Value {
        let response = self.request("tools/call", json!({"name": name, "arguments": arguments}));
        let result = response["result"].clone();
        assert_ne!(result["isError"], true, "{name}: {result}");
        result
    }

    /// A tool's answer: its structured content, a list unwrapped, or else
    /// its text blocks parsed.
    fn call(&mut self, name: &str, arguments: Value) -> Value {
        let result = self.raw_call(name, arguments);
        match result["structuredContent"].as_object() {
            Some(object) if object.len() == 1 && object.contains_key("result") => {
                object["result"].clone()
            }
            Some(object) => Value::Object(object.clone()),
            None => match blocks(&result) {
                Value::Array(mut one) if one.len() == 1 => one.remove(0),
                many => many,
            },
        }
    }

    /// A resource's text, parsed.
    fn read(&mut self, uri: &str) -> Value {
        let response = self.request("resources/read", json!({"uri": uri}));
        let text = response["result"]["contents"][0]["text"].as_str();
        let text = text.unwrap_or_else(|| panic!("no contents for {uri}: {response}"));
        serde_json::from_str(text).unwrap()
    }

    /// A line of stdout, which must be text: bytes that are not UTF-8 are
    /// no JSON-RPC frame.
    fn text(&self, line: Result<String, String>) -> String {
        line.unwrap_or_else(|error| panic!("garbled stdout ({error}): {}", self.stderr()))
    }

    fn stderr(&self) -> String {
        self.stderr.lock().unwrap().clone()
    }

    /// Closes stdin: the server exits, and everything it still wrote to
    /// stdout must be JSON-RPC.
    fn close(mut self) {
        drop(self.stdin.take());
        while let Some(line) = self.lines.recv_timeout(PATIENCE).expect("stdout to close") {
            let line = self.text(line);
            if !line.trim().is_empty() {
                frame(&line);
            }
        }
        // Stdout is closed, so the server has exited or is about to: a
        // server that does not is a failure, not a hung test.
        let started = Instant::now();
        let status = loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                break status;
            }
            assert!(
                started.elapsed() < PATIENCE,
                "the server did not exit; stderr:\n{}",
                self.stderr()
            );
            std::thread::sleep(Duration::from_millis(20));
        };
        assert!(status.success(), "{}", self.stderr());
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

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

/// `tests/fixtures/tide_corpus` in the `.opentide/` layout under `root`.
fn corpus(root: &Path) -> PathBuf {
    let source =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/tide_corpus/current");
    let ws = root.join("corpus");
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

/// The server on a fresh corpus, the workspace variables naming it.
fn on_the_corpus() -> (tempfile::TempDir, PathBuf, Client) {
    let dir = tempfile::tempdir().unwrap();
    let ws = corpus(dir.path());
    let env = [
        ("OPENTIDE_REPO_ROOT", &*ws),
        ("OPENTIDE_TIDE_WORKSPACE", &*ws),
    ];
    let client = start(&ws, &[], &env);
    (dir, ws, client)
}

fn uuids(hits: &Value) -> Vec<&str> {
    let hits = hits.as_array().unwrap_or_else(|| panic!("a list: {hits}"));
    hits.iter()
        .map(|hit| hit["uuid"].as_str().unwrap())
        .collect()
}

#[test]
fn the_handshake_names_the_server_its_version_and_workflow() {
    let (_dir, _, mut client) = on_the_corpus();
    let result = client.handshake();
    assert_eq!(result["protocolVersion"], PROTOCOL_VERSION);
    assert_eq!(result["serverInfo"]["name"], "opentide");
    // opentide's version, not the MCP library's.
    let version = option_env!("OPENTIDE_VERSION").unwrap_or(env!("CARGO_PKG_VERSION"));
    assert_eq!(result["serverInfo"]["version"], version);
    assert!(result["capabilities"]["tools"].is_object(), "{result}");
    let instructions = result["instructions"].as_str().unwrap();
    let tagline = "opentide: Spec-driven development for agentic detection engineering.";
    assert!(instructions.starts_with(tagline), "{instructions}");
    assert!(instructions.contains("validation_report"), "{instructions}");
    assert!(instructions.contains("dry_run true"), "{instructions}");

    let tools = client.request("tools/list", json!({}))["result"]["tools"].clone();
    let mut names = Vec::new();
    for tool in tools.as_array().unwrap() {
        let words = tool["description"].as_str().unwrap().split_whitespace();
        assert!(words.count() >= 8, "{tool} describes itself");
        names.push(tool["name"].as_str().unwrap());
    }
    names.sort_unstable();
    let expected = "coverage deploy_rule deployment_status explain get_chaining run_query \
                    search validate_query validate_rule validation_report";
    assert_eq!(names, expected.split(' ').collect::<Vec<_>>());
    client.close();
}

/// The catalogue's tools and resources over stdio, and stdout holding only
/// JSON-RPC frames while they run, the query service's included, until the
/// server exits.
#[test]
fn tools_and_resources_answer_with_nothing_but_json_rpc_on_stdout() {
    let (_dir, _, mut client) = on_the_corpus();
    client.handshake();
    assert_eq!(
        uuids(&client.call("search", json!({"query": SENTINEL_RULE}))),
        [SENTINEL_RULE]
    );
    let filtered = json!({"query": "Rule", "platform": "sentinel"});
    let hits = client.call("search", filtered.clone());
    assert!(uuids(&hits).contains(&SENTINEL_RULE), "{hits}");
    assert!(!uuids(&hits).contains(&SENTINEL_ONE_RULE), "{hits}");
    // One text block per hit, which says what the structured content does.
    let raw = client.raw_call("search", filtered);
    assert_eq!(raw["structuredContent"]["result"], blocks(&raw));

    let coverage = client.call("coverage", json!({"technique": "T1059"}));
    assert_eq!(coverage["covered"], true, "{coverage}");
    // Every platform's rule in the corpus covers it.
    for suffix in ["1", "2", "3", "4", "5", "6", "7", "9", "5d1a90"] {
        let uuid = format!("00000000-0000-4000-8003-{suffix:0>12}");
        let rules = coverage["rules"].as_array().unwrap();
        assert!(rules.contains(&json!(uuid)), "{uuid}: {coverage}");
    }

    let page = client.call("explain", json!({"code": "invalid_ref"}));
    assert_eq!(
        (&page["found"], &page["code"]),
        (&json!(true), &json!("invalid_ref"))
    );
    assert!(
        page["markdown"]
            .as_str()
            .unwrap()
            .starts_with("# invalid_ref")
    );
    let listing = client.call("explain", json!({}));
    assert!(
        listing["codes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["code"] == "invalid_ref")
    );

    let query = json!({"query": "SecurityEvent", "platform": "sentinel", "live": true});
    let checked = client.call("validate_query", query);
    assert!(
        checked.is_object() && checked.get("_failure_code").is_none(),
        "{checked}"
    );
    client.call("validation_report", json!({}));

    let platforms = client.read("opentide://platforms");
    let platform = |name: &str| {
        let all = platforms.as_array().unwrap();
        all.iter().find(|entry| entry["name"] == name).unwrap()["can_validate"].clone()
    };
    assert_eq!(
        (platform("sentinel"), platform("crowdstrike")),
        (json!(true), json!(false))
    );
    let rule = client.read(&format!("opentide://rules/{SENTINEL_RULE}"));
    assert_eq!(rule["metadata"]["uuid"], SENTINEL_RULE);
    client.read("opentide://index");

    // Every vocabulary the index advertises is readable, `att&ck` too, and
    // its name percent-encoded as RFC 6570 has it.
    let index = client.read("opentide://vocabularies");
    let actors = client.read(index["actors"]["uri"].as_str().unwrap());
    let entries = &actors["entries"];
    let count = entries
        .as_array()
        .map(Vec::len)
        .or(entries.as_object().map(|o| o.len()));
    assert_eq!(json!(count), index["actors"]["entry_count"], "{actors}");
    assert!(index.get("att&ck").is_some(), "{index}");
    for (name, entry) in index.as_object().unwrap() {
        let uri = entry["uri"].as_str().unwrap();
        let response = client.request("resources/read", json!({"uri": uri}));
        assert!(response.get("error").is_none(), "{name}: {response}");
        assert!(client.read(uri).get("error").is_none(), "{name}");
    }
    assert!(
        client
            .read("opentide://vocabularies/att%26ck")
            .get("error")
            .is_none()
    );
    client.close();
}

/// A typo on disk comes back with its position, a fix and the next actions.
#[test]
fn the_validation_report_carries_the_diagnostic_fields() {
    let dir = tempfile::tempdir().unwrap();
    let ws = corpus(dir.path());
    let rule = ws.join(RULE_FILE);
    let text = std::fs::read_to_string(&rule).unwrap();
    std::fs::write(&rule, text.replacen("  tlp: clear\n", "  tlp: clearr\n", 1)).unwrap();
    let env = [
        ("OPENTIDE_REPO_ROOT", &*ws),
        ("OPENTIDE_TIDE_WORKSPACE", &*ws),
    ];
    let mut client = start(&ws, &[], &env);
    client.handshake();
    let report = client.call("validation_report", json!({"file": RULE_FILE}));
    let issues = report["issues"].as_array().unwrap();
    let issue = issues
        .iter()
        .find(|issue| issue["code"] == "vocab_unknown")
        .unwrap();
    assert_eq!(
        issue["line"],
        json!(issue["yaml_line"].as_u64().unwrap() + 1)
    );
    assert_eq!(issue["fix"]["safe"], false, "{issue}");
    assert_eq!(issue["fix"]["edits"][0]["replacement"], "clear", "{issue}");
    assert_eq!(issue["explain"], "opentide explain vocab_unknown");
    assert_eq!(report["next_actions"][0]["tool"], "explain", "{report}");
    client.close();
}

/// MCP stdio is newline-delimited: LSP's `Content-Length` header is no
/// frame, and the body, a last line that only the end of stdin terminates,
/// is still answered.
#[test]
fn content_length_headers_are_skipped_and_the_body_is_answered() {
    let (_dir, ws, mut client) = on_the_corpus();
    let client_info = json!({"name": "lsp-style", "version": "1"});
    let params =
        json!({"protocolVersion": PROTOCOL_VERSION, "capabilities": {}, "clientInfo": client_info});
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": params});
    let body = body.to_string();
    let stdin = client.stdin.as_mut().unwrap();
    write!(stdin, "Content-Length: {}\r\n\r\n{body}", body.len()).unwrap();
    stdin.flush().unwrap();
    // No newline ends the body: the end of stdin does.
    drop(client.stdin.take());
    let line = client
        .lines
        .recv_timeout(PATIENCE)
        .unwrap()
        .expect("an answer");
    let answer = frame(&client.text(line));
    assert_eq!(answer["id"], 1, "{answer}");
    assert_eq!(answer["result"]["serverInfo"]["name"], "opentide");
    client.close();
    drop(ws);
}

/// `tools/call` and `resources/read` without their params are methods the
/// server has: the answer is `Invalid params`, not `Method not found`.
#[test]
fn a_known_method_without_its_params_is_invalid_params() {
    let (_dir, ws, mut client) = on_the_corpus();
    client.handshake();
    for (id, method) in [(41, "tools/call"), (42, "resources/read")] {
        client.send(&json!({"jsonrpc": "2.0", "id": id, "method": method}));
        let answer = loop {
            let line = client
                .lines
                .recv_timeout(PATIENCE)
                .unwrap()
                .expect("an answer");
            let answer = frame(&client.text(line));
            if answer["id"] == id {
                break answer;
            }
        };
        assert_eq!(answer["error"]["code"], -32602, "{answer}");
        assert_eq!(answer["error"]["data"], method, "{answer}");
    }
    client.close();
    drop(ws);
}

/// `opentide --repo <ws> mcp start` from another folder serves `<ws>`.
#[test]
fn repo_names_the_workspace_from_outside_it() {
    let dir = tempfile::tempdir().unwrap();
    let ws = corpus(dir.path());
    let outside = dir.path().join("outside");
    std::fs::create_dir(&outside).unwrap();
    let mut client = start(&outside, &["--repo", ws.to_str().unwrap()], &[]);
    client.handshake();
    let hits = client.call("search", json!({"query": "Rule", "platform": "sentinel"}));
    assert!(uuids(&hits).contains(&SENTINEL_RULE), "{hits}");
    let report = client.call("validation_report", json!({"file": RULE_FILE}));
    assert_eq!(report["ok"], true, "{report}");
    assert_eq!(report["stats"]["objects_checked"], 1, "{report}");
    let rules = client.read("opentide://rules");
    assert!(rules.to_string().contains(SENTINEL_RULE), "{rules}");
    client.close();
}

/// An Agent Plugin root (#431): what a plugin host starts the server in.
fn plugin_root(path: &Path) -> PathBuf {
    std::fs::create_dir_all(path.join("skills")).unwrap();
    std::fs::create_dir_all(path.join(".git")).unwrap();
    let manifest = json!({
        "$schema": "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json",
        "name": "opentide",
    });
    std::fs::write(path.join("plugin.json"), manifest.to_string()).unwrap();
    path.to_path_buf()
}

#[test]
fn a_plugin_launch_serves_the_host_project() {
    let dir = tempfile::tempdir().unwrap();
    let ws = corpus(dir.path());
    let plugin = plugin_root(&dir.path().join("skills"));
    let mut client = start(&plugin, &[], &[("CLAUDE_PROJECT_DIR", &ws)]);
    client.handshake();
    assert_eq!(
        uuids(&client.call("search", json!({"query": SENTINEL_RULE}))),
        [SENTINEL_RULE]
    );
    client.close();
}

#[test]
fn a_plugin_launch_without_a_workspace_says_how_to_name_one() {
    let dir = tempfile::tempdir().unwrap();
    let plugin = plugin_root(&dir.path().join("skills"));
    let mut client = start(&plugin, &[], &[]);
    client.handshake();
    let response = client.request(
        "tools/call",
        json!({"name": "search", "arguments": {"query": ""}}),
    );
    assert_eq!(response["result"]["isError"], true, "{response}");
    let text = response["result"]["content"][0]["text"].as_str().unwrap();
    assert!(
        text.contains("workspace_not_found") && text.contains("OPENTIDE_REPO_ROOT"),
        "{text}"
    );
    // A tool that needs no catalogue still works.
    let explained = client.call("explain", json!({"code": "workspace_not_found"}));
    assert!(explained.is_object(), "{explained}");
    client.close();
}
