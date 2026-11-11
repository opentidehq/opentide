//! `opentide lsp start` on the Rust CLI (UC-3.6b, #947): the editor contract
//! `tests/test_lsp/e2e/test_lsp_stdio_e2e.py` holds the Python host to, held
//! here against the `opentide` binary. An editor spawns the command and
//! speaks `Content-Length` framed JSON-RPC on its stdio: stdout carries
//! nothing else, and the exit code is LSP's.

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test helpers: a server that does not answer is a failure"
)]

use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use serde_json::{Value, json};

const RULE: &str = "\
name: Suspicious Process
metadata:
  uuid: 00000000-0000-4000-8003-000000000001
  schema: rule::1.0
  version: 1
  created: 2026-01-01
  modified: 2026-01-02
  tlp: clear
configurations:
  sentinel:
    query: |
      SecurityEvent
      | wher EventID == 4688
";

fn server(cwd: &Path, flags: &[&str]) -> Child {
    Command::new(env!("CARGO_BIN_EXE_opentide"))
        .args(["lsp", "start"])
        .args(flags)
        .current_dir(cwd)
        .env_clear()
        .env("HOME", cwd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

fn send(stdin: &mut ChildStdin, message: &Value) {
    let body = message.to_string();
    write!(stdin, "Content-Length: {}\r\n\r\n{body}", body.len()).unwrap();
    stdin.flush().unwrap();
}

fn read(stdout: &mut BufReader<ChildStdout>) -> Value {
    let mut length = None;
    loop {
        let mut line = String::new();
        assert!(
            stdout.read_line(&mut line).unwrap() > 0,
            "the server closed stdout"
        );
        if line == "\r\n" || line == "\n" {
            break;
        }
        let (name, value) = line.split_once(':').expect("a protocol header");
        assert!(
            name.eq_ignore_ascii_case("content-length"),
            "not a protocol header: {line:?}"
        );
        length = Some(value.trim().parse::<usize>().unwrap());
    }
    let mut body = vec![0; length.expect("Content-Length")];
    stdout.read_exact(&mut body).unwrap();
    serde_json::from_slice(&body).unwrap()
}

fn uri(path: &Path) -> String {
    format!("file://{}", path.display())
}

/// Opens the rule in a session: the diagnostics the server publishes for it.
fn session(cwd: &Path, flags: &[&str], rule: &Path) -> (Value, Value, Child) {
    let mut child = server(cwd, flags);
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    send(
        &mut stdin,
        &json!({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"capabilities": {}, "rootUri": uri(cwd)}}),
    );
    let init = read(&mut stdout);
    send(
        &mut stdin,
        &json!({"jsonrpc": "2.0", "method": "initialized", "params": {}}),
    );
    send(
        &mut stdin,
        &json!({"jsonrpc": "2.0", "method": "textDocument/didOpen", "params": {
            "textDocument": {"uri": uri(rule), "languageId": "opentide-yaml",
                             "version": 1, "text": RULE}}}),
    );
    let published = read(&mut stdout);
    send(
        &mut stdin,
        &json!({"jsonrpc": "2.0", "id": 2, "method": "shutdown"}),
    );
    assert_eq!(read(&mut stdout)["id"], 2);
    send(&mut stdin, &json!({"jsonrpc": "2.0", "method": "exit"}));
    drop(stdin);
    let mut rest = Vec::new();
    stdout.read_to_end(&mut rest).unwrap();
    assert!(
        rest.is_empty(),
        "stdout carries the protocol and nothing else"
    );
    (init, published, child)
}

fn workspace() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    let rule = root.join("objects/rules/suspicious-process.yaml");
    std::fs::create_dir_all(rule.parent().unwrap()).unwrap();
    std::fs::write(&rule, RULE).unwrap();
    (dir, rule)
}

#[test]
fn an_editor_session_from_initialize_to_exit() {
    for flags in [&[][..], &["--stdio"][..]] {
        let (dir, rule) = workspace();
        let root = rule.ancestors().nth(3).unwrap().to_path_buf();
        let (init, published, mut child) = session(&root, flags, &rule);
        assert_eq!(init["id"], 1);
        assert_eq!(init["result"]["serverInfo"]["name"], "opentide-lsp");
        assert_eq!(init["result"]["capabilities"]["hoverProvider"], true);
        // The client can tell `opentide lsp start` from the bare binary.
        let host = &init["result"]["capabilities"]["experimental"]["opentide"];
        assert_eq!(host["host"]["name"], "opentide", "{flags:?}");
        assert_eq!(host["catalog"], "host");
        assert_eq!(host["configurationChecks"], true);
        assert_eq!(host["configurationSchemas"], true);
        assert_eq!(published["method"], "textDocument/publishDiagnostics");
        let codes: Vec<&str> = published["params"]["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|item| item["code"].as_str())
            .collect();
        assert!(codes.contains(&"kql_unknown_operator"), "{codes:?}");
        assert_eq!(child.wait().unwrap().code(), Some(0));
        drop(dir);
    }
}

#[test]
fn closing_stdin_ends_the_server_with_1() {
    let dir = tempfile::tempdir().unwrap();
    let mut child = server(dir.path(), &[]);
    drop(child.stdin.take());
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    // Not a terminal: an editor, which needs no hint.
    assert!(output.stderr.is_empty(), "{:?}", output.stderr);
}

/// #677: a catalog committed by an older opentide (one whose TLP
/// vocabulary is only `house`) does not replace opentide's own.
#[test]
fn the_server_checks_with_opentides_catalog_not_a_committed_copy() {
    let (dir, rule) = workspace();
    let root = rule.ancestors().nth(3).unwrap().to_path_buf();
    let committed = root.join(".opentide/lsp/catalogs/generated");
    std::fs::create_dir_all(&committed).unwrap();
    let stale = json!({
        "opentide": "0.0.1",
        "fields": [
            {"schema": "rule", "path": "metadata", "name": "metadata", "type": "object"},
            {"schema": "rule", "path": "metadata.tlp", "name": "tlp", "enum": ["house"]},
        ],
    });
    std::fs::write(committed.join("fields.json"), stale.to_string()).unwrap();
    let (_, published, mut child) = session(&root, &[], &rule);
    let messages: Vec<&str> = published["params"]["diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|item| item["message"].as_str())
        .filter(|message| message.contains("tlp"))
        .collect();
    assert!(messages.is_empty(), "{messages:?}");
    assert_eq!(child.wait().unwrap().code(), Some(0));
    drop(dir);
}
