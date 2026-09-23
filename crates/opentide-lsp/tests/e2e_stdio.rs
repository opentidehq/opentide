//! Protocol tests over stdio. The CLI never speaks JSON-RPC; `--stdio` does.

use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_opentide-lsp"))
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

struct Lsp {
    child: std::process::Child,
    reader: BufReader<std::process::ChildStdout>,
    stdin: std::process::ChildStdin,
    next_id: i64,
}

impl Lsp {
    fn spawn() -> Self {
        let mut child = Command::new(bin())
            .arg("--stdio")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn opentide-lsp");
        let stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        Self {
            child,
            reader: BufReader::new(stdout),
            stdin,
            next_id: 1,
        }
    }

    fn write(&mut self, body: &Value) {
        let payload = serde_json::to_vec(body).unwrap();
        write!(self.stdin, "Content-Length: {}\r\n\r\n", payload.len()).unwrap();
        self.stdin.write_all(&payload).unwrap();
        self.stdin.flush().unwrap();
    }

    fn read(&mut self) -> Value {
        let mut content_length = None;
        loop {
            let mut header = String::new();
            self.reader.read_line(&mut header).unwrap();
            let header = header.trim_end();
            if header.is_empty() {
                break;
            }
            if let Some(v) = header.strip_prefix("Content-Length:") {
                content_length = Some(v.trim().parse::<usize>().unwrap());
            }
        }
        let len = content_length.expect("Content-Length");
        let mut buf = vec![0u8; len];
        self.reader.read_exact(&mut buf).unwrap();
        serde_json::from_slice(&buf).unwrap()
    }

    fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        self.write(&json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params
        }));
        loop {
            let msg = self.read();
            if msg.get("id") == Some(&json!(id)) {
                return msg;
            }
            // skip notifications (publishDiagnostics)
        }
    }

    fn notify(&mut self, method: &str, params: Value) {
        self.write(&json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params
        }));
    }
}

impl Drop for Lsp {
    fn drop(&mut self) {
        let _ = self.child.kill();
    }
}

#[test]
fn initialize_and_analyze_kql() {
    let mut lsp = Lsp::spawn();
    let init = lsp.request(
        "initialize",
        json!({
            "capabilities": {},
            "rootUri": format!("file://{}", repo_root().display())
        }),
    );
    assert_eq!(init["result"]["serverInfo"]["name"], "opentide-lsp");
    assert_eq!(init["result"]["capabilities"]["hoverProvider"], true);
    assert!(
        init["result"]["capabilities"]["signatureHelpProvider"].is_object(),
        "{init}"
    );
    lsp.notify("initialized", json!({}));

    let kql = "SecurityEvent | where EventID == 4688 | take 1";
    lsp.notify(
        "textDocument/didOpen",
        json!({
            "textDocument": {
                "uri": "file:///tmp/sample.kql",
                "languageId": "kql",
                "version": 1,
                "text": kql
            }
        }),
    );
    let _diag = lsp.read(); // publishDiagnostics
    let hover = lsp.request(
        "textDocument/hover",
        json!({
            "textDocument": { "uri": "file:///tmp/sample.kql" },
            "position": { "line": 0, "character": 16 }
        }),
    );
    assert!(
        hover["result"]["contents"]["value"]
            .as_str()
            .unwrap_or("")
            .contains("where"),
        "{hover}"
    );

    let event_hover = lsp.request(
        "textDocument/hover",
        json!({
            "textDocument": { "uri": "file:///tmp/sample.kql" },
            "position": { "line": 0, "character": 24 }
        }),
    );
    let event_md = event_hover["result"]["contents"]["value"]
        .as_str()
        .unwrap_or("");
    assert!(
        event_md.contains("EventID"),
        "column hover for EventID, got {event_hover}"
    );

    let sig = lsp.request(
        "textDocument/signatureHelp",
        json!({
            "textDocument": { "uri": "file:///tmp/sample.kql" },
            "position": { "line": 0, "character": 16 }
        }),
    );
    assert!(
        sig["result"].is_object() || sig["result"].is_null(),
        "{sig}"
    );

    let tokens = lsp.request(
        "textDocument/semanticTokens/full",
        json!({ "textDocument": { "uri": "file:///tmp/sample.kql" } }),
    );
    assert!(!tokens["result"]["data"].as_array().unwrap().is_empty());

    let pipe_src = "SecurityEvent | ";
    lsp.notify(
        "textDocument/didOpen",
        json!({
            "textDocument": {
                "uri": "file:///tmp/pipe.kql",
                "languageId": "kql",
                "version": 1,
                "text": pipe_src
            }
        }),
    );
    let _ = lsp.read();
    let completion = lsp.request(
        "textDocument/completion",
        json!({
            "textDocument": { "uri": "file:///tmp/pipe.kql" },
            "position": { "line": 0, "character": pipe_src.len() }
        }),
    );
    assert!(
        completion["result"]
            .as_array()
            .unwrap()
            .iter()
            .any(|i| i["label"] == "where"),
        "{completion}"
    );

    let compiled = lsp.request(
        "opentide/compiledKql",
        json!({ "query": "DeviceEvents | take 1", "tenant": "t1" }),
    );
    assert_eq!(compiled["result"]["compiled"], "DeviceEvents | take 1");

    let highlight = lsp.request(
        "opentide/highlight",
        json!({ "language": "kql", "text": kql }),
    );
    assert!(
        highlight["result"]["tokens"]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t["capture"] == "operator.pipe")
    );

    lsp.request("shutdown", json!(null));
    lsp.notify("exit", json!({}));
}

#[test]
fn unknown_spl_command_is_published() {
    let mut lsp = Lsp::spawn();
    lsp.request("initialize", json!({ "capabilities": {} }));
    lsp.notify("initialized", json!({}));
    lsp.notify(
        "textDocument/didOpen",
        json!({
            "textDocument": {
                "uri": "file:///tmp/sample.spl",
                "languageId": "spl",
                "version": 1,
                "text": "index=main | bogus foo=bar"
            }
        }),
    );
    let msg = lsp.read();
    let diags = msg["params"]["diagnostics"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(
        diags.iter().any(|d| d["code"] == "spl_unknown_command"),
        "{msg}"
    );
}

#[test]
fn tide_yaml_pull_diagnostics_and_symbols() {
    let mut lsp = Lsp::spawn();
    let root = repo_root().join("testdata/workspaces/tide_corpus");
    lsp.request(
        "initialize",
        json!({
            "capabilities": {},
            "rootUri": format!("file://{}", root.display())
        }),
    );
    lsp.notify("initialized", json!({}));
    let path = root.join("objects/rules/rule-0001-sentinel-kql.yaml");
    let text = std::fs::read_to_string(&path).unwrap();
    let uri = format!("file://{}", path.display());
    lsp.notify(
        "textDocument/didOpen",
        json!({
            "textDocument": {
                "uri": uri,
                "languageId": "opentide-yaml",
                "version": 1,
                "text": text
            }
        }),
    );
    let _ = lsp.read();
    let pull = lsp.request(
        "textDocument/diagnostic",
        json!({ "textDocument": { "uri": uri } }),
    );
    assert_eq!(pull["result"]["kind"], "full");
    let symbols = lsp.request(
        "textDocument/documentSymbol",
        json!({ "textDocument": { "uri": uri } }),
    );
    assert!(
        symbols["result"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s["name"] == "Sentinel KQL Rule"),
        "{symbols}"
    );
    let compiled_spl = lsp.request(
        "opentide/compiledSpl",
        json!({ "query": "index=main | head 1" }),
    );
    assert_eq!(compiled_spl["result"]["compiled"], "index=main | head 1");
}

#[test]
fn cli_analyze_and_highlight_never_emit_jsonrpc() {
    let file = repo_root()
        .join("testdata/workspaces/tide_corpus/objects/rules/rule-0001-sentinel-kql.yaml");
    let analyze = Command::new(bin())
        .args(["analyze", file.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        analyze.status.success(),
        "{}",
        String::from_utf8_lossy(&analyze.stderr)
    );
    let stdout = String::from_utf8_lossy(&analyze.stdout);
    assert!(
        !stdout.contains("jsonrpc"),
        "CLI must not speak JSON-RPC: {stdout}"
    );
    let v: Value = serde_json::from_str(&stdout).unwrap();
    assert!(v.is_array());

    let highlight = Command::new(bin())
        .args([
            "highlight",
            file.to_str().unwrap(),
            "--language",
            "opentide-yaml",
        ])
        .output()
        .unwrap();
    assert!(highlight.status.success());
    let h: Value = serde_json::from_slice(&highlight.stdout).unwrap();
    let captures: Vec<_> = h["tokens"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["capture"].as_str().unwrap())
        .collect();
    assert!(captures.contains(&"tide.keyword"));
    assert!(
        captures
            .iter()
            .any(|c| *c == "keyword" || *c == "function" || *c == "type"),
        "{captures:?}"
    );
}

#[test]
fn highlight_html_contains_spans() {
    let file = repo_root().join("testdata/corpus/kql/take_operator__valid.kql");
    let out = Command::new(bin())
        .args(["highlight", file.to_str().unwrap(), "--html"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let html = String::from_utf8_lossy(&out.stdout);
    assert!(html.contains("<span class=\"keyword\">") && html.contains("operator-pipe"));
}
