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
        sig["result"].is_null() || sig["result"].is_object(),
        "{sig}"
    );
    lsp.notify(
        "textDocument/didChange",
        json!({
            "textDocument": { "uri": "file:///tmp/sample.kql" },
            "contentChanges": [{ "text": "SecurityEvent | where ago(" }]
        }),
    );
    let _ = lsp.read();
    let ago = lsp.request(
        "textDocument/signatureHelp",
        json!({
            "textDocument": { "uri": "file:///tmp/sample.kql" },
            "position": { "line": 0, "character": 26 }
        }),
    );
    let label = ago["result"]["signatures"][0]["label"]
        .as_str()
        .unwrap_or("");
    assert!(
        label.contains("ago("),
        "signature must be an object, got {ago}"
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

    fn pos(text: &str, needle: &str) -> (u32, u32) {
        let off = text.find(needle).expect(needle);
        let line = text[..off].bytes().filter(|b| *b == b'\n').count() as u32;
        let col = text[..off]
            .rsplit_once('\n')
            .map(|(_, rest)| rest.len())
            .unwrap_or(off) as u32;
        (line, col)
    }

    let (dline, dcol) = pos(&text, "description:");
    let hover = lsp.request(
        "textDocument/hover",
        json!({
            "textDocument": { "uri": uri },
            "position": { "line": dline, "character": dcol }
        }),
    );
    let hover_md = hover["result"]["contents"]["value"].as_str().unwrap_or("");
    assert!(
        hover_md.contains("Description") && hover_md.contains("required"),
        "field hover, got {hover}"
    );

    let (mline, mcol) = pos(&text, "  tlp:");
    let completion = lsp.request(
        "textDocument/completion",
        json!({
            "textDocument": { "uri": uri },
            "position": { "line": mline, "character": mcol }
        }),
    );
    let labels: Vec<&str> = completion["result"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|i| i["label"].as_str())
        .collect();
    assert!(labels.contains(&"author"), "{labels:?}");
    assert!(
        completion["result"]
            .as_array()
            .unwrap()
            .iter()
            .any(|i| i["documentation"]["value"]
                .as_str()
                .is_some_and(|d| d.contains("Author"))),
        "{completion}"
    );
    assert!(
        !labels.contains(&"High"),
        "no global vocab dump: {labels:?}"
    );

    let resolve = lsp.request(
        "completionItem/resolve",
        json!({ "label": "description", "kind": 5 }),
    );
    assert!(
        resolve["result"]["documentation"]["value"]
            .as_str()
            .unwrap_or("")
            .contains("Description"),
        "{resolve}"
    );

    let inlays = lsp.request(
        "textDocument/inlayHint",
        json!({
            "textDocument": { "uri": uri },
            "range": {
                "start": { "line": 0, "character": 0 },
                "end": { "line": 80, "character": 0 }
            }
        }),
    );
    assert!(
        inlays["result"]
            .as_array()
            .unwrap()
            .iter()
            .any(|h| h["label"]
                .as_str()
                .is_some_and(|l| l.to_lowercase().contains("objective"))),
        "{inlays}"
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
    assert!(captures.contains(&"tide.property"));
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

#[test]
fn tide_structure_methods_are_not_whole_buffer_stubs() {
    let mut lsp = Lsp::spawn();
    lsp.request(
        "initialize",
        json!({ "capabilities": {}, "rootUri": "file:///tmp" }),
    );
    lsp.notify("initialized", json!({}));
    let yaml = "name: Sentinel Rule\nmetadata:\n  uuid: 00000000-0000-4000-8003-000000000001\n  schema: rule::1.0\n  tlp: clear\ndescription: |\n  hello\n  world\n";
    let uri = "file:///tmp/struct-rule.yaml";
    lsp.notify(
        "textDocument/didOpen",
        json!({
            "textDocument": {
                "uri": uri,
                "languageId": "opentide-yaml",
                "version": 1,
                "text": yaml
            }
        }),
    );
    let _ = lsp.read();

    let folds = lsp.request(
        "textDocument/foldingRange",
        json!({ "textDocument": { "uri": uri } }),
    );
    let ranges = folds["result"].as_array().unwrap();
    assert!(ranges.len() > 1, "{folds}");
    assert!(
        ranges
            .iter()
            .all(|r| !(r["startLine"] == 0 && r["endLine"].as_u64().unwrap() >= 4)),
        "folding must not be one whole-buffer region: {folds}"
    );

    let sel = lsp.request(
        "textDocument/selectionRange",
        json!({
            "textDocument": { "uri": uri },
            "positions": [{ "line": 2, "character": 4 }]
        }),
    );
    let parent_end = sel["result"][0]["parent"]["range"]["end"]["line"]
        .as_u64()
        .unwrap();
    assert!(
        parent_end < 5,
        "selection parent must be the metadata block, got {sel}"
    );

    let symbols = lsp.request("workspace/symbol", json!({ "query": "Sentinel Rule" }));
    let range = &symbols["result"][0]["location"]["range"];
    assert_eq!(range["start"]["line"], 0);
    assert!(
        range["end"]["character"].as_u64().unwrap() > range["start"]["character"].as_u64().unwrap()
    );

    let actions = lsp.request(
        "textDocument/codeAction",
        json!({
            "textDocument": { "uri": uri },
            "range": { "start": { "line": 4, "character": 0 }, "end": { "line": 4, "character": 4 } }
        }),
    );
    assert_eq!(actions["result"].as_array().unwrap().len(), 0, "{actions}");

    lsp.notify(
        "textDocument/didChange",
        json!({
            "textDocument": { "uri": uri },
            "contentChanges": [
                { "range": { "start": { "line": 0, "character": 6 }, "end": { "line": 0, "character": 6 } }, "text": "X" },
                { "range": { "start": { "line": 0, "character": 7 }, "end": { "line": 0, "character": 7 } }, "text": "Y" }
            ]
        }),
    );
    let _ = lsp.read();
    let after = lsp.request("workspace/symbol", json!({ "query": "XYSentinel" }));
    assert!(
        !after["result"].as_array().unwrap().is_empty(),
        "both incremental edits must apply, got {after}"
    );

    lsp.notify(
        "textDocument/didClose",
        json!({ "textDocument": { "uri": uri } }),
    );
    let closed = lsp.read();
    assert_eq!(closed["method"], "textDocument/publishDiagnostics");
    assert!(
        closed["params"]["diagnostics"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let pull = lsp.request(
        "textDocument/diagnostic",
        json!({ "textDocument": { "uri": uri } }),
    );
    assert!(
        pull["result"]["items"].as_array().unwrap().is_empty(),
        "{pull}"
    );
}
