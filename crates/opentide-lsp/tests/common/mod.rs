//! The test client shared by the protocol tests (#185 P2.8): the server
//! binary over stdio, real LSP frames, and helpers to read what it sends.
// `allow`, not `expect`: a test binary that uses every helper would leave an
// expectation unfulfilled.
#![allow(
    dead_code,
    reason = "each test binary uses a different part of the shared client"
)]

use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};

pub fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_opentide-lsp"))
}

pub fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// A path's `file:` URI as the platform's editors write it (`file:///C:/…`
/// on Windows), so the tests run on every platform (#185 P0.3).
pub fn file_uri(path: &std::path::Path) -> String {
    opentide_lsp::uri::path_to_uri(&path.display().to_string())
}

pub struct Lsp {
    pub child: std::process::Child,
    pub reader: BufReader<std::process::ChildStdout>,
    pub stdin: std::process::ChildStdin,
    pub next_id: i64,
    pub next_version: i64,
}

impl Lsp {
    pub fn spawn() -> Self {
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
            next_version: 1000,
        }
    }

    pub fn write(&mut self, body: &Value) {
        let payload = serde_json::to_vec(body).unwrap();
        write!(self.stdin, "Content-Length: {}\r\n\r\n", payload.len()).unwrap();
        self.stdin.write_all(&payload).unwrap();
        self.stdin.flush().unwrap();
    }

    /// The next message, logs left out.
    pub fn read(&mut self) -> Value {
        loop {
            let message = self.read_any();
            if message["method"] != "window/logMessage" {
                return message;
            }
        }
    }

    pub fn read_any(&mut self) -> Value {
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

    pub fn request(&mut self, method: &str, params: Value) -> Value {
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

    pub fn notify(&mut self, method: &str, mut params: Value) {
        // LSP versions every edit; a test that does not say gives each edit
        // the next one.
        if method == "textDocument/didChange" && params["textDocument"].get("version").is_none() {
            self.next_version += 1;
            params["textDocument"]["version"] = json!(self.next_version);
        }
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

/// Open a document, return the diagnostic codes published for it.
pub fn published_codes(lsp: &mut Lsp, uri: &str, language_id: &str, text: &str) -> Vec<String> {
    lsp.notify(
        "textDocument/didOpen",
        json!({
            "textDocument": {
                "uri": uri,
                "languageId": language_id,
                "version": 1,
                "text": text
            }
        }),
    );
    // Opening a Tide object re-checks the other open ones (they may reference
    // it), so other documents' publishes can come first.
    published_for(lsp, uri)
        .iter()
        .filter_map(|d| d["code"].as_str().map(str::to_string))
        .collect()
}

/// A fresh directory under the system temp dir, removed on drop.
pub struct Scratch(pub PathBuf);

impl Scratch {
    pub fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("opentide-e2e-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

pub fn copy_dir(from: &std::path::Path, to: &std::path::Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let path = entry.unwrap().path();
        let target = to.join(path.file_name().unwrap());
        if path.is_dir() {
            copy_dir(&path, &target);
        } else {
            std::fs::copy(&path, &target).unwrap();
        }
    }
}

pub fn next_diagnostics(lsp: &mut Lsp, uri: &str) -> Vec<String> {
    loop {
        let msg = lsp.read();
        if msg["method"] == "textDocument/publishDiagnostics" && msg["params"]["uri"] == uri {
            return msg["params"]["diagnostics"]
                .as_array()
                .unwrap()
                .iter()
                .filter_map(|d| d["code"].as_str().map(str::to_string))
                .collect();
        }
    }
}

pub fn codes_of(diagnostics: &[Value]) -> Vec<String> {
    diagnostics
        .iter()
        .filter_map(|d| d["code"].as_str().map(str::to_string))
        .collect()
}

pub fn published_for(lsp: &mut Lsp, uri: &str) -> Vec<Value> {
    loop {
        let msg = lsp.read();
        if msg["method"] == "textDocument/publishDiagnostics" && msg["params"]["uri"] == uri {
            return msg["params"]["diagnostics"]
                .as_array()
                .cloned()
                .unwrap_or_default();
        }
    }
}

pub fn raw(lsp: &mut Lsp, body: &str) {
    write!(lsp.stdin, "content-length: {}\r\n\r\n{body}", body.len()).unwrap();
    lsp.stdin.flush().unwrap();
}

pub fn exit_code(mut lsp: Lsp) -> i32 {
    lsp.child.wait().expect("server exits").code().unwrap_or(-1)
}
