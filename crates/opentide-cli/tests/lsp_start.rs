//! `opentide lsp start` on the Rust CLI (UC-3.6b, #947): the editor contract
//! `tests/test_lsp/e2e/test_lsp_stdio_e2e.py` holds the Python host to, held
//! here against the `opentide` binary. An editor spawns the command and
//! speaks `Content-Length` framed JSON-RPC on its stdio: stdout carries
//! nothing else, and the exit code is LSP's.
//!
//! The harness never blocks on the server: a thread reads its stdout frame
//! by frame and another drains its stderr, and every wait (a message, the
//! end of stdout, the exit) gives up after [`PATIENCE`] with what it waited
//! for and the server's stderr, so a server that stays silent fails the test
//! instead of hanging it until the runner kills it.

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test helpers: a server that does not answer is a failure"
)]

use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, channel};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

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

/// How long the server has to send a message, close stdout or exit. A whole
/// session takes well under a second; past this the test fails and says what
/// it waited for.
const PATIENCE: Duration = Duration::from_secs(30);

/// What the reader thread found next on the server's stdout.
enum Event {
    Message(Value),
    /// End of stdout between two frames.
    Closed,
    /// Anything but a protocol frame.
    Garbled(String),
}

/// `opentide lsp start` in a child process, as an editor drives it.
struct Server {
    child: Child,
    stdin: Option<ChildStdin>,
    events: Receiver<Event>,
    stderr: Arc<Mutex<Vec<u8>>>,
    stderr_closed: Receiver<()>,
    /// How long each wait lasts: [`PATIENCE`].
    patience: Duration,
}

impl Server {
    fn start(cwd: &Path, flags: &[&str]) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_opentide-cli"))
            .args(["lsp", "start"])
            .args(flags)
            .current_dir(cwd)
            .env_clear()
            .env("HOME", cwd)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take();
        let stdout = child.stdout.take().unwrap();
        let (sender, events) = channel();
        std::thread::spawn(move || frames(stdout, &sender));
        let mut pipe = child.stderr.take().unwrap();
        let stderr = Arc::new(Mutex::new(Vec::new()));
        let (closed, stderr_closed) = channel();
        let sink = Arc::clone(&stderr);
        std::thread::spawn(move || {
            let mut chunk = [0; 4096];
            while let Ok(read @ 1..) = pipe.read(&mut chunk) {
                sink.lock().unwrap().extend_from_slice(&chunk[..read]);
            }
            let _ = closed.send(());
        });
        Self {
            child,
            stdin,
            events,
            stderr,
            stderr_closed,
            patience: PATIENCE,
        }
    }

    fn send(&mut self, message: &Value) {
        let stdin = self.stdin.as_mut().expect("stdin is open");
        let body = message.to_string();
        write!(stdin, "Content-Length: {}\r\n\r\n{body}", body.len()).unwrap();
        stdin.flush().unwrap();
    }

    /// The next message, or `None` once stdout is closed.
    fn next(&self, waiting_for: &str) -> Option<Value> {
        match self.events.recv_timeout(self.patience) {
            Ok(Event::Message(message)) => Some(message),
            Ok(Event::Closed) | Err(RecvTimeoutError::Disconnected) => None,
            Ok(Event::Garbled(what)) => panic!(
                "stdout carries the protocol and nothing else: {what}; stderr: {}",
                self.stderr_so_far()
            ),
            Err(RecvTimeoutError::Timeout) => panic!(
                "the server sent nothing in {:?} while the test waited for {waiting_for}; \
                 stderr: {}",
                self.patience,
                self.stderr_so_far()
            ),
        }
    }

    fn read(&self, waiting_for: &str) -> Value {
        self.next(waiting_for).unwrap_or_else(|| {
            panic!(
                "the server closed stdout while the test waited for {waiting_for}; stderr: {}",
                self.stderr_so_far()
            )
        })
    }

    fn until_diagnostics(&self, uri: &str) -> Value {
        let waiting_for = format!("the diagnostics of {uri}");
        loop {
            let message = self.read(&waiting_for);
            if message["method"] == "textDocument/publishDiagnostics"
                && message["params"]["uri"] == uri
            {
                return message["params"]["diagnostics"].clone();
            }
        }
    }

    fn until_reply(&self, id: i64) -> Value {
        let waiting_for = format!("the reply to request {id}");
        loop {
            let message = self.read(&waiting_for);
            // A reply, not a request the server sends the client.
            if message["id"] == id && message.get("method").is_none() {
                return message;
            }
        }
    }

    /// `initialize` for `root`; the reply, which must be a result.
    fn initialize(&mut self, root: &Path) -> Value {
        self.send(&json!({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                          "params": {"capabilities": {}, "rootUri": uri(root)}}));
        let reply = self.until_reply(1);
        // A refused `initialize` leaves the server uninitialized, and it then
        // drops every notification: say so here rather than wait for
        // diagnostics that never come.
        assert!(reply.get("error").is_none(), "initialize failed: {reply}");
        reply
    }

    /// `shutdown`, then `exit` and stdin closed: stdout carries nothing after
    /// the reply to `shutdown`; the exit code.
    fn shut_down(&mut self) -> Option<i32> {
        self.send(&json!({"jsonrpc": "2.0", "id": 99, "method": "shutdown"}));
        let reply = self.until_reply(99);
        assert!(reply.get("error").is_none(), "shutdown failed: {reply}");
        self.send(&json!({"jsonrpc": "2.0", "method": "exit"}));
        self.close_stdin()
    }

    /// Closes stdin; the exit code, once stdout is closed with nothing more
    /// on it.
    fn close_stdin(&mut self) -> Option<i32> {
        drop(self.stdin.take());
        if let Some(message) = self.next("stdout to close") {
            panic!("stdout carries the protocol and nothing else: {message} after the session");
        }
        self.wait()
    }

    /// The exit code, within [`PATIENCE`].
    fn wait(&mut self) -> Option<i32> {
        let started = Instant::now();
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return status.code();
            }
            if started.elapsed() > self.patience {
                let _ = self.child.kill();
                panic!(
                    "the server did not exit in {:?}; stderr: {}",
                    self.patience,
                    self.stderr_so_far()
                );
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// All of stderr, once the server closed it.
    fn stderr(&self) -> String {
        assert!(
            self.stderr_closed.recv_timeout(self.patience).is_ok(),
            "the server did not close stderr in {:?}: {}",
            self.patience,
            self.stderr_so_far()
        );
        self.stderr_so_far()
    }

    fn stderr_so_far(&self) -> String {
        String::from_utf8_lossy(&self.stderr.lock().unwrap()).into_owned()
    }
}

impl Drop for Server {
    /// A test that failed leaves no server behind.
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The reader thread: the server's stdout, one event per frame, until it
/// closes or carries something that is not a frame.
fn frames(stdout: ChildStdout, events: &Sender<Event>) {
    let mut stdout = BufReader::new(stdout);
    loop {
        let event = match frame(&mut stdout) {
            Ok(Some(message)) => Event::Message(message),
            Ok(None) => Event::Closed,
            Err(what) => Event::Garbled(what),
        };
        let last = !matches!(event, Event::Message(_));
        if events.send(event).is_err() || last {
            return;
        }
    }
}

/// One `Content-Length` framed message; `None` at the end of stdout between
/// two frames.
fn frame(stdout: &mut impl BufRead) -> Result<Option<Value>, String> {
    let mut length = None;
    let mut headers = 0;
    loop {
        let mut line = String::new();
        let read = stdout
            .read_line(&mut line)
            .map_err(|err| format!("stdout: {err}"))?;
        if read == 0 {
            return if headers == 0 {
                Ok(None)
            } else {
                Err("stdout closed inside a frame's headers".to_owned())
            };
        }
        headers += 1;
        if line == "\r\n" || line == "\n" {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(format!("not a protocol header: {line:?}"));
        };
        if !name.eq_ignore_ascii_case("content-length") {
            return Err(format!("not a protocol header: {line:?}"));
        }
        length = Some(
            value
                .trim()
                .parse::<usize>()
                .map_err(|err| format!("{line:?}: {err}"))?,
        );
    }
    let mut body = vec![0; length.ok_or("a frame without Content-Length")?];
    stdout
        .read_exact(&mut body)
        .map_err(|err| format!("a frame's body: {err}"))?;
    serde_json::from_slice(&body)
        .map(Some)
        .map_err(|err| format!("a frame's body is not JSON: {err}"))
}

/// The `file:` URI an editor sends for `path`. On Windows `path` is
/// `\\?\C:\...` (`canonicalize`): pasted after `file://` it is no URI, the
/// server refuses `initialize` and drops the session's notifications, so the
/// URI is built as the server reads it back.
fn uri(path: &Path) -> String {
    opentide_lsp::uri::path_to_uri(&path.display().to_string())
}

/// Opens the rule in a session: the reply to `initialize`, the diagnostics
/// the server publishes for the rule, and the exit code.
fn session(cwd: &Path, flags: &[&str], rule: &Path) -> (Value, Value, Option<i32>) {
    let mut server = Server::start(cwd, flags);
    let init = server.initialize(cwd);
    server.send(&json!({"jsonrpc": "2.0", "method": "initialized", "params": {}}));
    server.send(
        &json!({"jsonrpc": "2.0", "method": "textDocument/didOpen", "params": {
            "textDocument": {"uri": uri(rule), "languageId": "opentide-yaml",
                             "version": 1, "text": RULE}}}),
    );
    let published = server.read(&format!("the diagnostics of {}", uri(rule)));
    let code = server.shut_down();
    (init, published, code)
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
        let (init, published, code) = session(&root, flags, &rule);
        assert_eq!(init["id"], 1);
        assert_eq!(init["result"]["serverInfo"]["name"], "opentide-lsp");
        assert_eq!(init["result"]["capabilities"]["hoverProvider"], true);
        // The client can tell `opentide lsp start` from the bare binary.
        let host = &init["result"]["capabilities"]["experimental"]["opentide"];
        assert_eq!(host["host"]["name"], "opentide", "{flags:?}");
        // The server builds the field catalogs and the configuration schemas
        // from opentide-schema itself (#926): `lsp start` hands it neither.
        assert_eq!(host["catalog"], "models");
        assert_eq!(host["configurationChecks"], true);
        assert_eq!(host["configurationSchemas"], true);
        assert_eq!(published["method"], "textDocument/publishDiagnostics");
        assert_eq!(published["params"]["uri"], uri(&rule));
        let codes: Vec<&str> = published["params"]["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|item| item["code"].as_str())
            .collect();
        assert!(codes.contains(&"kql_unknown_operator"), "{codes:?}");
        assert_eq!(code, Some(0));
        drop(dir);
    }
}

#[test]
fn closing_stdin_ends_the_server_with_1() {
    let dir = tempfile::tempdir().unwrap();
    let mut server = Server::start(dir.path(), &[]);
    assert_eq!(server.close_stdin(), Some(1));
    // Not a terminal: an editor, which needs no hint.
    assert_eq!(server.stderr(), "");
    drop(server);
    drop(dir);
}

/// The harness gives up on a silent server and says what it waited for:
/// a session the server ignores fails here, not at the runner's timeout.
#[test]
fn a_server_that_ignores_the_session_fails_the_test_not_hangs_it() {
    let dir = tempfile::tempdir().unwrap();
    let started = Instant::now();
    let failure = std::panic::catch_unwind(|| {
        let mut server = Server::start(dir.path(), &[]);
        server.patience = Duration::from_millis(500);
        // Nothing sent: the server waits for `initialize`.
        server.read("a message the server never sends")
    })
    .expect_err("the server sent nothing");
    assert!(started.elapsed() < PATIENCE, "{:?}", started.elapsed());
    let message = failure.downcast_ref::<String>().unwrap();
    assert!(
        message.contains("while the test waited for a message the server never sends"),
        "{message}"
    );
    drop(dir);
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
    let (_, published, code) = session(&root, &[], &rule);
    assert_eq!(published["method"], "textDocument/publishDiagnostics");
    let messages: Vec<&str> = published["params"]["diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|item| item["message"].as_str())
        .filter(|message| message.contains("tlp"))
        .collect();
    assert!(messages.is_empty(), "{messages:?}");
    assert_eq!(code, Some(0));
    drop(dir);
}

const SHARING: &str = r#"[[misp]]
name = "misp-internal"
url = "https://misp.example"
api_key = "${MISP_KEY}"
max_tlp = "amber"
distribution = "this-community"
"#;

/// #730: a configuration buffer gets what opentide's configuration models
/// find, on the key they name, an override in a nested workspace is checked
/// against its parent instance, and completion comes from the schemas the
/// host generates.
#[test]
fn configuration_toml_is_checked_with_opentides_models() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    let sharing = root.join(".opentide/configurations/sharing.toml");
    let lab = root.join("lab/.opentide/configurations/sharing.toml");
    std::fs::create_dir_all(sharing.parent().unwrap()).unwrap();
    std::fs::create_dir_all(lab.parent().unwrap()).unwrap();
    // The parent instance holds misp-internal: an override in a nested
    // workspace may restate only `name` and what it changes.
    std::fs::write(
        &sharing,
        SHARING.replace("distribution = \"this-community\"\n", ""),
    )
    .unwrap();
    let mut server = Server::start(&root, &[]);
    server.initialize(&root);
    server.send(&json!({"jsonrpc": "2.0", "method": "initialized", "params": {}}));
    let open = |server: &mut Server, path: &Path, text: &str| {
        server.send(
            &json!({"jsonrpc": "2.0", "method": "textDocument/didOpen", "params": {
                "textDocument": {"uri": uri(path), "languageId": "toml",
                                 "version": 1, "text": text}}}),
        );
    };

    open(&mut server, &sharing, SHARING);
    let diagnostics = server.until_diagnostics(&uri(&sharing));
    let found: Vec<(&str, u64)> = diagnostics
        .as_array()
        .unwrap()
        .iter()
        .map(|item| {
            (
                item["code"].as_str().unwrap(),
                item["range"]["start"]["line"].as_u64().unwrap(),
            )
        })
        .collect();
    assert_eq!(found, [("unknown_key", 5)], "{diagnostics}");

    open(
        &mut server,
        &lab,
        "[[misp]]\nname = \"misp-internal\"\nmax_tlp = \"red\"\n",
    );
    assert_eq!(server.until_diagnostics(&uri(&lab)), json!([]));

    server.send(
        &json!({"jsonrpc": "2.0", "id": 2, "method": "textDocument/completion", "params": {
            "textDocument": {"uri": uri(&sharing)},
            "position": {"line": 4, "character": "max_tlp = ".len()}}}),
    );
    let reply = server.until_reply(2);
    let labels: Vec<&str> = reply["result"]
        .as_array()
        .expect("a completion list")
        .iter()
        .map(|item| item["label"].as_str().unwrap())
        .collect();
    assert_eq!(
        labels,
        [
            r#""clear""#,
            r#""green""#,
            r#""amber""#,
            r#""amber+strict""#,
            r#""red""#
        ]
    );

    assert_eq!(server.shut_down(), Some(0));
    drop(server);
    drop(dir);
}

/// Ctrl-C stops a server a person started at once, with 130: the server
/// blocks on stdin, so the run gets no grace to stop on its own.
#[cfg(unix)]
#[test]
fn ctrl_c_stops_the_server_at_once_with_130() {
    use rustix::process::{Pid, Signal, kill_process};
    let dir = tempfile::tempdir().unwrap();
    let mut server = Server::start(dir.path(), &[]);
    // Serving: the reply to `initialize` comes after the handler is in place.
    assert_eq!(server.initialize(dir.path())["id"], 1);
    let started = Instant::now();
    let pid = Pid::from_raw(i32::try_from(server.child.id()).unwrap()).unwrap();
    kill_process(pid, Signal::INT).unwrap();
    // stdin stays open: the signal alone stops the server.
    let code = server.wait();
    // Well inside the 5-second grace a run that polls gets.
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(code, Some(130));
    assert_eq!(server.stderr(), "error: interrupted\n");
    drop(server);
    drop(dir);
}
