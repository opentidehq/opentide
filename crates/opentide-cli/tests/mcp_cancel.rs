//! `opentide mcp start` while a tool call is running: the `opentide` binary
//! serves MCP on stdio, and `run_query` (`live: true`) goes to a stand-in
//! Elasticsearch that takes the request and never answers, so the call runs
//! until something stops it. Meanwhile the server answers a `ping`, and
//! `notifications/cancelled` stops the call: the request is dropped at the
//! tenant, the call answers nothing (MCP's outcome for a cancelled request),
//! and the next call runs and reaches the tenant uninterrupted. A call still
//! running when the client closes stdin is stopped too, and the server exits.
//!
//! Every wait gives up after [`PATIENCE`], says what it waited for and shows
//! the server's stderr: the query's own timeout (120 s) is longer, so a
//! server that stays busy fails the test instead of passing late.

#![expect(
    clippy::unwrap_used,
    reason = "a test helper: a stand-in or a child that fails is a failure"
)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{Receiver, channel};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

/// How long the test waits for each step.
const PATIENCE: Duration = Duration::from_secs(60);

/// What the stand-in saw.
#[derive(Debug, PartialEq)]
enum Seen {
    /// A request's first line.
    Request(String),
    /// A connection the client closed.
    Closed,
}

/// A stand-in Elasticsearch that reads each request's head, reports it,
/// holds the connection open without answering and reports when the client
/// closes it. Its address.
fn stalling_tenant() -> (String, Receiver<Seen>) {
    let (seen, events) = channel();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = format!("http://{}", listener.local_addr().unwrap());
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let seen = seen.clone();
            std::thread::spawn(move || {
                let mut head = Vec::new();
                let mut byte = [0_u8; 1];
                while !head.ends_with(b"\r\n\r\n") && stream.read(&mut byte).unwrap_or(0) == 1 {
                    head.push(byte[0]);
                }
                let first = String::from_utf8_lossy(&head)
                    .lines()
                    .next()
                    .unwrap_or_default()
                    .to_owned();
                let _ = seen.send(Seen::Request(first));
                // The body, then nothing until the client hangs up.
                let mut rest = [0_u8; 1024];
                while stream.read(&mut rest).unwrap_or(0) > 0 {}
                let _ = seen.send(Seen::Closed);
            });
        }
    });
    (address, events)
}

/// The server, its stdin, what it wrote and what the stand-in saw.
struct Session {
    child: Child,
    stdin: Option<ChildStdin>,
    messages: Receiver<Value>,
    /// Every message read so far.
    read: Vec<Value>,
    stderr: Arc<Mutex<Vec<u8>>>,
    tenant: Receiver<Seen>,
}

impl Session {
    fn fail(&self, what: &str) -> ! {
        let stderr = self.stderr.lock().unwrap();
        panic!(
            "{what} within {PATIENCE:?}\nread: {:?}\nstderr:\n{}",
            self.read,
            String::from_utf8_lossy(&stderr)
        )
    }

    fn send(&mut self, message: &Value) {
        let stdin = self.stdin.as_mut().unwrap();
        writeln!(stdin, "{message}").unwrap();
        stdin.flush().unwrap();
    }

    /// The answer to request `id`.
    fn answer(&mut self, id: i64, waiting_for: &str) -> Value {
        let deadline = Instant::now() + PATIENCE;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            let Ok(message) = self.messages.recv_timeout(left) else {
                self.fail(&format!("no answer to {waiting_for}"))
            };
            self.read.push(message.clone());
            if message["id"] == id {
                return message;
            }
        }
    }

    /// The stand-in's next event, which must be `wanted`.
    fn expect(&self, wanted: &Seen) {
        match self.tenant.recv_timeout(PATIENCE) {
            Ok(seen) if seen == *wanted => {}
            seen => self.fail(&format!("the tenant saw {seen:?}, not {wanted:?},")),
        }
    }

    /// Closes stdin and waits for the exit.
    fn close(&mut self) {
        self.stdin = None;
        let deadline = Instant::now() + PATIENCE;
        while self.child.try_wait().unwrap().is_none() {
            if Instant::now() > deadline {
                let _ = self.child.kill();
                self.fail("the server did not exit after its stdin closed");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

fn run_query(id: i64) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": {
        "name": "run_query",
        "arguments": {"query": "FROM x", "platform": "elastic", "live": true},
    }})
}

fn cancel(id: i64) -> Value {
    json!({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {
        "requestId": id, "reason": "the user stopped it",
    }})
}

fn ping(id: i64) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": "ping"})
}

fn start() -> (Session, tempfile::TempDir) {
    let (address, tenant) = stalling_tenant();
    let scratch = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(scratch.path()).unwrap();
    let ws = root.join("ws");
    let home = root.join("home");
    let platforms = ws.join(".opentide/configurations/platforms");
    std::fs::create_dir_all(&platforms).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(
        platforms.join("elastic.toml"),
        format!(
            "[platform]\nenabled = true\nname = \"Elastic Security\"\n\n\
             [[tenants]]\nname = \"stalls\"\nstrategies = [\"PREVIEW\"]\n[tenants.setup]\n\
             url = \"{address}\"\nelasticsearch_url = \"{address}\"\napi_key = \"key\"\n"
        ),
    )
    .unwrap();

    let mut command = Command::new(env!("CARGO_BIN_EXE_opentide-cli"));
    command
        .args(["mcp", "start"])
        .current_dir(&ws)
        .env_clear()
        .env("HOME", &home)
        .env("PATH", std::env::var_os("PATH").unwrap_or_default());
    // Winsock does not start without them.
    for name in ["SYSTEMROOT", "USERPROFILE"] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let (sender, messages) = channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            let Ok(line) = line else { return };
            if sender.send(serde_json::from_str(&line).unwrap()).is_err() {
                return;
            }
        }
    });
    let stderr = Arc::new(Mutex::new(Vec::new()));
    let mut pipe = child.stderr.take().unwrap();
    let kept = Arc::clone(&stderr);
    std::thread::spawn(move || {
        let mut chunk = [0_u8; 4096];
        while let Ok(read @ 1..) = pipe.read(&mut chunk) {
            kept.lock().unwrap().extend_from_slice(&chunk[..read]);
        }
    });
    let mut session = Session {
        stdin: child.stdin.take(),
        child,
        messages,
        read: Vec::new(),
        stderr,
        tenant,
    };
    session.send(
        &json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "test", "version": "0"},
        }}),
    );
    session.answer(1, "initialize");
    session.send(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}));
    (session, scratch)
}

#[test]
fn a_running_tool_call_leaves_the_server_answering_and_is_cancelled() {
    let (mut session, _scratch) = start();

    // A call that runs until it is stopped.
    session.send(&run_query(2));
    session.expect(&Seen::Request("POST /_query HTTP/1.1".into()));

    // The server reads the client meanwhile.
    session.send(&ping(3));
    let pong = session.answer(3, "a ping while a tool call runs");
    assert_eq!(pong["result"], json!({}), "{pong}");
    session.send(&cancel(2));
    session.expect(&Seen::Closed);

    // The next call is not interrupted: it reaches the tenant too.
    session.send(&run_query(4));
    session.expect(&Seen::Request("POST /_query HTTP/1.1".into()));
    session.send(&cancel(4));
    session.expect(&Seen::Closed);
    session.send(&ping(5));
    session.answer(5, "a ping after two cancelled calls");
    assert!(
        session
            .read
            .iter()
            .all(|message| message["id"] != 2 && message["id"] != 4),
        "a cancelled call answers nothing: {:?}",
        session.read
    );

    // A call still running when the client leaves is stopped, and the
    // server exits.
    session.send(&run_query(6));
    session.expect(&Seen::Request("POST /_query HTTP/1.1".into()));
    session.close();
    session.expect(&Seen::Closed);
}
