//! `opentide mcp start` while a tool call is running: the `opentide` binary
//! serves MCP on stdio, and `run_query` (`live: true`) goes to a stand-in
//! Elasticsearch that takes the request and never answers, so the call runs
//! until something stops it. Meanwhile the server answers a `ping`, and
//! `notifications/cancelled` stops the call: the request is dropped at the
//! tenant, the call answers nothing (MCP's outcome for a cancelled request),
//! and the next call runs and reaches the tenant uninterrupted.
//!
//! Every wait gives up after [`PATIENCE`] and says what it waited for: the
//! query's own timeout (120 s) is longer, so a server that stays busy fails
//! the test instead of passing late.

#![expect(
    clippy::unwrap_used,
    reason = "a test helper: a stand-in or a child that fails is a failure"
)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::process::{ChildStdin, Command, Stdio};
use std::sync::mpsc::{Receiver, channel};
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

/// The server's stdin and the messages it wrote, line by line.
struct Client {
    stdin: ChildStdin,
    messages: Receiver<Value>,
    /// Every message read so far.
    read: Vec<Value>,
}

impl Client {
    fn send(&mut self, message: &Value) {
        writeln!(self.stdin, "{message}").unwrap();
        self.stdin.flush().unwrap();
    }

    /// The answer to request `id`.
    fn answer(&mut self, id: i64, waiting_for: &str) -> Value {
        let deadline = Instant::now() + PATIENCE;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            let Ok(message) = self.messages.recv_timeout(left) else {
                panic!(
                    "no answer to {waiting_for} within {PATIENCE:?}; read: {:?}",
                    self.read
                )
            };
            self.read.push(message.clone());
            if message["id"] == id {
                return message;
            }
        }
    }
}

fn expect(events: &Receiver<Seen>, wanted: &Seen) {
    let seen = events.recv_timeout(PATIENCE);
    assert_eq!(seen.as_ref().ok(), Some(wanted), "{seen:?}");
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

#[test]
fn a_running_tool_call_leaves_the_server_answering_and_is_cancelled() {
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

    let mut child = Command::new(env!("CARGO_BIN_EXE_opentide-cli"))
        .args(["mcp", "start"])
        .current_dir(&ws)
        .env_clear()
        .env("HOME", &home)
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
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
    let mut client = Client {
        stdin: child.stdin.take().unwrap(),
        messages,
        read: Vec::new(),
    };

    client.send(
        &json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "test", "version": "0"},
        }}),
    );
    client.answer(1, "initialize");
    client.send(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}));

    // A call that runs until it is stopped.
    client.send(&run_query(2));
    expect(&tenant, &Seen::Request("POST /_query HTTP/1.1".into()));

    // The server reads the client meanwhile.
    client.send(&ping(3));
    let pong = client.answer(3, "a ping while a tool call runs");
    assert_eq!(pong["result"], json!({}), "{pong}");
    client.send(&cancel(2));
    expect(&tenant, &Seen::Closed);

    // The next call is not interrupted: it reaches the tenant too.
    client.send(&run_query(4));
    expect(&tenant, &Seen::Request("POST /_query HTTP/1.1".into()));
    client.send(&cancel(4));
    expect(&tenant, &Seen::Closed);
    client.send(&ping(5));
    client.answer(5, "a ping after two cancelled calls");
    assert!(
        client
            .read
            .iter()
            .all(|message| message["id"] != 2 && message["id"] != 4),
        "a cancelled call answers nothing: {:?}",
        client.read
    );

    drop(client);
    let deadline = Instant::now() + PATIENCE;
    while child.try_wait().unwrap().is_none() {
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("the server did not exit {PATIENCE:?} after its stdin closed");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}
