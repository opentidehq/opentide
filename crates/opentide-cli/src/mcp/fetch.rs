//! `OPENTIDE_FETCH=stdio`: the WASI build's MCP server asks its client to make
//! each tenant request.
//!
//! WASI gives the module no sockets, so a tool that reaches a tenant
//! (`validate_query` and `run_query` with `live`, `deploy_rule` without
//! `dry_run`) fails with `network_unavailable`. With `OPENTIDE_FETCH=stdio`
//! the server instead writes each request to its client as a JSON-RPC 2.0
//! request line of its own on stdout, method `opentide/fetch`, with the params
//! [`opentide serve`](crate::serve::fetch) sends, interleaved with its MCP
//! messages, and reads the answer, a response with the same id, from stdin,
//! interleaved with the client's MCP messages (`docs/mcp/index.md`).
//!
//! - **Ids** are the strings `opentide-fetch-1`, `opentide-fetch-2`…, which no
//!   MCP client id takes by accident.
//! - **While a request waits**, the server has no thread to read stdin with
//!   (WASI has none): the tool call reads it itself, a line at a time. A line
//!   that is the answer is handed to the call; every other line is the
//!   client's MCP message, kept in order and read by the server once the call
//!   returns, as it would have read it had it arrived then. A
//!   `notifications/cancelled` for the call in progress also stops it at once
//!   (the request is withdrawn, and the call ends interrupted).
//! - **A request withdrawn** (the call was cancelled) is announced with MCP's
//!   own `notifications/cancelled {requestId}`. An answer that arrives for a
//!   withdrawn or unknown `opentide-fetch-` id is dropped, never read as an MCP
//!   message.
//! - **End of input** with a request unanswered fails the call: its tool
//!   error says the client closed its input before answering.
//!
//! Only the WASI build does any of this (`mcp::serve` reads the variable
//! there); natively the variable is ignored and a tenant is reached with
//! opentide's own HTTP client.

use std::collections::VecDeque;
use std::io::{BufRead, Write};
use std::sync::{Arc, Mutex, OnceLock, PoisonError, Weak};

use rmcp::model::NumberOrString;
use serde::Deserialize as _;
use serde_json::Value;

use crate::env::Env;
use crate::json::Json;
use crate::serve::fetch::{ClientFetch, Fetcher, Wire};

/// The variable that turns the bridge on (WASI only).
pub const VARIABLE: &str = "OPENTIDE_FETCH";

/// Its only value.
pub const STDIO: &str = "stdio";

/// The prefix of the server's request ids.
pub const ID_PREFIX: &str = "opentide-fetch-";

/// Whether *env* asks for tenant requests over stdio.
pub fn requested(env: &Env) -> bool {
    env.get(VARIABLE) == Some(STDIO)
}

/// How a request is withdrawn: MCP's cancellation notification.
fn withdrawal(id: &str) -> Json {
    Json::object([
        ("jsonrpc", Json::str("2.0")),
        ("method", Json::str("notifications/cancelled")),
        (
            "params",
            Json::object([
                ("requestId", Json::str(id)),
                ("reason", Json::str("opentide withdrew its request")),
            ]),
        ),
    ])
}

/// The dialect MCP's stdio speaks.
const WIRE: Wire = Wire {
    prefix: ID_PREFIX,
    withdraw: withdrawal,
    gone: "the client closed its input before answering an opentide/fetch request \
           (OPENTIDE_FETCH=stdio): it must answer each one on stdin",
};

/// The request the server is handling.
struct Current {
    id: NumberOrString,
    /// As a `run` names it in the request's params: the id's JSON text.
    run: String,
}

struct Inner {
    input: Box<dyn BufRead + Send>,
    output: Box<dyn Write + Send>,
    /// The client's MCP lines read while a request waited for its answer.
    queued: VecDeque<Vec<u8>>,
    /// The input ended, or the output failed: nothing more will be answered.
    ended: bool,
    current: Option<Current>,
    /// The client cancelled the request in progress.
    cancelled: bool,
}

/// stdin and stdout shared between the MCP server's reader and the tenant
/// requests a tool call makes while it runs.
pub struct Bridge {
    inner: Mutex<Inner>,
    fetcher: OnceLock<Weak<Fetcher>>,
}

impl std::fmt::Debug for Bridge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Bridge").finish_non_exhaustive()
    }
}

/// What a line from the client is to the bridge.
enum Line {
    /// The answer to a request of ours: its id and a result or an error.
    Answer(String, Result<Json, Json>),
    /// Anything else: the client's MCP message.
    Message,
}

fn classify(line: &[u8]) -> Line {
    let Ok(message) = serde_json::from_slice::<Value>(line) else {
        return Line::Message;
    };
    if message.get("method").is_some() {
        return Line::Message;
    }
    let Some(id) = message
        .get("id")
        .and_then(Value::as_str)
        .filter(|id| id.starts_with(ID_PREFIX))
    else {
        return Line::Message;
    };
    let reply = match (message.get("result"), message.get("error")) {
        (Some(result), None) => Json::deserialize(result).map_err(|_| malformed("result")),
        (None, Some(error)) => Err(Json::deserialize(error).unwrap_or_else(|_| malformed("error"))),
        _ => Err(malformed("answer")),
    };
    Line::Answer(id.to_owned(), reply)
}

/// An error object for an answer that is neither a result nor an error.
fn malformed(what: &str) -> Json {
    Json::object([
        (
            "message",
            Json::Str(format!(
                "the client's answer to opentide/fetch has no valid {what}"
            )),
        ),
        ("data", Json::object([("kind", Json::str("answer"))])),
    ])
}

impl Bridge {
    /// A bridge reading the client's lines from *input* and writing to *output*.
    pub fn new(
        input: impl BufRead + Send + 'static,
        output: impl Write + Send + 'static,
    ) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(Inner {
                input: Box::new(input),
                output: Box::new(output),
                queued: VecDeque::new(),
                ended: false,
                current: None,
                cancelled: false,
            }),
            fetcher: OnceLock::new(),
        })
    }

    /// The fetcher whose requests this bridge carries.
    pub fn fetcher(self: &Arc<Self>) -> Arc<Fetcher> {
        let (send, run, pump, cancelled) = (
            Arc::downgrade(self),
            Arc::downgrade(self),
            Arc::downgrade(self),
            Arc::downgrade(self),
        );
        let fetcher = Fetcher::with_wire(
            WIRE,
            move |message: &str| {
                if let Some(bridge) = send.upgrade() {
                    bridge.write(message);
                }
            },
            move || {
                let bridge = run.upgrade()?;
                let inner = bridge.state();
                inner.current.as_ref().map(|current| current.run.clone())
            },
            move || pump.upgrade().is_some_and(|bridge| bridge.pump()),
            move || {
                cancelled
                    .upgrade()
                    .is_some_and(|bridge| bridge.state().cancelled)
            },
        );
        let _first = self.fetcher.set(Arc::downgrade(&fetcher));
        fetcher
    }

    /// Makes every tenant's transport ask the client, until the guard drops.
    pub fn install(self: &Arc<Self>) -> (Arc<Fetcher>, opentide_connectors::transport::Installed) {
        let fetcher = self.fetcher();
        let installed = opentide_connectors::transport::install(ClientFetch::new(&fetcher));
        (fetcher, installed)
    }

    fn state(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn fetcher_now(&self) -> Option<Arc<Fetcher>> {
        self.fetcher.get().and_then(Weak::upgrade)
    }

    /// Writes one line to the client; a failed write ends the bridge.
    fn write(&self, message: &str) {
        let mut inner = self.state();
        if inner.ended {
            return;
        }
        let mut line = Vec::with_capacity(message.len() + 1);
        line.extend_from_slice(message.as_bytes());
        line.push(b'\n');
        if inner
            .output
            .write_all(&line)
            .and_then(|()| inner.output.flush())
            .is_err()
        {
            inner.ended = true;
        }
    }

    /// The client's next line, read here: `None` at the end of input. A last
    /// line without its newline is framed.
    fn read(inner: &mut Inner) -> Option<Vec<u8>> {
        if inner.ended {
            return None;
        }
        let mut line = Vec::new();
        match inner.input.read_until(b'\n', &mut line) {
            Ok(0) | Err(_) => {
                inner.ended = true;
                None
            }
            Ok(_) => {
                if line.last() != Some(&b'\n') {
                    line.push(b'\n');
                }
                Some(line)
            }
        }
    }

    /// Reads one line of the client's input for a call waiting for its
    /// request's answer, and acts on it: an answer reaches the call, the
    /// client's cancellation of the call in progress is noted, and every
    /// other message is kept for the server. Whether a line came; at the end
    /// of input every request waiting fails.
    fn pump(&self) -> bool {
        let line = {
            let mut inner = self.state();
            Self::read(&mut inner)
        };
        let Some(line) = line else {
            if let Some(fetcher) = self.fetcher_now() {
                fetcher.close();
            }
            return false;
        };
        match classify(&line) {
            Line::Answer(id, reply) => {
                if let Some(fetcher) = self.fetcher_now() {
                    // A late answer to a withdrawn request is not pending: dropped.
                    let _delivered = fetcher.deliver(&id, reply);
                }
            }
            Line::Message => {
                let mut inner = self.state();
                if cancels(&line, inner.current.as_ref()) {
                    inner.cancelled = true;
                }
                inner.queued.push_back(line);
            }
        }
        true
    }

    /// The next line for the MCP server: what was kept while a call waited,
    /// else what the client sends next. An answer to a request nobody awaits
    /// (late, after its withdrawal) is dropped.
    pub fn next_line(&self) -> Option<Vec<u8>> {
        loop {
            let line = {
                let mut inner = self.state();
                match inner.queued.pop_front() {
                    Some(line) => line,
                    None => Self::read(&mut inner)?,
                }
            };
            if matches!(classify(&line), Line::Answer(..)) {
                continue;
            }
            return Some(line);
        }
    }

    /// The server hands the request *id* to its handlers: tenant requests it
    /// makes name it, and a cancellation of it stops them.
    pub fn begin(&self, id: Option<NumberOrString>) {
        let mut inner = self.state();
        inner.cancelled = false;
        inner.current = id.map(|id| Current {
            run: serde_json::to_string(&id).unwrap_or_default(),
            id,
        });
    }
}

/// Whether *line* is `notifications/cancelled` for *current*.
fn cancels(line: &[u8], current: Option<&Current>) -> bool {
    let Some(current) = current else {
        return false;
    };
    let Ok(message) = serde_json::from_slice::<Value>(line) else {
        return false;
    };
    message.get("method").and_then(Value::as_str) == Some("notifications/cancelled")
        && message
            .get("params")
            .and_then(|params| params.get("requestId"))
            .and_then(|id| serde_json::from_value::<NumberOrString>(id.clone()).ok())
            .is_some_and(|id| id == current.id)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::sync::Arc;

    use serde_json::json;
    use tokio::sync::oneshot::error::TryRecvError;

    use super::*;

    /// What the bridge wrote, shared with the test.
    #[derive(Clone, Default)]
    struct Written(Arc<Mutex<Vec<u8>>>);

    impl Write for Written {
        fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(data);
            Ok(data.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl Written {
        fn lines(&self) -> Vec<Value> {
            String::from_utf8(self.0.lock().unwrap().clone())
                .unwrap()
                .lines()
                .map(|line| serde_json::from_str(line).unwrap())
                .collect()
        }
    }

    fn lines(messages: &[Value]) -> Cursor<Vec<u8>> {
        let mut text = String::new();
        for message in messages {
            text.push_str(&message.to_string());
            text.push('\n');
        }
        Cursor::new(text.into_bytes())
    }

    fn bridge(input: &[Value]) -> (Arc<Bridge>, Arc<Fetcher>, Written) {
        let written = Written::default();
        let bridge = Bridge::new(lines(input), written.clone());
        let fetcher = bridge.fetcher();
        (bridge, fetcher, written)
    }

    fn params() -> Json {
        Json::object([
            ("platform", Json::str("elastic")),
            ("method", Json::str("GET")),
            ("url", Json::str("https://tenant.example/_cluster/health")),
        ])
    }

    #[test]
    fn the_variable_is_read_as_stdio_alone() {
        let env = |value: &str| Env::from_pairs([("OPENTIDE_FETCH", value)]);
        assert!(requested(&env("stdio")));
        for other in ["", "1", "true", "STDIO", "stdio "] {
            assert!(!requested(&env(other)), "{other:?}");
        }
        assert!(!requested(&Env::from_pairs::<&str, &str>([])));
    }

    #[test]
    fn a_request_is_a_json_rpc_line_with_a_prefixed_string_id() {
        let (_bridge, fetcher, written) = bridge(&[]);
        let (first, _) = fetcher.ask(params());
        let (second, _) = fetcher.ask(params());
        assert_eq!(first, "opentide-fetch-1");
        assert_eq!(second, "opentide-fetch-2");
        let sent = written.lines();
        assert_eq!(sent.len(), 2, "one line a request: {sent:?}");
        assert_eq!(sent[0]["jsonrpc"], "2.0");
        assert_eq!(sent[0]["id"], "opentide-fetch-1");
        assert_eq!(sent[0]["method"], "opentide/fetch");
        assert_eq!(
            sent[0]["params"]["url"],
            "https://tenant.example/_cluster/health"
        );
        assert_eq!(sent[1]["id"], "opentide-fetch-2");
        // One message a line: no newline inside a message.
        let raw = String::from_utf8(written.0.lock().unwrap().clone()).unwrap();
        assert_eq!(raw.matches('\n').count(), 2, "{raw}");
    }

    #[test]
    fn the_answer_is_found_among_the_clients_own_messages() {
        let ping = json!({"jsonrpc": "2.0", "id": 7, "method": "ping"});
        let progress = json!({"jsonrpc": "2.0", "method": "notifications/progress", "params": {}});
        // A client response (to a request of the server's own, with a number id)
        // is not ours: it is the client's message.
        let theirs = json!({"jsonrpc": "2.0", "id": 5, "result": {}});
        let answer = json!({"jsonrpc": "2.0", "id": "opentide-fetch-1",
            "result": {"status": 200, "headers": [], "body": null}});
        let after = json!({"jsonrpc": "2.0", "id": 8, "method": "tools/list"});
        let (bridge, fetcher, _written) = bridge(&[
            ping.clone(),
            progress.clone(),
            theirs.clone(),
            answer,
            after.clone(),
        ]);
        let (_id, mut reply) = fetcher.ask(params());
        for _ in 0..4 {
            assert!(bridge.pump());
        }
        let delivered = reply.try_recv().expect("answered").expect("a result");
        assert_eq!(delivered.get("status"), Some(&Json::Int(200)));
        // Everything that was not the answer reaches the server, in order,
        // and the one line after the answer is still unread.
        let read = |line: Option<Vec<u8>>| -> Value {
            serde_json::from_slice(&line.expect("a line")).unwrap()
        };
        assert_eq!(read(bridge.next_line()), ping);
        assert_eq!(read(bridge.next_line()), progress);
        assert_eq!(read(bridge.next_line()), theirs);
        assert_eq!(read(bridge.next_line()), after);
        assert_eq!(bridge.next_line(), None);
    }

    #[test]
    fn an_error_answer_reaches_the_request() {
        let answer = json!({"jsonrpc": "2.0", "id": "opentide-fetch-1",
            "error": {"code": -32000, "message": "refused", "data": {"kind": "connect"}}});
        let (bridge, fetcher, _written) = bridge(&[answer]);
        let (_id, mut reply) = fetcher.ask(params());
        assert!(bridge.pump());
        let error = reply.try_recv().expect("answered").expect_err("an error");
        assert_eq!(error.get("message"), Some(&Json::str("refused")));
    }

    #[test]
    fn an_answer_with_neither_result_nor_error_fails_the_request() {
        let answer = json!({"jsonrpc": "2.0", "id": "opentide-fetch-1"});
        let (bridge, fetcher, _written) = bridge(&[answer]);
        let (_id, mut reply) = fetcher.ask(params());
        assert!(bridge.pump());
        let error = reply.try_recv().expect("answered").expect_err("an error");
        assert_eq!(
            error.get("data").and_then(|data| data.get("kind")),
            Some(&Json::str("answer"))
        );
    }

    #[test]
    fn a_late_answer_is_dropped_and_never_read_as_an_mcp_message() {
        let late = json!({"jsonrpc": "2.0", "id": "opentide-fetch-9", "result": {"status": 200}});
        let ping = json!({"jsonrpc": "2.0", "id": 1, "method": "ping"});
        let (bridge, fetcher, _written) = bridge(&[late.clone(), ping.clone()]);
        // Pumped while another request waits.
        let (_id, mut reply) = fetcher.ask(params());
        assert!(bridge.pump());
        assert!(matches!(reply.try_recv(), Err(TryRecvError::Empty)));
        assert!(bridge.pump());
        assert_eq!(
            serde_json::from_slice::<Value>(&bridge.next_line().unwrap()).unwrap(),
            ping
        );
        // And when the server itself reads it, nobody awaiting.
        let (bridge, _fetcher, _written) = self::bridge(&[late, ping.clone()]);
        assert_eq!(
            serde_json::from_slice::<Value>(&bridge.next_line().unwrap()).unwrap(),
            ping
        );
    }

    #[test]
    fn the_end_of_input_fails_every_request_waiting() {
        let (bridge, fetcher, _written) = bridge(&[]);
        let (_id, mut reply) = fetcher.ask(params());
        assert!(!bridge.pump(), "no line came");
        assert!(matches!(reply.try_recv(), Err(TryRecvError::Closed)));
        // A request made after the end fails at once too, once pumped.
        let (_id, mut later) = fetcher.ask(params());
        assert!(!bridge.pump());
        assert!(matches!(later.try_recv(), Err(TryRecvError::Closed)));
        assert_eq!(bridge.next_line(), None);
        assert!(WIRE.gone.contains("closed its input"));
    }

    #[test]
    fn a_last_line_without_its_newline_is_read() {
        let written = Written::default();
        let bridge = Bridge::new(
            Cursor::new(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}".to_vec()),
            written,
        );
        let line = bridge.next_line().expect("a line");
        assert_eq!(line.last(), Some(&b'\n'));
    }

    #[test]
    fn a_withdrawn_request_is_cancelled_with_mcps_notification() {
        let (_bridge, fetcher, written) = bridge(&[]);
        let (id, reply) = fetcher.ask(params());
        // Dropping the receiver does not withdraw: the call does, by id.
        fetcher.cancel(&id);
        drop(reply);
        let sent = written.lines();
        assert_eq!(sent.len(), 2);
        assert_eq!(sent[1]["method"], "notifications/cancelled");
        assert_eq!(sent[1]["params"]["requestId"], "opentide-fetch-1");
        assert!(sent[1].get("id").is_none(), "a notification has no id");
        // Withdrawn once: a second withdrawal says nothing.
        fetcher.cancel(&id);
        assert_eq!(written.lines().len(), 2);
    }

    #[test]
    fn the_clients_cancellation_of_the_call_in_progress_is_noted_and_kept() {
        let other = json!({"jsonrpc": "2.0", "method": "notifications/cancelled",
            "params": {"requestId": 8}});
        let cancel = json!({"jsonrpc": "2.0", "method": "notifications/cancelled",
            "params": {"requestId": 7, "reason": "user"}});
        let (bridge, fetcher, _written) = bridge(&[other.clone(), cancel.clone()]);
        let _ = fetcher; // the bridge reads without one waiting
        bridge.begin(Some(NumberOrString::Number(7)));
        assert!(!bridge.state().cancelled);
        assert!(bridge.pump());
        assert!(!bridge.state().cancelled, "another request's cancellation");
        assert!(bridge.pump());
        assert!(bridge.state().cancelled);
        // Both still reach the server, which drops the answer of the call.
        for expected in [other, cancel] {
            assert_eq!(
                serde_json::from_slice::<Value>(&bridge.next_line().unwrap()).unwrap(),
                expected
            );
        }
        // The next request starts clean.
        bridge.begin(Some(NumberOrString::Number(9)));
        assert!(!bridge.state().cancelled);
    }

    #[test]
    fn the_run_is_the_calls_request_id() {
        let (bridge, _fetcher, _written) = bridge(&[]);
        bridge.begin(Some(NumberOrString::Number(3)));
        assert_eq!(
            bridge
                .state()
                .current
                .as_ref()
                .map(|current| current.run.as_str()),
            Some("3")
        );
        bridge.begin(Some(NumberOrString::String("abc".into())));
        assert_eq!(
            bridge
                .state()
                .current
                .as_ref()
                .map(|current| current.run.as_str()),
            Some("\"abc\"")
        );
        bridge.begin(None);
        assert!(bridge.state().current.is_none());
    }
}
