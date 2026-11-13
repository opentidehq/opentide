//! The JSON-RPC loop: reads requests, runs commands one at a time, writes answers.
//!
//! [`Server::receive`] takes each line on the reading thread: a parse error
//! or an invalid request is answered at once, `$/cancelRequest` and `exit`
//! act at once, and everything else is queued. [`Server::serve`] handles the
//! queue in order on its own thread, so `invalidate` takes effect after the
//! running command and before the next one. Answers go through one writer,
//! under a lock; once a write fails the client has gone and the session
//! ends. A message whose handling fails unexpectedly is answered `-32603`
//! and the loop goes on.

use std::collections::{HashMap, HashSet, VecDeque};
use std::io::Read;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use sha2::{Digest, Sha256};

use super::decode;
use super::runner::{EventSink, Job, RunOutcome, RunRequest, Runner, compact, failure};
use crate::envelope::INTERRUPTED_EXIT_CODE;
use crate::json::Json;

/// `initialize`'s `protocol`: bumped only when a message changes meaning.
pub const PROTOCOL_VERSION: i64 = 1;

/// JSON-RPC 2.0's error codes.
pub const PARSE_ERROR: i64 = -32700;
/// The message is not a request.
pub const INVALID_REQUEST: i64 = -32600;
/// No such method.
pub const METHOD_NOT_FOUND: i64 = -32601;
/// The parameters are wrong.
pub const INVALID_PARAMS: i64 = -32602;
/// The server failed handling the message.
pub const INTERNAL_ERROR: i64 = -32603;

/// Writes one message (a JSON text without its newline).
pub type Writer = Box<dyn Fn(&str) -> std::io::Result<()> + Send + Sync>;

/// The loop, shared by the reading thread, the serving thread and the runs.
#[derive(Clone)]
pub struct Server {
    inner: Arc<Inner>,
}

struct Inner {
    write: Writer,
    /// Held while writing; `true` once a write failed.
    output_closed: Mutex<bool>,
    runner: Arc<dyn Runner>,
    queue: Mutex<VecDeque<Option<Json>>>,
    ready: Condvar,
    state: Mutex<State>,
    version: String,
    /// The client's input, read on this thread when no thread reads it
    /// ([`Server::read_inline`]: the WASI build, which has no threads).
    inline: Mutex<Option<Lines<Box<dyn Read + Send>>>>,
}

/// The lines of a stream, one at a time, without their `\n`; a last line
/// without one is read at the end of input.
pub struct Lines<R> {
    source: R,
    pending: Vec<u8>,
    ended: bool,
}

impl<R: Read> Lines<R> {
    /// The lines `source` will give.
    pub fn new(source: R) -> Lines<R> {
        Lines {
            source,
            pending: Vec::new(),
            ended: false,
        }
    }

    /// The next line, reading as much as it takes; `None` at the end of
    /// input (or once reading fails).
    pub fn next_line(&mut self) -> Option<Vec<u8>> {
        let mut chunk = [0_u8; 8192];
        loop {
            if let Some(end) = self.pending.iter().position(|byte| *byte == b'\n') {
                let mut line: Vec<u8> = self.pending.drain(..=end).collect();
                line.pop();
                return Some(line);
            }
            if self.ended {
                return (!self.pending.is_empty()).then(|| std::mem::take(&mut self.pending));
            }
            match self.source.read(&mut chunk) {
                Ok(0) | Err(_) => self.ended = true,
                Ok(read) => self.pending.extend_from_slice(&chunk[..read]),
            }
        }
    }
}

#[derive(Default)]
struct State {
    /// The run in progress: its id, as a key, and its job.
    active: Option<(String, Arc<Job>)>,
    /// Ids of queued runs a cancel named: each is answered 130 when reached.
    cancelled: HashSet<String>,
    /// Ids of the runs queued and not yet reached, each as often as queued.
    queued: HashMap<String, usize>,
    shut_down: bool,
    /// Set by `exit` or the end of input: queued runs answer 130 unrun.
    closing: bool,
    digest: Option<String>,
}

/// A request id as a set member.
fn id_key(id: &Json) -> String {
    compact(id)
}

/// The last member `key` of an object, as Python's `dict` keeps it.
fn member<'a>(object: &'a Json, key: &str) -> Option<&'a Json> {
    match object {
        Json::Object(members) => members.iter().rev().find(|(k, _)| k == key).map(|(_, v)| v),
        _ => None,
    }
}

/// A path `invalidate` names: a string as is, anything else as its JSON.
fn path_text(value: &Json) -> String {
    match value {
        Json::Str(text) => text.clone(),
        other => compact(other),
    }
}

/// A protocol problem, answered with a JSON-RPC error.
struct ProtocolError(i64, &'static str);

/// `run`'s `argv`, `cwd` and `env`, or the error it is answered with.
fn run_params(params: &Json) -> Result<RunRequest, ProtocolError> {
    let Json::Object(_) = params else {
        return Err(ProtocolError(
            INVALID_PARAMS,
            "run takes an object: {argv, cwd?, env?}",
        ));
    };
    let bad_argv = ProtocolError(
        INVALID_PARAMS,
        "run needs argv: a non-empty list of strings",
    );
    let Some(Json::Array(items)) = member(params, "argv") else {
        return Err(bad_argv);
    };
    let mut argv = Vec::with_capacity(items.len());
    for item in items {
        let Json::Str(text) = item else {
            return Err(bad_argv);
        };
        argv.push(text.clone());
    }
    if argv.is_empty() {
        return Err(bad_argv);
    }
    let cwd = match member(params, "cwd") {
        None | Some(Json::Null) => None,
        Some(Json::Str(text)) => Some(text.clone()),
        Some(_) => return Err(ProtocolError(INVALID_PARAMS, "cwd must be a string")),
    };
    let env = match member(params, "env") {
        None | Some(Json::Null) => None,
        Some(Json::Object(members)) => {
            let mut pairs: Vec<(String, String)> = Vec::new();
            for (name, value) in members {
                let Json::Str(value) = value else {
                    return Err(ProtocolError(
                        INVALID_PARAMS,
                        "env must map names to strings",
                    ));
                };
                pairs.retain(|(existing, _)| existing != name);
                pairs.push((name.clone(), value.clone()));
            }
            Some(pairs)
        }
        Some(_) => {
            return Err(ProtocolError(
                INVALID_PARAMS,
                "env must map names to strings",
            ));
        }
    };
    // --json is implied. A leading copy is dropped; any other stays where it
    // is: it may be an option's value (`--query --json`) or follow `--`.
    let start = argv.iter().take_while(|token| *token == "--json").count();
    argv.drain(..start);
    if argv.is_empty() {
        return Err(ProtocolError(
            INVALID_PARAMS,
            "run needs argv: a command to run",
        ));
    }
    Ok(RunRequest { argv, cwd, env })
}

/// sha256 of `opentide --json commands`'s document without `duration_ms`,
/// its keys sorted at every level and written compactly: the digest names
/// the command tree and nothing about the run that printed it.
pub fn commands_digest(document: &Json) -> String {
    fn sorted(value: &Json) -> Json {
        match value {
            Json::Object(members) => {
                let mut members: Vec<(String, Json)> = members
                    .iter()
                    .map(|(key, value)| (key.clone(), sorted(value)))
                    .collect();
                members.sort_by(|a, b| a.0.cmp(&b.0));
                Json::Object(members)
            }
            Json::Array(items) => Json::Array(items.iter().map(sorted).collect()),
            other => other.clone(),
        }
    }
    let stable = match document {
        Json::Object(members) => Json::Object(
            members
                .iter()
                .filter(|(key, _)| key != "duration_ms")
                .cloned()
                .collect(),
        ),
        other => other.clone(),
    };
    let digest = Sha256::digest(compact(&sorted(&stable)).as_bytes());
    digest
        .iter()
        .fold(String::with_capacity(64), |mut hex, byte| {
            use std::fmt::Write;
            let _infallible = write!(hex, "{byte:02x}");
            hex
        })
}

impl Server {
    /// A server that answers through `write` and runs through `runner`;
    /// `version` is the package's, which `initialize` names.
    pub fn new(write: Writer, runner: Arc<dyn Runner>, version: &str) -> Server {
        Server {
            inner: Arc::new(Inner {
                write,
                output_closed: Mutex::new(false),
                runner,
                queue: Mutex::new(VecDeque::new()),
                ready: Condvar::new(),
                state: Mutex::new(State::default()),
                version: version.to_owned(),
                inline: Mutex::new(None),
            }),
        }
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.inner
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    // --- output ---------------------------------------------------------------------

    /// Writes `message`; once a write fails, nothing more is written and the
    /// session ends.
    pub fn send(&self, message: &str) {
        {
            let mut closed = self
                .inner
                .output_closed
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if *closed {
                return;
            }
            if (self.inner.write)(message).is_ok() {
                return;
            }
            *closed = true;
        }
        tracing::debug!("serve_output_closed");
        self.close();
    }

    fn respond(&self, id: &Json, result: &str) {
        self.send(&format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":{},\"result\":{result}}}",
            compact(id)
        ));
    }

    fn error(&self, id: &Json, code: i64, message: &str) {
        self.send(&format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":{},\"error\":{{\"code\":{code},\"message\":{}}}}}",
            compact(id),
            compact(&Json::str(message))
        ));
    }

    fn progress(&self, id: &Json, event: &str) {
        self.send(&format!(
            "{{\"jsonrpc\":\"2.0\",\"method\":\"progress\",\"params\":{{\"id\":{},\"event\":{event}}}}}",
            compact(id)
        ));
    }

    // --- input ----------------------------------------------------------------------

    /// Reads the client's input on the serving thread instead of a reading
    /// thread of its own (the WASI build, which has none): [`Server::serve`]
    /// takes a line from `source` whenever its queue is empty.
    pub fn read_inline(&self, source: Box<dyn Read + Send>) {
        *self
            .inner
            .inline
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(Lines::new(source));
    }

    /// Reads one line of the inline input ([`Server::read_inline`]) and takes
    /// it, as the reading thread does; at the end of input, closes it.
    /// Returns whether a line came. A part of the server that waits for the
    /// client's answer to a request of its own (a host-handled request)
    /// pumps until that answer is taken; the other messages queue as usual.
    /// Without inline input it reads nothing and returns `false`.
    pub fn pump(&self) -> bool {
        let line = {
            let mut inline = self
                .inner
                .inline
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            let Some(lines) = inline.as_mut() else {
                return false;
            };
            let line = lines.next_line();
            if line.is_none() {
                *inline = None;
            }
            line
        };
        match line {
            Some(line) => {
                self.receive(&line);
                true
            }
            None => {
                self.close_input();
                false
            }
        }
    }

    /// Whether the input is read on the serving thread.
    fn reads_inline(&self) -> bool {
        self.inner
            .inline
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_some()
    }

    /// Takes one line from the client, on the reading thread.
    pub fn receive(&self, line: &[u8]) {
        let text = String::from_utf8_lossy(line);
        if text.trim().is_empty() {
            return;
        }
        let message = match decode::parse(&text) {
            Ok(message) => message,
            Err(problem) => {
                self.error(&Json::Null, PARSE_ERROR, &format!("Parse error: {problem}"));
                return;
            }
        };
        if let Json::Array(_) = message {
            self.error(
                &Json::Null,
                INVALID_REQUEST,
                "Batches are not supported: send one message a line",
            );
            return;
        }
        let method = match member(&message, "method") {
            Some(Json::Str(method)) => method.clone(),
            _ => {
                let id = member(&message, "id").cloned().unwrap_or(Json::Null);
                self.error(&id, INVALID_REQUEST, "Invalid request: no method");
                return;
            }
        };
        match method.as_str() {
            "$/cancelRequest" => {
                if let Some(params @ Json::Object(_)) = member(&message, "params")
                    && let Some(id) = member(params, "id")
                {
                    self.cancel(id);
                }
                return;
            }
            "exit" => {
                self.close();
                return;
            }
            "run" => {
                if let Some(id) = member(&message, "id") {
                    *self.state().queued.entry(id_key(id)).or_default() += 1;
                }
            }
            _ => {}
        }
        self.push(Some(message));
    }

    fn push(&self, message: Option<Json>) {
        self.inner
            .queue
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push_back(message);
        self.inner.ready.notify_all();
    }

    /// The client closed its input: as `exit`.
    pub fn close_input(&self) {
        self.close();
    }

    /// Stops the running command now and runs no queued one, then leaves:
    /// each queued `run` is answered 130, as a cancelled one is.
    pub fn close(&self) {
        let active = {
            let mut state = self.state();
            state.closing = true;
            state.active.as_ref().map(|(_, job)| Arc::clone(job))
        };
        if let Some(job) = active
            && job.cancel()
        {
            self.inner.runner.interrupt();
        }
        self.push(None);
    }

    /// Cancels the `run` `id`: the running one now, a queued one when it is
    /// reached. A cancel for a run that has answered, or was never sent,
    /// changes nothing.
    pub fn cancel(&self, id: &Json) {
        let key = id_key(id);
        let job = {
            let mut state = self.state();
            match &state.active {
                Some((active, job)) if *active == key => Arc::clone(job),
                _ => {
                    if state.queued.get(&key).copied().unwrap_or_default() > 0 {
                        state.cancelled.insert(key);
                    }
                    return;
                }
            }
        };
        if job.cancel() {
            self.inner.runner.interrupt();
        }
    }

    /// How many queued runs a cancel named that have not been reached.
    pub fn pending_cancels(&self) -> usize {
        self.state().cancelled.len()
    }

    // --- the loop -------------------------------------------------------------------

    /// Handles queued messages until `exit` or the end of input. `stop` is
    /// polled while the queue is empty: when it answers true (Ctrl-C), the
    /// server closes and this returns `false`; otherwise `true`.
    pub fn serve(&self, stop: &dyn Fn() -> bool) -> bool {
        loop {
            let message = {
                let mut queue = self
                    .inner
                    .queue
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                loop {
                    if let Some(message) = queue.pop_front() {
                        break message;
                    }
                    if stop() {
                        drop(queue);
                        self.close();
                        return false;
                    }
                    if self.reads_inline() {
                        drop(queue);
                        self.pump();
                        queue = self
                            .inner
                            .queue
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner);
                        continue;
                    }
                    queue = self
                        .inner
                        .ready
                        .wait_timeout(queue, Duration::from_millis(100))
                        .unwrap_or_else(PoisonError::into_inner)
                        .0;
                }
            };
            let Some(message) = message else {
                return true;
            };
            let handled = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                self.handle(&message);
            }));
            if handled.is_err() {
                tracing::error!("serve_message_failed");
                if let Some(id) = member(&message, "id") {
                    self.error(id, INTERNAL_ERROR, "Internal error");
                }
            }
        }
    }

    fn handle(&self, message: &Json) {
        let method = match member(message, "method") {
            Some(Json::Str(method)) => method.as_str(),
            _ => return,
        };
        let id = member(message, "id");
        let params = match member(message, "params") {
            None | Some(Json::Null) => Json::Object(Vec::new()),
            Some(params) => params.clone(),
        };
        if method == "invalidate" {
            if let Some(Json::Array(paths)) = member(&params, "paths") {
                let paths: Vec<String> = paths.iter().map(path_text).collect();
                self.inner.runner.invalidate(&paths);
                tracing::debug!(paths = paths.len(), "serve_invalidated");
            }
            return;
        }
        // An unknown notification is ignored, as JSON-RPC asks.
        let Some(id) = id else { return };
        let cancelled = if method == "run" {
            let key = id_key(id);
            let mut state = self.state();
            if let Some(count) = state.queued.get_mut(&key) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    state.queued.remove(&key);
                }
            }
            // Reached: from here on a cancel acts on the running job, or not at all.
            state.cancelled.remove(&key)
        } else {
            false
        };
        if self.state().shut_down {
            self.error(id, INVALID_REQUEST, "The server is shut down; send exit");
            return;
        }
        match method {
            "initialize" => {
                let result = self.initialize();
                self.respond(id, &result);
            }
            "run" => match run_params(&params) {
                Ok(request) => {
                    let outcome = self.run(id, &request, cancelled);
                    self.respond(id, &outcome.result_text());
                }
                Err(ProtocolError(code, message)) => self.error(id, code, message),
            },
            "shutdown" => {
                self.state().shut_down = true;
                self.respond(id, "null");
            }
            other => self.error(id, METHOD_NOT_FOUND, &format!("Method not found: {other}")),
        }
    }

    fn initialize(&self) -> String {
        let known = self.state().digest.clone();
        let digest = known.unwrap_or_else(|| {
            let request = RunRequest {
                argv: vec!["commands".into()],
                ..RunRequest::default()
            };
            let runner = &self.inner.runner;
            let plan = runner.plan(&request);
            let outcome = runner.run(&request, &plan, &Arc::new(Job::default()), Arc::new(|_| {}));
            let digest = commands_digest(&outcome.document());
            self.state().digest = Some(digest.clone());
            digest
        });
        format!(
            "{{\"protocol\":{PROTOCOL_VERSION},\"version\":{},\"commands_digest\":{}}}",
            compact(&Json::str(&self.inner.version)),
            compact(&Json::str(digest))
        )
    }

    fn run(&self, id: &Json, request: &RunRequest, cancelled: bool) -> RunOutcome {
        let runner = Arc::clone(&self.inner.runner);
        let plan = runner.plan(request);
        let job = {
            let mut state = self.state();
            if state.closing || cancelled {
                return failure(&plan.words, "Interrupted", INTERRUPTED_EXIT_CODE);
            }
            let job = Arc::new(Job::default());
            state.active = Some((id_key(id), Arc::clone(&job)));
            job
        };
        let server = self.clone();
        let id_for_events = id.clone();
        let event: EventSink =
            Arc::new(move |event: String| server.progress(&id_for_events, &event));
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            runner.run(request, &plan, &job, event)
        }));
        self.state().active = None;
        match outcome {
            Ok(outcome) => outcome,
            Err(panic) => std::panic::resume_unwind(panic),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(text: &str) -> Result<RunRequest, &'static str> {
        run_params(&Json::parse(text).unwrap_or(Json::Null)).map_err(|ProtocolError(_, m)| m)
    }

    #[test]
    fn run_params_are_checked_as_the_python_host_checks_them() {
        for bad in [
            "null",
            "{}",
            "{\"argv\": []}",
            "{\"argv\": \"validate\"}",
            "{\"argv\": [1]}",
            "{\"argv\": [\"--json\"]}",
            "{\"argv\": [\"info\"], \"env\": {\"A\": 1}}",
            "{\"argv\": [\"info\"], \"env\": []}",
            "{\"argv\": [\"info\"], \"cwd\": 3}",
        ] {
            assert!(params(bad).is_err(), "{bad}");
        }
        for argv in [
            vec!["validate", "--", "--json"],
            vec!["query", "--platform", "sentinel", "--query", "--json"],
        ] {
            let text = |argv: &[&str]| {
                format!(
                    "{{\"argv\": {}}}",
                    compact(&Json::Array(argv.iter().map(|a| Json::str(*a)).collect()))
                )
            };
            let mut with_json = vec!["--json"];
            with_json.extend(&argv);
            for given in [text(&argv), text(&with_json)] {
                assert_eq!(
                    params(&given).map(|request| request.argv),
                    Ok(argv.iter().map(|a| (*a).to_owned()).collect::<Vec<_>>())
                );
            }
        }
    }

    #[test]
    fn the_digest_ignores_the_duration() {
        let digest = |text: &str| commands_digest(&Json::parse(text).unwrap_or(Json::Null));
        assert_eq!(
            digest("{\"a\":1,\"duration_ms\":3}"),
            digest("{\"duration_ms\":9,\"a\":1}")
        );
        assert_ne!(digest("{\"a\":1}"), digest("{\"a\":2}"));
        // As Python's json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=False).
        assert_eq!(
            digest("{\"b\":{\"z\":1,\"é\":[2]},\"a\":\"x\"}"),
            "dca7015199a10e069c267f7485ce26dac9e49b1e989dedd6db2c5e58add16e5f"
        );
    }
}
