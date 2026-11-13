//! `opentide serve`'s protocol (UC-3.8, #830): the scenarios the Python host
//! was held to (`tests/test_cli/test_serve.py`, vscode-extension's
//! `fake-opentide.mjs`), on the Rust host, and the oracle's recorded
//! sessions (`tests/golden/cases/serve/*/session`) replayed byte for byte.
//!
//! The runs that reach the process's warm workspaces and its one run in
//! progress take [`SESSION`] first: those are process-wide.

#![cfg(unix)]
#![expect(
    clippy::unwrap_used,
    reason = "a test helper: a broken recording is a failure"
)]

#[path = "common/replay.rs"]
mod replay;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, channel};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use opentide_cli::json::Json;
use opentide_cli::serve::runner::{failure, keeps_workspace, refusal};
use opentide_cli::serve::{
    EventSink, HostRunner, Job, Plan, RunOutcome, RunRequest, Runner, Server, Writer,
    commands_digest,
};

const TIMEOUT: Duration = Duration::from_secs(120);

/// The process's warm workspaces and its run in progress.
static SESSION: Mutex<()> = Mutex::new(());

fn session() -> MutexGuard<'static, ()> {
    SESSION.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A client of a [`Server`] serving on its own thread.
struct Client {
    server: Server,
    lines: Receiver<String>,
    notifications: Vec<Json>,
    serving: Option<std::thread::JoinHandle<bool>>,
    next: i64,
}

impl Client {
    fn new(runner: Arc<dyn Runner>) -> Client {
        Client::with_writer(runner, |_| Ok(()))
    }

    fn with_writer(
        runner: Arc<dyn Runner>,
        check: impl Fn(usize) -> std::io::Result<()> + Send + Sync + 'static,
    ) -> Client {
        let (sender, lines) = channel();
        let sender = Mutex::new(sender);
        let written = AtomicUsize::new(0);
        let write: Writer = Box::new(move |line: &str| {
            check(written.fetch_add(1, Ordering::SeqCst))?;
            assert!(!line.contains('\n'), "{line}");
            let _ignored = sender
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .send(line.to_owned());
            Ok(())
        });
        let server = Server::new(write, runner, "0.23.0");
        Client {
            server,
            lines,
            notifications: Vec::new(),
            serving: None,
            next: 0,
        }
    }

    fn start(mut self) -> Client {
        let server = self.server.clone();
        self.serving = Some(std::thread::spawn(move || server.serve(&|| false)));
        self
    }

    fn send(&self, line: &str) {
        self.server.receive(line.as_bytes());
    }

    fn message(&self) -> Json {
        let line = self.lines.recv_timeout(TIMEOUT).unwrap();
        let message = Json::parse(&line).unwrap();
        assert_eq!(message.get("jsonrpc"), Some(&Json::str("2.0")));
        message
    }

    fn request(&mut self, method: &str, params: &str) -> i64 {
        self.next += 1;
        self.send(&format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":{},\"method\":\"{method}\",\"params\":{params}}}",
            self.next
        ));
        self.next
    }

    fn answer(&mut self, id: i64) -> Json {
        loop {
            let message = self.message();
            if message.get("method").is_some() {
                self.notifications.push(message);
                continue;
            }
            assert_eq!(message.get("id"), Some(&Json::Int(id)), "{message:?}");
            return message;
        }
    }

    fn call(&mut self, method: &str, params: &str) -> Json {
        let id = self.request(method, params);
        self.answer(id)
    }

    fn run(&mut self, params: &str) -> Json {
        let answer = self.call("run", params);
        answer.get("result").cloned().unwrap()
    }

    fn stop(mut self) -> bool {
        self.send("{\"jsonrpc\":\"2.0\",\"method\":\"exit\"}");
        self.serving.take().unwrap().join().unwrap()
    }
}

fn exit_code(result: &Json) -> &Json {
    result.get("exit_code").unwrap()
}

fn failure_code(result: &Json) -> Option<&Json> {
    result.get("document")?.get("failure")?.get("code")
}

/// A runner that runs nothing: it records each run and answers `{"ok": true}`,
/// or as `behaviour` says.
#[derive(Default)]
struct Recording {
    calls: Mutex<Vec<Vec<String>>>,
    interrupts: AtomicUsize,
    interrupted: AtomicBool,
    started: AtomicBool,
    /// Runs block until interrupted.
    block: bool,
    /// Runs panic.
    panic: bool,
    /// A run returns, then waits for `release` before answering.
    hold_after_return: Option<Arc<AtomicBool>>,
}

impl Runner for Recording {
    fn plan(&self, request: &RunRequest) -> Plan {
        let words: Vec<String> = request.argv.iter().take(1).cloned().collect();
        Plan {
            refused: refusal(&words),
            keep: keeps_workspace(&words, &request.argv),
            words,
            rust: None,
        }
    }

    fn run(&self, request: &RunRequest, plan: &Plan, job: &Arc<Job>, _: EventSink) -> RunOutcome {
        self.calls.lock().unwrap().push(request.argv.clone());
        self.started.store(true, Ordering::SeqCst);
        assert!(!self.panic, "the runner exploded");
        if self.block {
            while !self.interrupted.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(5));
            }
            job.finish();
            return failure(&plan.words, "Interrupted", 130);
        }
        let cancelled = job.finish();
        if let Some(release) = &self.hold_after_return {
            while !release.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(5));
            }
        }
        assert!(!cancelled || self.hold_after_return.is_none());
        RunOutcome::Built {
            document: Json::object([
                ("ok", Json::Bool(true)),
                ("command", Json::str(plan.words.join(" "))),
            ]),
            exit_code: 0,
        }
    }

    fn interrupt(&self) {
        self.interrupts.fetch_add(1, Ordering::SeqCst);
        self.interrupted.store(true, Ordering::SeqCst);
    }

    fn invalidate(&self, _: &[String]) {}
}

fn wait_for(flag: &AtomicBool) {
    let deadline = std::time::Instant::now() + TIMEOUT;
    while !flag.load(Ordering::SeqCst) {
        assert!(std::time::Instant::now() < deadline, "timed out");
        std::thread::sleep(Duration::from_millis(5));
    }
}

// --- the protocol ----------------------------------------------------------------------

#[test]
fn protocol_problems_are_json_rpc_errors() {
    let mut client = Client::new(Arc::new(Recording::default())).start();
    let code = |message: &Json| message.get("error").unwrap().get("code").cloned().unwrap();
    client.send("{not json");
    let parse = client.message();
    assert_eq!(code(&parse), Json::Int(-32700));
    assert_eq!(parse.get("id"), Some(&Json::Null));
    assert_eq!(
        parse.get("error").unwrap().get("message"),
        Some(&Json::str(
            "Parse error: Expecting property name enclosed in double quotes: line 1 column 2 (char 1)"
        ))
    );
    client.send("[]");
    assert_eq!(code(&client.message()), Json::Int(-32600));
    client.send("{\"jsonrpc\":\"2.0\",\"id\":7}");
    let no_method = client.message();
    assert_eq!(code(&no_method), Json::Int(-32600));
    assert_eq!(no_method.get("id"), Some(&Json::Int(7)));
    assert_eq!(code(&client.call("nope", "{}")), Json::Int(-32601));
    for params in [
        "null",
        "{}",
        "{\"argv\":[]}",
        "{\"argv\":\"validate\"}",
        "{\"argv\":[1]}",
        "{\"argv\":[\"--json\"]}",
        "{\"argv\":[\"info\"],\"env\":{\"A\":1}}",
    ] {
        assert_eq!(
            code(&client.call("run", params)),
            Json::Int(-32602),
            "{params}"
        );
    }
    client.send("{\"jsonrpc\":\"2.0\",\"method\":\"unknown/notification\"}");
    client.send("   ");
    assert_eq!(
        exit_code(&client.run("{\"argv\":[\"explain\",\"vocab_unknown\"]}")),
        &Json::Int(0)
    );
    assert!(client.stop());
}

#[test]
fn shutdown_then_exit_ends_the_loop() {
    let mut client = Client::new(Arc::new(Recording::default())).start();
    assert_eq!(
        client.call("shutdown", "{}").get("result"),
        Some(&Json::Null)
    );
    let refused = client.call("run", "{\"argv\":[\"info\"]}");
    assert_eq!(
        refused.get("error").unwrap().get("code"),
        Some(&Json::Int(-32600))
    );
    assert!(client.stop());
}

#[test]
fn protocol_commands_are_refused_as_usage_errors() {
    let runner = HostRunner::new(Vec::new(), PathBuf::from("."), "0.23.0");
    let mut client = Client::new(Arc::new(runner)).start();
    for argv in [
        "[\"serve\"]",
        "[\"mcp\",\"start\"]",
        "[\"lsp\",\"start\"]",
        "[\"tui\"]",
    ] {
        let result = client.run(&format!("{{\"argv\":{argv}}}"));
        assert_eq!(exit_code(&result), &Json::Int(2), "{argv}");
        assert_eq!(failure_code(&result), Some(&Json::str("usage_error")));
    }
    assert!(client.stop());
}

#[test]
fn requests_are_answered_in_order() {
    let mut client = Client::new(Arc::new(Recording::default())).start();
    let ids: Vec<i64> = (0..5)
        .map(|_| client.request("run", "{\"argv\":[\"explain\",\"x\"]}"))
        .collect();
    let answered: Vec<Json> = (0..5)
        .map(|_| client.message().get("id").cloned().unwrap())
        .collect();
    assert_eq!(answered, ids.into_iter().map(Json::Int).collect::<Vec<_>>());
    assert!(client.stop());
}

#[test]
fn queued_runs_do_not_run_after_exit_or_the_end_of_input() {
    for ending in ["exit", "close"] {
        let runner = Arc::new(Recording::default());
        let mut client = Client::new(runner.clone());
        for id in 1..=3 {
            client.send(&format!(
                "{{\"jsonrpc\":\"2.0\",\"id\":{id},\"method\":\"run\",\"params\":{{\"argv\":[\"deploy\",\"--strategy\",\"PRODUCTION\"]}}}}"
            ));
        }
        if ending == "exit" {
            client.send("{\"jsonrpc\":\"2.0\",\"method\":\"exit\"}");
        } else {
            client.server.close_input();
        }
        assert!(client.server.serve(&|| false));
        assert!(runner.calls.lock().unwrap().is_empty());
        for id in 1..=3 {
            let answer = client.answer(id);
            let result = answer.get("result").unwrap();
            assert_eq!(exit_code(result), &Json::Int(130));
            assert_eq!(failure_code(result), Some(&Json::str("interrupted")));
            assert_eq!(
                result.get("document").unwrap().get("command"),
                Some(&Json::str("deploy"))
            );
        }
        client.next = 0;
    }
}

#[test]
fn a_client_that_disconnects_ends_the_session() {
    let runner = Arc::new(Recording::default());
    let client = Client::with_writer(runner.clone(), |written| {
        if written == 0 {
            Ok(())
        } else {
            Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
        }
    });
    for id in 1..=3 {
        client.send(&format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":{id},\"method\":\"run\",\"params\":{{\"argv\":[\"validate\"]}}}}"
        ));
    }
    // No exit and no end of input: the failed write alone ends the session.
    assert!(client.server.serve(&|| false));
    assert_eq!(client.message().get("id"), Some(&Json::Int(1)));
    // The run whose answer could not be written was the last one to run.
    assert_eq!(runner.calls.lock().unwrap().len(), 2);
}

#[test]
fn ctrl_c_ends_the_loop() {
    let client = Client::new(Arc::new(Recording::default()));
    assert!(!client.server.serve(&|| true));
}

// --- cancel and crash ------------------------------------------------------------------

#[test]
fn cancel_interrupts_the_run_in_progress_and_it_answers_130() {
    let runner = Arc::new(Recording {
        block: true,
        ..Recording::default()
    });
    let mut client = Client::new(runner.clone()).start();
    let id = client.request("run", "{\"argv\":[\"validate\"]}");
    wait_for(&runner.started);
    client.send(&format!(
        "{{\"jsonrpc\":\"2.0\",\"method\":\"$/cancelRequest\",\"params\":{{\"id\":{id}}}}}"
    ));
    let result = client.answer(id).get("result").cloned().unwrap();
    assert_eq!(exit_code(&result), &Json::Int(130));
    assert_eq!(failure_code(&result), Some(&Json::str("interrupted")));
    assert_eq!(runner.interrupts.load(Ordering::SeqCst), 1);
    assert!(client.stop());
}

#[test]
fn cancelling_a_queued_run_answers_130_without_running_it() {
    let runner = Arc::new(Recording {
        block: true,
        ..Recording::default()
    });
    let mut client = Client::new(runner.clone()).start();
    let first = client.request("run", "{\"argv\":[\"validate\"]}");
    wait_for(&runner.started);
    let second = client.request("run", "{\"argv\":[\"explain\",\"x\"]}");
    client.send(&format!(
        "{{\"jsonrpc\":\"2.0\",\"method\":\"$/cancelRequest\",\"params\":{{\"id\":{second}}}}}"
    ));
    assert_eq!(client.server.pending_cancels(), 1);
    // A cancel names the queued run, not the running one: release it.
    client.send(&format!(
        "{{\"jsonrpc\":\"2.0\",\"method\":\"$/cancelRequest\",\"params\":{{\"id\":{first}}}}}"
    ));
    assert_eq!(
        exit_code(client.answer(first).get("result").unwrap()),
        &Json::Int(130)
    );
    let queued = client.answer(second).get("result").cloned().unwrap();
    assert_eq!(exit_code(&queued), &Json::Int(130));
    assert_eq!(
        queued.get("document").unwrap().get("command"),
        Some(&Json::str("explain")),
        "a cancelled run names its command"
    );
    assert_eq!(runner.calls.lock().unwrap().len(), 1);
    assert_eq!(client.server.pending_cancels(), 0);
    assert!(client.stop());
}

#[test]
fn a_cancel_after_the_command_returned_keeps_its_answer() {
    let release = Arc::new(AtomicBool::new(false));
    let runner = Arc::new(Recording {
        hold_after_return: Some(Arc::clone(&release)),
        ..Recording::default()
    });
    let mut client = Client::new(runner.clone()).start();
    let id = client.request("run", "{\"argv\":[\"explain\",\"x\"]}");
    wait_for(&runner.started);
    client.send(&format!(
        "{{\"jsonrpc\":\"2.0\",\"method\":\"$/cancelRequest\",\"params\":{{\"id\":{id}}}}}"
    ));
    release.store(true, Ordering::SeqCst);
    let result = client.answer(id).get("result").cloned().unwrap();
    assert_eq!(exit_code(&result), &Json::Int(0));
    assert_eq!(runner.interrupts.load(Ordering::SeqCst), 0);
    assert!(client.stop());
}

#[test]
fn a_cancel_for_a_finished_or_unknown_run_changes_nothing() {
    let mut client = Client::new(Arc::new(Recording::default())).start();
    let id = client.request("run", "{\"argv\":[\"explain\",\"x\"]}");
    assert_eq!(
        exit_code(client.answer(id).get("result").unwrap()),
        &Json::Int(0)
    );
    client.send(&format!(
        "{{\"jsonrpc\":\"2.0\",\"method\":\"$/cancelRequest\",\"params\":{{\"id\":{id}}}}}"
    ));
    client.send(
        "{\"jsonrpc\":\"2.0\",\"method\":\"$/cancelRequest\",\"params\":{\"id\":\"never-sent\"}}",
    );
    assert_eq!(client.server.pending_cancels(), 0);
    // A later request that reuses the id runs.
    client.send(&format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":{id},\"method\":\"run\",\"params\":{{\"argv\":[\"explain\",\"x\"]}}}}"
    ));
    assert_eq!(
        exit_code(client.answer(id).get("result").unwrap()),
        &Json::Int(0)
    );
    assert!(client.stop());
}

#[test]
fn an_internal_failure_is_answered_and_the_server_keeps_serving() {
    let runner = Arc::new(Recording {
        panic: true,
        ..Recording::default()
    });
    let mut client = Client::new(runner).start();
    let answer = client.call("run", "{\"argv\":[\"validate\"]}");
    let error = answer.get("error").unwrap();
    assert_eq!(error.get("code"), Some(&Json::Int(-32603)));
    assert_eq!(error.get("message"), Some(&Json::str("Internal error")));
    assert_eq!(
        client.call("shutdown", "{}").get("result"),
        Some(&Json::Null)
    );
    assert!(client.stop());
}

// --- runs on the Rust implementation ----------------------------------------------------

fn workspace(name: &str) -> (tempfile::TempDir, PathBuf) {
    let root = replay::case_root();
    let ws = std::fs::canonicalize(root.path()).unwrap().join("ws");
    std::fs::create_dir_all(&ws).unwrap();
    replay::fixture(name, &ws);
    (root, ws)
}

fn host(ws: &Path) -> Client {
    let base = vec![
        ("OPENTIDE_JSON_INDENT".to_owned(), "0".to_owned()),
        ("NO_COLOR".to_owned(), "1".to_owned()),
        ("HOME".to_owned(), ws.display().to_string()),
        (
            "XDG_STATE_HOME".to_owned(),
            ws.join(".state").display().to_string(),
        ),
    ];
    Client::new(Arc::new(HostRunner::new(base, ws.to_path_buf(), "0.23.0"))).start()
}

#[test]
fn initialize_names_the_protocol_version_and_command_tree() {
    let _session = session();
    let (_root, ws) = workspace("none");
    let mut client = host(&ws);
    let result = client
        .call("initialize", "{}")
        .get("result")
        .cloned()
        .unwrap();
    let commands = client.run("{\"argv\":[\"commands\"]}");
    let digest = commands_digest(commands.get("document").unwrap());
    assert_eq!(
        result,
        Json::object([
            ("protocol", Json::Int(1)),
            ("version", Json::str("0.23.0")),
            ("commands_digest", Json::str(digest)),
        ])
    );
    assert!(client.stop());
}

#[test]
fn a_rust_run_answers_its_document_warm_and_with_progress() {
    let _session = session();
    opentide_cli::embed::clear_workspaces();
    let (_root, ws) = workspace("tide-corpus");
    let mut client = host(&ws);
    let id = client.request("run", "{\"argv\":[\"validate\"]}");
    let cold = client.answer(id).get("result").cloned().unwrap();
    assert_eq!(
        cold.get("document").unwrap().get("command"),
        Some(&Json::str("validate"))
    );
    let events: Vec<&Json> = client
        .notifications
        .iter()
        .filter(|n| n.get("method") == Some(&Json::str("progress")))
        .map(|n| n.get("params").unwrap())
        .collect();
    assert!(!events.is_empty());
    assert!(
        events
            .iter()
            .all(|params| params.get("id") == Some(&Json::Int(id)))
    );
    let before = opentide_cli::embed::workspace_stats();
    assert_eq!(before.kept, 1);
    let warm = client.run("{\"argv\":[\"validate\"]}");
    assert_eq!(opentide_cli::embed::workspace_stats().hits, before.hits + 1);
    assert_eq!(exit_code(&warm), exit_code(&cold));
    // A run that may write drops the warm workspaces.
    let fixed = client.run("{\"argv\":[\"validate\",\"--fix\"]}");
    assert!(fixed.get("document").is_some());
    assert_eq!(opentide_cli::embed::workspace_stats().kept, 0);
    assert!(client.stop());
}

#[test]
fn a_run_in_a_missing_directory_fails() {
    let _session = session();
    let (_root, ws) = workspace("none");
    let mut client = host(&ws);
    let missing = ws.join("missing");
    let result = client.run(&format!(
        "{{\"argv\":[\"info\"],\"cwd\":{}}}",
        opentide_cli::serve::runner::compact(&Json::str(missing.display().to_string()))
    ));
    assert_eq!(exit_code(&result), &Json::Int(1));
    assert_eq!(failure_code(&result), Some(&Json::str("command_failed")));
    assert_eq!(
        result.get("document").unwrap().get("message"),
        Some(&Json::str(format!(
            "[Errno 2] No such file or directory: {:?}",
            missing.display().to_string()
        )))
    );
    assert!(client.stop());
}

#[test]
fn a_rust_run_cancelled_before_it_started_answers_130_unrun() {
    let _session = session();
    opentide_cli::embed::clear_workspaces();
    let (_root, ws) = workspace("tide-corpus");
    let runner = HostRunner::new(Vec::new(), ws.clone(), "0.23.0");
    let request = RunRequest {
        argv: vec!["info".into()],
        ..RunRequest::default()
    };
    let plan = runner.plan(&request);
    assert!(plan.keep && plan.rust.is_some());
    let job = Arc::new(Job::default());
    assert!(job.cancel(), "a run not yet returned is interrupted");
    let opens = opentide_cli::embed::workspace_stats().opens;
    let outcome = runner.run(&request, &plan, &job, Arc::new(|_| {}));
    let document = outcome.document();
    assert_eq!(document.get("exit_code"), Some(&Json::Int(130)));
    assert_eq!(document.get("command"), Some(&Json::str("info")));
    assert_eq!(opentide_cli::embed::workspace_stats().opens, opens);
    assert!(!job.cancel(), "a cancel after the run changes nothing");
}

/// The oracle's recorded sessions, replayed: the same lines in, the same
/// bytes out.
#[test]
fn recorded_sessions_are_answered_as_the_oracle_answered_them() {
    let _session = session();
    let cases = replay::repo().join("tests/golden/cases/serve/plain");
    for fixture in ["tide-corpus", "vscode"] {
        let dir = cases.join(fixture).join("session");
        let case: toml::Table =
            toml::from_str(&std::fs::read_to_string(dir.join("case.toml")).unwrap()).unwrap();
        let input = case["stdin"]["input"].as_str().unwrap().to_owned();
        let expected = std::fs::read_to_string(dir.join("stdout")).unwrap();
        let (_root, ws) = workspace(fixture);
        let (sender, lines) = channel();
        let sender = Mutex::new(sender);
        let write: Writer = Box::new(move |line: &str| {
            let _ignored = sender.lock().unwrap().send(format!("{line}\n"));
            Ok(())
        });
        let base = vec![("HOME".to_owned(), ws.display().to_string())];
        let runner = HostRunner::new(base, ws.clone(), "0.23.0");
        let server = Server::new(write, Arc::new(runner), "0.23.0");
        // The reading thread takes every line before the first run starts.
        opentide_cli::serve::read_lines(input.as_bytes(), &server);
        assert!(server.serve(&|| false));
        drop(server);
        let output: String = lines.try_iter().collect();
        // The digest names today's command tree, which has changed since
        // the oracle under approved entries (`commands`'s own cases); it is
        // computed as the oracle computed it from the oracle's tree.
        let recorded =
            std::fs::read_to_string(cases.join("../../commands/json/none/default/stdout")).unwrap();
        let oracle_digest = commands_digest(&Json::parse(&recorded).unwrap());
        assert!(
            expected.contains(&oracle_digest),
            "the oracle's digest is its tree's"
        );
        let today = host(&ws).run("{\"argv\":[\"commands\"]}");
        let today = commands_digest(today.get("document").unwrap());
        assert_eq!(
            output,
            expected.replace(&oracle_digest, &today),
            "{fixture}"
        );
    }
}

/// The `serve` fuzz target's seeds and saved crashes (`fuzz/seeds/serve`,
/// `fuzz/regressions/serve`), replayed on stable Rust: each is a client's
/// stdin, served to its end with runs that run nothing. The loop is
/// `fuzz/src/lib.rs::serve`'s.
#[test]
fn the_serve_fuzz_seeds_and_regressions_are_served_to_the_end() {
    struct NoRuns;
    impl Runner for NoRuns {
        fn plan(&self, request: &RunRequest) -> Plan {
            Recording::default().plan(request)
        }
        fn run(&self, _: &RunRequest, plan: &Plan, job: &Arc<Job>, _: EventSink) -> RunOutcome {
            job.finish();
            match &plan.refused {
                Some(message) => opentide_cli::serve::runner::usage(&plan.words, message),
                None => opentide_cli::serve::runner::document(&plan.words, "{\"ok\": true}", 0),
            }
        }
        fn interrupt(&self) {}
        fn invalidate(&self, _: &[String]) {}
    }
    let fuzz = replay::repo().join("fuzz");
    let mut replayed = 0;
    for dir in ["seeds/serve", "regressions/serve"] {
        let Ok(entries) = std::fs::read_dir(fuzz.join(dir)) else {
            continue;
        };
        for entry in entries {
            let path = entry.unwrap().path();
            let data = std::fs::read(&path).unwrap();
            let (sender, lines) = channel();
            let sender = Mutex::new(sender);
            let write: Writer = Box::new(move |line: &str| {
                let _ignored = sender.lock().unwrap().send(line.to_owned());
                Ok(())
            });
            let server = Server::new(write, Arc::new(NoRuns), "0.0.0");
            opentide_cli::serve::read_lines(data.as_slice(), &server);
            assert!(server.serve(&|| false), "{}", path.display());
            drop(server);
            for line in lines.try_iter() {
                assert!(
                    line.starts_with("{\"jsonrpc\":\"2.0\",") && !line.contains('\n'),
                    "{}: {line}",
                    path.display()
                );
                assert!(
                    !line.contains("\"code\":-32603"),
                    "{}: {line}",
                    path.display()
                );
            }
            replayed += 1;
        }
    }
    assert!(replayed >= 5, "only {replayed} seeds");
}
