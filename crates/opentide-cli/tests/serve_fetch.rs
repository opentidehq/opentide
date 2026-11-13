//! `opentide serve`'s `opentide/fetch` (W2): tenant commands whose HTTP the
//! client makes, against the cassettes the golden cases replay.
//!
//! A stand-in client says `capabilities.fetch` at `initialize`, then answers
//! each `opentide/fetch` from a cassette (`tests/cassettes/golden/`), in
//! order, as the WASI host answers from the editor's HTTP stack. Each run
//! must send the cassette's requests (compared as `opentide-cassette` compares
//! a replay: redacted, a JSON body as data) and answer the document the same
//! command answers natively, its requests sent by reqwest through the
//! replaying proxy. Then the client's failures (`data.kind`) and a run
//! cancelled while the client holds its request.
//!
//! One test binary of its own: the transport `initialize` installs is the
//! process's, so these runs take [`SESSION`] and nothing else runs here.

#![cfg(unix)]
#![expect(
    clippy::unwrap_used,
    reason = "a test helper: a broken stand-in is a failure"
)]

#[path = "common/replay.rs"]
mod replay;

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, channel};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use base64::Engine as _;
use opentide_cassette::{Cassette, Mode, Proxy, Redaction};
use opentide_cli::json::Json;
use opentide_cli::serve::{HostRunner, Server, Writer};

const TIMEOUT: Duration = Duration::from_secs(40);

/// The process's installed transport, and its warm workspaces.
static SESSION: Mutex<()> = Mutex::new(());

fn session() -> MutexGuard<'static, ()> {
    SESSION.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The credential every run gets: the cassettes redact it.
const SECRET: &str = "golden-stand-in-credential";

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn cassette(name: &str) -> Cassette {
    let path = repo().join(format!("tests/cassettes/{name}.json"));
    Cassette::parse(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), target).unwrap();
        }
    }
}

/// A fresh copy of the golden fixture *name* (`tests/golden/fixtures/`).
fn workspace(name: &str) -> (tempfile::TempDir, PathBuf) {
    let root = replay::case_root();
    let ws = std::fs::canonicalize(root.path()).unwrap().join("ws");
    copy_tree(&repo().join("tests/golden/fixtures").join(name), &ws);
    (root, ws)
}

/// A server on its own thread, serving a host runner in *ws*.
struct Session {
    server: Server,
    lines: Receiver<String>,
    serving: Option<std::thread::JoinHandle<bool>>,
    next: i64,
}

impl Session {
    fn start(ws: &Path) -> Session {
        let (sender, lines) = channel();
        let sender = Mutex::new(sender);
        let write: Writer = Box::new(move |line: &str| {
            let _ignored = sender
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .send(line.to_owned());
            Ok(())
        });
        let base = vec![
            ("OPENTIDE_JSON_INDENT".to_owned(), "0".to_owned()),
            ("NO_COLOR".to_owned(), "1".to_owned()),
            ("HOME".to_owned(), ws.display().to_string()),
            (
                "XDG_STATE_HOME".to_owned(),
                ws.join(".state").display().to_string(),
            ),
        ];
        let runner = Arc::new(HostRunner::new(base, ws.to_path_buf(), "0.23.0"));
        let server = Server::new(write, runner, "0.23.0");
        let serving = server.clone();
        Session {
            server,
            lines,
            serving: Some(std::thread::spawn(move || serving.serve(&|| false))),
            next: 0,
        }
    }

    fn send(&self, message: &Json) {
        let line = serde_json::to_string(message).unwrap();
        self.server.receive(line.as_bytes());
    }

    fn message(&self) -> Json {
        Json::parse(&self.lines.recv_timeout(TIMEOUT).unwrap()).unwrap()
    }

    fn request(&mut self, method: &str, params: Json) -> i64 {
        self.next += 1;
        self.send(&Json::object([
            ("jsonrpc", Json::str("2.0")),
            ("id", Json::Int(self.next)),
            ("method", Json::str(method)),
            ("params", params),
        ]));
        self.next
    }

    /// Answers each `opentide/fetch` with *host* until the answer to *id*;
    /// the messages the server sent besides, in order.
    fn answer(&self, id: i64, host: &mut dyn FnMut(&Json) -> Json) -> (Json, Vec<Json>) {
        let mut others = Vec::new();
        loop {
            let message = self.message();
            if message.get("method") == Some(&Json::str("opentide/fetch")) {
                let reply = host(&message);
                self.send(&reply);
                others.push(message);
                continue;
            }
            if message.get("method").is_some() {
                others.push(message);
                continue;
            }
            assert_eq!(message.get("id"), Some(&Json::Int(id)), "{message:?}");
            return (message, others);
        }
    }

    fn initialize(&mut self, fetch: bool) -> Json {
        let params = if fetch {
            Json::object([("capabilities", Json::object([("fetch", Json::Bool(true))]))])
        } else {
            Json::object(Vec::<(String, Json)>::new())
        };
        let id = self.request("initialize", params);
        self.answer(id, &mut |_| panic!("no fetch at initialize"))
            .0
            .get("result")
            .cloned()
            .unwrap()
    }

    fn stop(mut self) -> bool {
        self.send(&Json::object([
            ("jsonrpc", Json::str("2.0")),
            ("method", Json::str("exit")),
        ]));
        self.serving.take().unwrap().join().unwrap()
    }
}

fn run_params(argv: &[&str], env: &[(String, String)]) -> Json {
    Json::object([
        (
            "argv",
            Json::Array(argv.iter().map(|word| Json::str(*word)).collect()),
        ),
        (
            "env",
            Json::Object(
                env.iter()
                    .map(|(name, value)| (name.clone(), Json::str(value)))
                    .collect(),
            ),
        ),
    ])
}

/// The client's answers from a cassette, in order, and the requests it was
/// asked to make, as the recording proxy records them.
struct MockHost {
    cassette: Cassette,
    redaction: Redaction,
    next: usize,
    asked: Vec<opentide_cassette::cassette::Request>,
}

impl MockHost {
    fn new(name: &str) -> MockHost {
        MockHost {
            cassette: cassette(name),
            redaction: Redaction::new([SECRET.to_owned()]),
            next: 0,
            asked: Vec::new(),
        }
    }

    fn reply(id: &Json, member: (&str, Json)) -> Json {
        Json::object([
            ("jsonrpc", Json::str("2.0")),
            ("id", id.clone()),
            (member.0, member.1),
        ])
    }

    /// The answer to one `opentide/fetch`.
    fn fetch(&mut self, message: &Json) -> Json {
        let id = message.get("id").unwrap();
        let params = message.get("params").unwrap();
        let text = |key: &str| params.get(key).and_then(Json::as_str).unwrap().to_owned();
        let headers: Vec<(String, String)> = match params.get("headers") {
            Some(Json::Array(pairs)) => pairs
                .iter()
                .map(|pair| match pair {
                    Json::Array(items) => (
                        items[0].as_str().unwrap().to_owned(),
                        items[1].as_str().unwrap().to_owned(),
                    ),
                    other => panic!("a header is a pair: {other:?}"),
                })
                .collect(),
            other => panic!("headers: {other:?}"),
        };
        let body = match params.get("body") {
            Some(Json::Str(encoded)) => base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .unwrap(),
            _ => Vec::new(),
        };
        self.asked.push(opentide_cassette::cassette::Request {
            method: text("method"),
            url: self.redaction.url(&text("url")),
            headers: self
                .redaction
                .request_headers(headers.iter().map(|(n, v)| (n.as_str(), v.as_str()))),
            body: opentide_cassette::Body::from_bytes(&self.redaction.body(&body)),
        });
        let Some(interaction) = self.cassette.interactions.get(self.next) else {
            return Self::reply(
                id,
                (
                    "error",
                    Json::object([
                        ("code", Json::Int(-32000)),
                        ("message", Json::str("past the cassette's end")),
                        ("data", Json::object([("kind", Json::str("connect"))])),
                    ]),
                ),
            );
        };
        self.next += 1;
        let answer = &interaction.response;
        Self::reply(
            id,
            (
                "result",
                Json::object([
                    ("status", Json::Int(i64::from(answer.status))),
                    (
                        "headers",
                        Json::Array(
                            answer
                                .headers
                                .iter()
                                .map(|(n, v)| Json::Array(vec![Json::str(n), Json::str(v)]))
                                .collect(),
                        ),
                    ),
                    ("url", params.get("url").unwrap().clone()),
                    (
                        "body",
                        Json::str(
                            base64::engine::general_purpose::STANDARD.encode(answer.body.bytes()),
                        ),
                    ),
                ]),
            ),
        )
    }

    /// Every difference between what was asked and the recording.
    fn mismatches(&self) -> Vec<opentide_cassette::Mismatch> {
        let expected: Vec<&opentide_cassette::cassette::Request> = self
            .cassette
            .interactions
            .iter()
            .map(|interaction| &interaction.request)
            .collect();
        opentide_cassette::replay::compare(&expected, &self.asked)
    }
}

/// The run's document without what differs between two runs of it.
fn stable(document: &Json) -> Json {
    match document {
        Json::Object(members) => Json::Object(
            members
                .iter()
                .filter(|(key, _)| {
                    !matches!(key.as_str(), "duration_ms" | "elapsed_ms" | "seconds")
                })
                .map(|(key, value)| (key.clone(), stable(value)))
                .collect(),
        ),
        Json::Array(items) => Json::Array(items.iter().map(stable).collect()),
        // A message ends with the run's wall time: ` · 0.1s`.
        Json::Str(text) => match text.rsplit_once(" · ") {
            Some((head, tail))
                if tail.ends_with('s')
                    && tail[..tail.len() - 1]
                        .chars()
                        .all(|c| c.is_ascii_digit() || c == '.') =>
            {
                Json::Str(format!("{head} · <SECONDS>"))
            }
            _ => document.clone(),
        },
        other => other.clone(),
    }
}

/// Each place *right* differs from *left*, as a JSON pointer and both values.
fn differences(left: &Json, right: &Json, at: &str) -> Vec<String> {
    match (left, right) {
        (Json::Object(a), Json::Object(b)) => {
            let mut found = Vec::new();
            for (key, value) in a {
                let here = format!("{at}/{key}");
                match right.get(key) {
                    Some(other) => found.extend(differences(value, other, &here)),
                    None => found.push(format!("{here}: only natively")),
                }
            }
            for (key, _) in b {
                if left.get(key).is_none() {
                    found.push(format!("{at}/{key}: only through the client"));
                }
            }
            found
        }
        (Json::Array(a), Json::Array(b)) if a.len() == b.len() => a
            .iter()
            .zip(b)
            .enumerate()
            .flat_map(|(index, (x, y))| differences(x, y, &format!("{at}/{index}")))
            .collect(),
        _ if left == right => Vec::new(),
        _ => vec![format!(
            "{at}: {left:?} natively, {right:?} through the client"
        )],
    }
}

/// One golden case: its fixture, argv, credential and cassette.
struct Case {
    fixture: &'static str,
    argv: &'static [&'static str],
    credential: &'static str,
    cassette: &'static str,
}

/// *case* through the client's `opentide/fetch`, then natively through
/// the replaying proxy: the requests are the cassette's, and both answer
/// one document.
fn same_through_the_client(case: &Case) -> Json {
    let credential = vec![(case.credential.to_owned(), SECRET.to_owned())];

    // Natively: reqwest through the replaying proxy.
    let (_native_root, native_ws) = workspace(case.fixture);
    let proxy = Proxy::start(
        Mode::Replay {
            cassette: cassette(case.cassette),
        },
        Redaction::new([SECRET.to_owned()]),
    )
    .unwrap();
    let mut ca = tempfile::NamedTempFile::new().unwrap();
    ca.write_all(proxy.ca_pem().as_bytes()).unwrap();
    let mut native_env = proxy.client_env(ca.path().to_str().unwrap());
    native_env.extend(credential.clone());
    let mut native = Session::start(&native_ws);
    let result = native.initialize(false);
    assert_eq!(result.get("capabilities"), None, "{result:?}");
    let id = native.request("run", run_params(case.argv, &native_env));
    let (answer, _) = native.answer(id, &mut |_| panic!("no fetch without the capability"));
    let native_result = answer.get("result").cloned().unwrap();
    assert!(native.stop());
    assert_eq!(proxy.verify(), Vec::new(), "the native run's requests");

    // Through the client.
    let (_root, ws) = workspace(case.fixture);
    let mut client = Session::start(&ws);
    let result = client.initialize(true);
    assert_eq!(
        result.get("capabilities"),
        Some(&Json::object([("fetch", Json::Bool(true))]))
    );
    let mut host = MockHost::new(case.cassette);
    let id = client.request("run", run_params(case.argv, &credential));
    let (answer, sent) = client.answer(id, &mut |message| host.fetch(message));
    let fetched = sent
        .iter()
        .filter(|message| message.get("method") == Some(&Json::str("opentide/fetch")))
        .count();
    assert_eq!(fetched, host.cassette.interactions.len());
    for message in &sent {
        if message.get("method") == Some(&Json::str("opentide/fetch")) {
            let request_id = message.get("id").and_then(Json::as_str).unwrap();
            assert!(request_id.starts_with('h'), "{request_id}");
            assert_eq!(
                message.get("params").and_then(|p| p.get("run")),
                Some(&Json::str(id.to_string())),
                "each request names its run"
            );
        }
    }
    assert!(client.stop());
    assert_eq!(
        host.mismatches(),
        Vec::new(),
        "the requests asked of the client"
    );
    let client_result = answer.get("result").cloned().unwrap();
    assert_eq!(
        differences(&stable(&native_result), &stable(&client_result), ""),
        Vec::<String>::new(),
        "the same document through the client"
    );
    client_result
}

#[test]
fn a_query_through_the_client_is_the_native_query() {
    let _session = session();
    let result = same_through_the_client(&Case {
        fixture: "tenants",
        argv: &[
            "query",
            "--platform",
            "defender_for_endpoint",
            "--from",
            "2099-01-01T00:00:00Z",
            "--to",
            "2099-01-01T01:00:00Z",
            "--limit",
            "1",
            "DeviceProcessEvents | project Timestamp, DeviceName",
        ],
        credential: "DEFENDER_CLIENT_SECRET",
        cassette: "golden/query-defender",
    });
    assert_eq!(result.get("exit_code"), Some(&Json::Int(0)), "{result:?}");
}

#[test]
fn a_live_check_through_the_client_is_the_native_check() {
    let _session = session();
    let result = same_through_the_client(&Case {
        fixture: "live-tenants",
        argv: &[
            "validate",
            "query",
            "--live",
            "--platform",
            "splunk",
            "--uuid",
            "00000000-0000-4000-8046-000000000001",
        ],
        credential: "SPLUNK_TOKEN",
        cassette: "golden/validate-live-splunk-parsed",
    });
    assert_eq!(result.get("exit_code"), Some(&Json::Int(0)), "{result:?}");
}

#[test]
fn a_deploy_through_the_client_is_the_native_deploy() {
    let _session = session();
    let result = same_through_the_client(&Case {
        fixture: "deploy-tenants",
        argv: &[
            "deploy",
            "--platform",
            "crowdstrike",
            "--strategy",
            "PREVIEW",
            "--strategy",
            "RELEASE",
            "--all",
            "--keep-deprecated",
        ],
        credential: "CROWDSTRIKE_CLIENT_SECRET",
        cassette: "golden/deploy-crowdstrike",
    });
    assert_eq!(result.get("exit_code"), Some(&Json::Int(0)), "{result:?}");
}

#[test]
fn a_share_through_the_client_is_the_native_share() {
    let _session = session();
    let result = same_through_the_client(&Case {
        fixture: "share-misp",
        argv: &["share", "push"],
        credential: "MISP_API_KEY",
        cassette: "golden/share-push",
    });
    // misp-locked refuses its probe: a partial run.
    assert_eq!(result.get("exit_code"), Some(&Json::Int(3)), "{result:?}");
}

/// A query on Elastic's tenant in the `tenants` fixture, whose client
/// answers its one request with *error*.
fn query_failing_with(kind: &str) -> Json {
    let (_root, ws) = workspace("tenants");
    let mut client = Session::start(&ws);
    client.initialize(true);
    let credential = vec![("ELASTIC_API_KEY".to_owned(), SECRET.to_owned())];
    let id = client.request(
        "run",
        run_params(
            &[
                "query",
                "--platform",
                "elastic",
                "--from",
                "2099-01-01T00:00:00Z",
                "--to",
                "2099-01-01T01:00:00Z",
                "FROM logs-*",
            ],
            &credential,
        ),
    );
    let (answer, _) = client.answer(id, &mut |message| {
        MockHost::reply(
            message.get("id").unwrap(),
            (
                "error",
                Json::object([
                    ("code", Json::Int(-32000)),
                    ("message", Json::str(format!("the host's {kind}"))),
                    ("data", Json::object([("kind", Json::str(kind))])),
                ]),
            ),
        )
    });
    assert!(client.stop());
    answer.get("result").cloned().unwrap()
}

#[test]
fn the_clients_failures_are_the_tenants() {
    let _session = session();
    let error = |result: &Json| {
        result
            .get("document")
            .and_then(|document| document.get("results"))
            .and_then(|results| match results {
                Json::Array(items) => items.first().cloned(),
                _ => None,
            })
            .and_then(|first| first.get("error").and_then(Json::as_str).map(str::to_owned))
            .unwrap_or_else(|| panic!("no tenant error in {result:?}"))
    };
    let refused = query_failing_with("connect");
    assert_eq!(refused.get("exit_code"), Some(&Json::Int(1)));
    assert_eq!(
        error(&refused),
        "Cannot reach elastic tenant 'soc' at https://es.elastic.invalid: the host's connect"
    );
    let slow = query_failing_with("timeout");
    assert!(
        error(&slow).starts_with("elastic tenant \"soc\" did not answer the query within 120s"),
        "{}",
        error(&slow)
    );
}

#[test]
fn a_run_cancelled_while_the_client_holds_its_request_is_interrupted() {
    let _session = session();
    let (_root, ws) = workspace("tenants");
    let mut client = Session::start(&ws);
    client.initialize(true);
    let credential = vec![("ELASTIC_API_KEY".to_owned(), SECRET.to_owned())];
    let id = client.request(
        "run",
        run_params(
            &[
                "query",
                "--platform",
                "elastic",
                "--from",
                "2099-01-01T00:00:00Z",
                "--to",
                "2099-01-01T01:00:00Z",
                "FROM logs-*",
            ],
            &credential,
        ),
    );
    // The client takes the request and does not answer: it cancels the run.
    let fetch = client.message();
    assert_eq!(fetch.get("method"), Some(&Json::str("opentide/fetch")));
    let fetch_id = fetch.get("id").cloned().unwrap();
    client.send(&Json::object([
        ("jsonrpc", Json::str("2.0")),
        ("method", Json::str("$/cancelRequest")),
        ("params", Json::object([("id", Json::Int(id))])),
    ]));
    let mut cancelled_fetch = false;
    let answer = loop {
        let message = client.message();
        if message.get("method") == Some(&Json::str("$/cancelRequest")) {
            assert_eq!(
                message.get("params").and_then(|p| p.get("id")),
                Some(&fetch_id)
            );
            cancelled_fetch = true;
            continue;
        }
        if message.get("method").is_some() {
            continue;
        }
        break message;
    };
    assert!(cancelled_fetch, "the server withdraws its request");
    let result = answer.get("result").unwrap();
    assert_eq!(result.get("exit_code"), Some(&Json::Int(130)), "{result:?}");
    // The client's late answer to the withdrawn request changes nothing.
    client.send(&MockHost::reply(
        &fetch_id,
        ("result", Json::object([("status", Json::Int(200))])),
    ));
    assert!(client.stop());
}
