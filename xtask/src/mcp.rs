//! `cargo xtask mcp record|replay`: recorded MCP sessions, replayed against
//! the Python server, the Rust server, or both (UC-3.7, #829).
//!
//! `tests/golden/mcp/sessions.toml` holds the requests: each session's
//! fixture and its JSON-RPC messages, in order. `record` sends them to the
//! Python server (`opentide mcp start` with `OPENTIDE_ENGINE=python`) and
//! writes what it answered, one `<session>.jsonl` per session beside the
//! file: a header line, then one line per message with the response.
//! Recordings are never written by hand.
//!
//! `replay --engine python|rust|compare FILE...` sends each recording's
//! messages again, in order and each once the one before it was answered,
//! to a fresh server on a fresh copy of the fixture, and compares every
//! answer with the recording: `python` and `rust` run that engine's server
//! (`OPENTIDE_ENGINE`, which `mcp start` reads, the Rust server running in
//! the package's Python process through `opentide.cli.rust`); `compare` runs
//! both, the Python server against the recording and the Rust server against
//! the Python server's live answers. A Rust difference is approved only by an
//! entry of `tests/golden/APPROVED_DIFFS.toml` for command `mcp start` and
//! case `<session>/<step>`, whose target is `stdout`, the response.
//!
//! What a comparison sees of a message ([`canonical`]): the workspace's path
//! reads `<WS>`, the installed `opentide` package's directory (where its
//! bundled data lives) `<PACKAGE>`, and the server's version `<VERSION>`
//! (they differ between runs and checkouts); a text block or resource text that is a JSON document is compared
//! as that document (an MCP client parses it; its spacing is the
//! serialiser's); keys are sorted, since JSON-RPC objects are unordered; a
//! validation report's `wall_ms` (its run's wall time) reads `<MS>`. Nothing
//! else is normalised.

use crate::golden::fixture::FixtureSpec;
use anyhow::{Context, Result, bail, ensure};
use opentide_compare::ledger::{Ledger, Usage};
use opentide_compare::{Case, Run};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{Receiver, RecvTimeoutError, channel};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// The command path approved differences name.
pub const COMMAND: &str = "mcp start";

/// Whether a ledger entry is the replay's: command `mcp start` and a case that
/// is a session's step (`<session>/<step>`), not a golden case of `mcp start`
/// (`mcp.start/<mode>/<fixture>/<variant>`, `golden check`'s).
pub fn owns(entry: &opentide_compare::Entry) -> bool {
    entry.command == COMMAND && !entry.case.starts_with("mcp.start/")
}

/// The protocol version a session's `initialize` asks for, unless it names one.
pub const DEFAULT_PROTOCOL_VERSION: &str = "2025-06-18";

/// How long one message may take to be answered.
const ANSWER_TIMEOUT: Duration = Duration::from_secs(300);

const USAGE: &str = "\
usage: cargo xtask mcp record [--only NAME] [--python PATH]
       cargo xtask mcp replay --engine python|rust|compare [--python PATH]
                              [--show-approved] FILE...

record   sends each session of tests/golden/mcp/sessions.toml to the Python
         server and writes tests/golden/mcp/<session>.jsonl
replay   sends each recording's messages to the engine's server (compare: to
         both) and compares the answers; differences of the Rust server only
         through tests/golden/APPROVED_DIFFS.toml (command `mcp start`)

--python names the interpreter of the package under test (default: the
repository's .venv, or OPENTIDE_PYTHON).
";

/// `tests/golden/mcp/sessions.toml`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sessions {
    /// The fixtures, by name.
    pub fixtures: BTreeMap<String, FixtureSpec>,
    /// The sessions, in order.
    pub session: Vec<SessionSpec>,
}

/// One session: a fixture and the messages sent after the handshake.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionSpec {
    /// The recording's file name, without `.jsonl`.
    pub name: String,
    /// A fixture of [`Sessions::fixtures`].
    pub fixture: String,
    /// The version `initialize` asks for.
    #[serde(default)]
    pub protocol_version: Option<String>,
    /// How the client starts the server.
    #[serde(default)]
    pub launch: Launch,
    /// The messages.
    pub steps: Vec<Step>,
}

/// How a session's client starts `opentide mcp start`.
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Launch {
    /// In the workspace, which `OPENTIDE_REPO_ROOT` and
    /// `OPENTIDE_TIDE_WORKSPACE` also name.
    #[default]
    Workspace,
    /// In an empty folder outside the workspace, with no workspace variable:
    /// `opentide --repo <workspace> mcp start`.
    RepoOption,
    /// In the fixture as an Agent Plugin root (`plugin.json`), with no
    /// workspace variable and `PWD` the plugin root: a host that names no
    /// workspace.
    PluginRoot,
}

impl Launch {
    /// The name `sessions.toml` and a recording's header give it.
    pub fn as_str(self) -> &'static str {
        match self {
            Launch::Workspace => "workspace",
            Launch::RepoOption => "repo-option",
            Launch::PluginRoot => "plugin-root",
        }
    }

    fn parse(text: &str) -> Result<Launch> {
        Ok(match text {
            "workspace" => Launch::Workspace,
            "repo-option" => Launch::RepoOption,
            "plugin-root" => Launch::PluginRoot,
            other => bail!("unknown launch `{other}`"),
        })
    }
}

/// One message of a session.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Step {
    /// The step's name, unique in its session: the case id's second part.
    pub id: String,
    /// The JSON-RPC message without `jsonrpc` and `id`: `{"method", "params"}`.
    pub message: String,
}

/// One recorded exchange: the message sent and the server's answer (`None`
/// for a notification).
#[derive(Clone, Debug, PartialEq)]
pub struct Exchange {
    /// The step's name.
    pub step: String,
    /// The message as sent, `jsonrpc` and `id` included.
    pub request: Value,
    /// The answer, normalised ([`normalise`]).
    pub response: Option<Value>,
}

/// A recording: its session's name, fixture, protocol version and exchanges.
#[derive(Clone, Debug, PartialEq)]
pub struct Recording {
    /// The session's name.
    pub session: String,
    /// The fixture's name.
    pub fixture: String,
    /// How the server was started.
    pub launch: Launch,
    /// The exchanges, the handshake's first.
    pub exchanges: Vec<Exchange>,
}

impl Recording {
    /// The recording as JSON lines.
    pub fn to_jsonl(&self) -> String {
        let mut out = String::new();
        let mut header = json!({"session": self.session, "fixture": self.fixture});
        if self.launch != Launch::Workspace {
            header["launch"] = json!(self.launch.as_str());
        }
        out.push_str(&header.to_string());
        out.push('\n');
        for exchange in &self.exchanges {
            let line = json!({
                "step": exchange.step,
                "request": exchange.request,
                "response": exchange.response,
            });
            out.push_str(&line.to_string());
            out.push('\n');
        }
        out
    }

    /// Reads a recording written by [`Recording::to_jsonl`].
    pub fn parse(text: &str) -> Result<Recording> {
        let mut lines = text.lines().filter(|line| !line.trim().is_empty());
        let header: Value = serde_json::from_str(lines.next().context("an empty recording")?)
            .context("the header line is not JSON")?;
        let field = |name: &str| {
            header
                .get(name)
                .and_then(Value::as_str)
                .map(str::to_owned)
                .with_context(|| format!("the header has no `{name}`"))
        };
        let mut exchanges = Vec::new();
        for (index, line) in lines.enumerate() {
            let value: Value = serde_json::from_str(line)
                .with_context(|| format!("line {} is not JSON", index + 2))?;
            let step = value
                .get("step")
                .and_then(Value::as_str)
                .with_context(|| format!("line {} has no `step`", index + 2))?;
            let request = value
                .get("request")
                .cloned()
                .with_context(|| format!("line {} has no `request`", index + 2))?;
            let response = value
                .get("response")
                .cloned()
                .filter(|value| !value.is_null());
            exchanges.push(Exchange {
                step: step.to_owned(),
                request,
                response,
            });
        }
        let launch = match header.get("launch") {
            None => Launch::Workspace,
            Some(value) => Launch::parse(value.as_str().context("`launch` is not a string")?)?,
        };
        Ok(Recording {
            session: field("session")?,
            fixture: field("fixture")?,
            launch,
            exchanges,
        })
    }
}

/// `cargo xtask mcp <args>`; the exit status.
pub fn run(args: &[String]) -> Result<u8> {
    let Some((command, rest)) = args.split_first() else {
        eprint!("{USAGE}");
        return Ok(2);
    };
    let repo = crate::corpus::cli::repo_root();
    let mut python: Option<PathBuf> = None;
    let mut only: Option<String> = None;
    let mut engine: Option<String> = None;
    let mut show_approved = false;
    let mut files = Vec::new();
    let mut iter = rest.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--python" => python = Some(PathBuf::from(iter.next().context("--python PATH")?)),
            "--only" => only = Some(iter.next().context("--only NAME")?.clone()),
            "--engine" => engine = Some(iter.next().context("--engine NAME")?.clone()),
            "--show-approved" => show_approved = true,
            "help" | "--help" | "-h" => {
                print!("{USAGE}");
                return Ok(0);
            }
            other if other.starts_with('-') => bail!("unknown option {other}\n{USAGE}"),
            other => files.push(PathBuf::from(other)),
        }
    }
    let python = python.unwrap_or_else(|| default_python(&repo));
    let sessions = load_sessions(&repo)?;
    match command.as_str() {
        "record" => {
            record(&repo, &python, &sessions, only.as_deref())?;
            Ok(0)
        }
        "replay" => {
            let engine = engine.context("replay needs --engine python|rust|compare")?;
            let engines: &[&str] = match engine.as_str() {
                "python" => &["python"],
                "rust" => &["rust"],
                "compare" => &["python", "rust"],
                other => bail!("--engine {other}: choose python, rust or compare"),
            };
            ensure!(!files.is_empty(), "replay needs recordings\n{USAGE}");
            let passed = replay(&repo, &python, &sessions, engines, &files, show_approved)?;
            Ok(u8::from(!passed))
        }
        "help" | "--help" | "-h" => {
            print!("{USAGE}");
            Ok(0)
        }
        other => bail!("unknown command `{other}`\n{USAGE}"),
    }
}

/// The interpreter of the package under test: `OPENTIDE_PYTHON`, else the
/// repository's `.venv`.
fn default_python(repo: &Path) -> PathBuf {
    if let Some(python) = std::env::var_os("OPENTIDE_PYTHON") {
        return PathBuf::from(python);
    }
    if cfg!(windows) {
        repo.join(".venv/Scripts/python.exe")
    } else {
        repo.join(".venv/bin/python")
    }
}

/// `tests/golden/mcp/`.
pub fn mcp_dir(repo: &Path) -> PathBuf {
    repo.join("tests/golden/mcp")
}

/// Reads and checks `sessions.toml`.
pub fn load_sessions(repo: &Path) -> Result<Sessions> {
    let path = mcp_dir(repo).join("sessions.toml");
    let text =
        std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    let sessions: Sessions =
        toml::from_str(&text).with_context(|| format!("parse {}", path.display()))?;
    check_sessions(&sessions)?;
    Ok(sessions)
}

/// Every session names a known fixture, unique names, steps that are JSON
/// objects with a `method`.
pub fn check_sessions(sessions: &Sessions) -> Result<()> {
    let mut names = std::collections::BTreeSet::new();
    for session in &sessions.session {
        ensure!(
            names.insert(&session.name),
            "session `{}` is defined twice",
            session.name
        );
        ensure!(
            sessions.fixtures.contains_key(&session.fixture),
            "session `{}`: no fixture `{}`",
            session.name,
            session.fixture
        );
        let mut steps = std::collections::BTreeSet::new();
        for step in &session.steps {
            ensure!(
                steps.insert(&step.id) && step.id != "initialize" && step.id != "initialized",
                "session `{}`: step `{}` is not unique",
                session.name,
                step.id
            );
            let message: Value = serde_json::from_str(&step.message).with_context(|| {
                format!("session `{}`, step `{}`: not JSON", session.name, step.id)
            })?;
            ensure!(
                message.get("method").and_then(Value::as_str).is_some()
                    && message.get("id").is_none()
                    && message.get("jsonrpc").is_none(),
                "session `{}`, step `{}`: a message is {{\"method\", \"params\"}}",
                session.name,
                step.id
            );
        }
    }
    Ok(())
}

/// The messages a session sends, `jsonrpc` and `id` added: the handshake,
/// then its steps, numbered from 1.
pub fn messages(session: &SessionSpec) -> Result<Vec<(String, Value)>> {
    let version = session
        .protocol_version
        .as_deref()
        .unwrap_or(DEFAULT_PROTOCOL_VERSION);
    let mut out = vec![
        (
            "initialize".to_owned(),
            json!({
                "jsonrpc": "2.0",
                "id": 0,
                "method": "initialize",
                "params": {
                    "protocolVersion": version,
                    "capabilities": {},
                    "clientInfo": {"name": "opentide-xtask-mcp", "version": "1"},
                },
            }),
        ),
        (
            "initialized".to_owned(),
            json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        ),
    ];
    for (index, step) in session.steps.iter().enumerate() {
        let mut message: Map<String, Value> = serde_json::from_str(&step.message)?;
        let mut framed = Map::new();
        framed.insert("jsonrpc".into(), json!("2.0"));
        framed.insert("id".into(), json!(index + 1));
        framed.append(&mut message);
        out.push((step.id.clone(), Value::Object(framed)));
    }
    Ok(out)
}

fn record(repo: &Path, python: &Path, sessions: &Sessions, only: Option<&str>) -> Result<()> {
    let mut found = false;
    for session in &sessions.session {
        if only.is_some_and(|name| name != session.name) {
            continue;
        }
        found = true;
        let fixture = &sessions.fixtures[&session.fixture];
        let exchanges = run_session(
            repo,
            python,
            "python",
            fixture,
            session.launch,
            &messages(session)?,
        )?;
        let recording = Recording {
            session: session.name.clone(),
            fixture: session.fixture.clone(),
            launch: session.launch,
            exchanges,
        };
        let path = mcp_dir(repo).join(format!("{}.jsonl", session.name));
        std::fs::write(&path, recording.to_jsonl())
            .with_context(|| format!("write {}", path.display()))?;
        println!("recorded {}", path.display());
    }
    ensure!(
        found || only.is_none(),
        "no session `{}`",
        only.unwrap_or_default()
    );
    Ok(())
}

fn replay(
    repo: &Path,
    python: &Path,
    sessions: &Sessions,
    engines: &[&str],
    files: &[PathBuf],
    show_approved: bool,
) -> Result<bool> {
    let ledger_path = repo.join("tests/golden/APPROVED_DIFFS.toml");
    let ledger = Ledger::parse(
        &std::fs::read_to_string(&ledger_path)
            .with_context(|| format!("read {}", ledger_path.display()))?,
    )
    .map_err(|error| anyhow::anyhow!("{}: {error}", ledger_path.display()))?;
    let mut tally = Tally::new(&ledger, show_approved);
    let mut replayed = std::collections::BTreeSet::new();
    for file in files {
        let text =
            std::fs::read_to_string(file).with_context(|| format!("read {}", file.display()))?;
        let recording =
            Recording::parse(&text).with_context(|| format!("read {}", file.display()))?;
        let fixture = sessions.fixtures.get(&recording.fixture).with_context(|| {
            format!(
                "{}: no fixture `{}` in sessions.toml",
                file.display(),
                recording.fixture
            )
        })?;
        replayed.insert(recording.session.clone());
        let sent: Vec<(String, Value)> = recording
            .exchanges
            .iter()
            .map(|exchange| (exchange.step.clone(), exchange.request.clone()))
            .collect();
        let mut python_live = None;
        for engine in engines {
            let live = run_session(repo, python, engine, fixture, recording.launch, &sent)?;
            // The Rust server against the Python server's live answers when
            // both run, else against the recording; Python always against
            // the recording.
            let oracle = match (*engine, &python_live) {
                ("python", _) | (_, None) => &recording.exchanges,
                (_, Some(answers)) => answers,
            };
            tally.judge(engine, &recording.session, oracle, &live);
            if *engine == "python" {
                python_live = Some(live);
            }
        }
    }
    // A complete run of the Rust server: an approval that applied nowhere is stale.
    let complete = sessions
        .session
        .iter()
        .all(|session| replayed.contains(&session.name));
    let (passed, lines) = tally.finish(complete, engines);
    for line in lines {
        println!("{line}");
    }
    Ok(passed)
}

/// The replay's verdict as it builds up: each answer compared, each
/// difference and approval, and at the end the approvals that went unused.
pub struct Tally<'a> {
    ledger: &'a Ledger,
    usage: Usage,
    show_approved: bool,
    compared: usize,
    failures: usize,
    lines: Vec<String>,
}

impl<'a> Tally<'a> {
    /// An empty tally against `ledger`; `show_approved` reports approvals too.
    pub fn new(ledger: &'a Ledger, show_approved: bool) -> Tally<'a> {
        Tally {
            ledger,
            usage: Usage::default(),
            show_approved,
            compared: 0,
            failures: 0,
            lines: Vec::new(),
        }
    }

    /// Compares `engine`'s `live` answers in `session` with `oracle`'s. The
    /// Python server is the oracle: only another engine's difference may be
    /// approved by the ledger.
    pub fn judge(&mut self, engine: &str, session: &str, oracle: &[Exchange], live: &[Exchange]) {
        let approve = engine != "python";
        for (expected, got) in oracle.iter().zip(live) {
            self.compared += 1;
            let case = format!("{session}/{}", expected.step);
            let report = compare_answers(
                &case,
                expected.response.as_ref(),
                got.response.as_ref(),
                approve.then_some(self.ledger),
                &mut self.usage,
            );
            if !report.equal {
                self.failures += 1;
                self.lines.push(format!("DIFFERENT {engine} {case}"));
                for difference in &report.differences {
                    self.lines.push(format!(
                        "  {} at {}:\n    expected {}\n    got      {}",
                        difference.kind.as_str(),
                        difference.pointer.as_deref().unwrap_or("(document)"),
                        excerpt(&difference.oracle),
                        excerpt(&difference.candidate)
                    ));
                }
            } else if self.show_approved && !report.approved.is_empty() {
                self.lines.push(format!("APPROVED {engine} {case}"));
                for approval in &report.approved {
                    self.lines.push(format!(
                        "  entry {} ({}): {}",
                        approval.entry, approval.rule, approval.reason
                    ));
                }
            }
        }
        if live.len() != oracle.len() {
            self.failures += 1;
            self.lines.push(format!(
                "DIFFERENT {engine} {session}: {} answers, expected {}",
                live.len(),
                oracle.len()
            ));
        }
    }

    /// Whether the replay passed, and what it reports. When `complete` (every
    /// session replayed) and the Rust server ran, a replay ledger entry
    /// ([`owns`]) that approved nothing is stale, and fails the replay.
    pub fn finish(mut self, complete: bool, engines: &[&str]) -> (bool, Vec<String>) {
        let mut stale = 0usize;
        if complete && engines.contains(&"rust") {
            for (index, entry) in self.ledger.entries.iter().enumerate() {
                if owns(entry) && !self.usage.is_used(index) {
                    stale += 1;
                    self.lines.push(format!(
                        "STALE ledger entry {} ({} {}): it approved nothing",
                        index + 1,
                        entry.case,
                        entry.rule_text
                    ));
                }
            }
        }
        self.lines.push(format!(
            "{} answers compared, {} different, {stale} stale approvals ({})",
            self.compared,
            self.failures,
            engines.join(" + ")
        ));
        (self.failures == 0 && stale == 0, self.lines)
    }
}

fn excerpt(text: &str) -> String {
    const LIMIT: usize = 400;
    if text.chars().count() > LIMIT {
        let cut: String = text.chars().take(LIMIT).collect();
        format!("{cut}…")
    } else {
        text.to_owned()
    }
}

/// Compares two answers to one message, as [`canonical`] documents, through
/// the comparator (and the ledger, when given).
pub fn compare_answers(
    case: &str,
    expected: Option<&Value>,
    got: Option<&Value>,
    ledger: Option<&Ledger>,
    usage: &mut Usage,
) -> opentide_compare::CaseReport {
    let document = |value: Option<&Value>| {
        let mut bytes =
            serde_json::to_vec_pretty(&value.map_or(Value::Null, canonical)).unwrap_or_default();
        bytes.push(b'\n');
        Run {
            stdout: bytes,
            ..Run::default()
        }
    };
    let empty = Ledger::default();
    opentide_compare::compare(
        Case {
            command: COMMAND,
            id: case,
        },
        &document(expected),
        &document(got),
        ledger.unwrap_or(&empty),
        usage,
    )
}

/// What a comparison sees of a message: text blocks and resource texts that
/// hold a JSON document parsed, every object's keys sorted.
pub fn canonical(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut sorted: BTreeMap<&String, Value> = BTreeMap::new();
            let parse_text = map.get("type").and_then(Value::as_str) == Some("text")
                || (map.contains_key("uri") && map.contains_key("text"));
            for (key, item) in map {
                let item = match (key.as_str(), item) {
                    ("wall_ms", Value::Number(_)) => json!("<MS>"),
                    ("text", Value::String(text)) if parse_text => {
                        match serde_json::from_str::<Value>(text) {
                            Ok(parsed @ (Value::Object(_) | Value::Array(_))) => {
                                json!({"json": canonical(&parsed)})
                            }
                            _ => item.clone(),
                        }
                    }
                    _ => canonical(item),
                };
                sorted.insert(key, item);
            }
            let mut out = Map::new();
            for (key, item) in sorted {
                out.insert(key.clone(), item);
            }
            Value::Object(out)
        }
        Value::Array(items) => Value::Array(items.iter().map(canonical).collect()),
        other => other.clone(),
    }
}

/// An answer as recorded: each path of `roots` (`(path, placeholder)`, the
/// longest first, as [`roots`] lists them) is its placeholder, the server's
/// version `<VERSION>`.
pub fn normalise(mut answer: Value, roots: &[(String, String)]) -> Value {
    if let Some(version) = answer.pointer_mut("/result/serverInfo/version") {
        *version = json!("<VERSION>");
    }
    replace_strings(&mut answer, roots);
    answer
}

/// The paths a recording hides, with the golden runner's machinery: the
/// workspace `<WS>` and the `opentide` package directory `<PACKAGE>`, each
/// also in its canonical spelling, the longest first so a path is never
/// half replaced.
pub fn roots(ws: &Path, package: &Path) -> Vec<(String, String)> {
    let ws = ws.to_path_buf();
    let package = package.to_path_buf();
    let mut roots =
        crate::golden::run::path_literals(&[(&ws, crate::golden::case::WS), (&package, PACKAGE)]);
    roots.sort_by(|a, b| b.0.len().cmp(&a.0.len()).then_with(|| a.cmp(b)));
    roots.dedup();
    roots
}

/// Placeholder for the installed `opentide` package's directory.
pub const PACKAGE: &str = "<PACKAGE>";

/// The directory of the `opentide` package `python` imports (its bundled
/// data is under it): `src/opentide` in an editable checkout, a
/// `site-packages` folder otherwise. Found without importing the package.
pub fn package_dir(python: &Path) -> Result<PathBuf> {
    let output = Command::new(python)
        .args([
            "-c",
            "import importlib.util as u; print(u.find_spec('opentide').submodule_search_locations[0])",
        ])
        .stderr(Stdio::inherit())
        .output()
        .with_context(|| format!("run {}", python.display()))?;
    ensure!(
        output.status.success(),
        "{} could not find the opentide package",
        python.display()
    );
    let dir = String::from_utf8(output.stdout).context("the package directory is not UTF-8")?;
    let dir = PathBuf::from(dir.trim_end_matches(['\r', '\n']));
    ensure!(
        dir.is_dir(),
        "{}: the opentide package is not a directory",
        dir.display()
    );
    Ok(dir)
}

fn replace_strings(value: &mut Value, roots: &[(String, String)]) {
    match value {
        Value::String(text) => {
            for (path, placeholder) in roots {
                if !path.is_empty() && text.contains(path.as_str()) {
                    *text = text.replace(path.as_str(), placeholder);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                replace_strings(item, roots);
            }
        }
        Value::Object(map) => {
            for item in map.values_mut() {
                replace_strings(item, roots);
            }
        }
        _ => {}
    }
}

/// Runs one session against a fresh server of `engine` on a fresh copy of
/// `fixture`: each message sent once the one before it was answered.
pub fn run_session(
    repo: &Path,
    python: &Path,
    engine: &str,
    fixture: &FixtureSpec,
    launch: Launch,
    messages: &[(String, Value)],
) -> Result<Vec<Exchange>> {
    let scratch = tempfile::Builder::new()
        .prefix("opentide-mcp-")
        .tempdir_in(crate::golden::run::temp_parent())
        .context("create a scratch directory")?;
    let ws = scratch.path().join("ws");
    let home = scratch.path().join("home");
    std::fs::create_dir_all(&ws)?;
    std::fs::create_dir_all(home.join("tmp"))?;
    fixture.materialise(repo, &ws)?;
    let roots = roots(&ws, &package_dir(python)?);
    let outside = scratch.path().join("outside");
    std::fs::create_dir_all(&outside)?;
    let mut server = Server::start(python, engine, launch, &ws, &outside, &home)?;
    let mut exchanges = Vec::new();
    for (step, message) in messages {
        let response = server
            .send(message)
            .with_context(|| format!("{engine} server, step `{step}`"))?;
        exchanges.push(Exchange {
            step: step.clone(),
            request: message.clone(),
            response: response.map(|answer| normalise(answer, &roots)),
        });
    }
    server.finish()?;
    Ok(exchanges)
}

/// A running `opentide mcp start`.
struct Server {
    child: Child,
    stdin: Option<ChildStdin>,
    lines: Receiver<String>,
    stderr: Arc<Mutex<String>>,
}

impl Server {
    fn start(
        python: &Path,
        engine: &str,
        launch: Launch,
        ws: &Path,
        outside: &Path,
        home: &Path,
    ) -> Result<Server> {
        let mut command = Command::new(python);
        command.args(["-m", "opentide"]);
        command
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("HOME", home)
            .env("TMPDIR", home.join("tmp"))
            .env("TZ", "UTC")
            .env("LANG", "C.UTF-8")
            .env("PYTHONHASHSEED", "0")
            .env("CI", "true")
            .env("OPENTIDE_ENGINE", engine)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            // No network: a proxy that refuses every connection.
            .env("HTTP_PROXY", "http://127.0.0.1:9")
            .env("HTTPS_PROXY", "http://127.0.0.1:9")
            .env("http_proxy", "http://127.0.0.1:9")
            .env("https_proxy", "http://127.0.0.1:9")
            .env("NO_PROXY", "");
        match launch {
            Launch::Workspace => {
                command
                    .current_dir(ws)
                    .env("OPENTIDE_REPO_ROOT", ws)
                    .env("OPENTIDE_TIDE_WORKSPACE", ws);
            }
            Launch::RepoOption => {
                command.arg("--repo").arg(ws).current_dir(outside);
            }
            Launch::PluginRoot => {
                command.current_dir(ws).env("PWD", ws);
            }
        }
        command
            .args(["mcp", "start"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command
            .spawn()
            .with_context(|| format!("start {} -m opentide mcp start", python.display()))?;
        let stdout = child.stdout.take().context("no stdout")?;
        let stderr = child.stderr.take().context("no stderr")?;
        let (sender, lines) = channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                if sender.send(line).is_err() {
                    break;
                }
            }
        });
        let captured = Arc::new(Mutex::new(String::new()));
        let sink = Arc::clone(&captured);
        std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines() {
                let Ok(line) = line else { break };
                if let Ok(mut text) = sink.lock() {
                    text.push_str(&line);
                    text.push('\n');
                }
            }
        });
        Ok(Server {
            stdin: child.stdin.take(),
            child,
            lines,
            stderr: captured,
        })
    }

    fn stderr(&self) -> String {
        self.stderr
            .lock()
            .map(|text| text.clone())
            .unwrap_or_default()
    }

    /// Sends `message`; its answer, `None` for a notification.
    fn send(&mut self, message: &Value) -> Result<Option<Value>> {
        let stdin = self.stdin.as_mut().context("stdin closed")?;
        writeln!(stdin, "{message}")?;
        stdin.flush()?;
        let Some(id) = message.get("id") else {
            return Ok(None);
        };
        loop {
            let line = match self.lines.recv_timeout(ANSWER_TIMEOUT) {
                Ok(line) => line,
                Err(RecvTimeoutError::Timeout) => {
                    bail!(
                        "no answer in {ANSWER_TIMEOUT:?}; stderr:\n{}",
                        self.stderr()
                    )
                }
                Err(RecvTimeoutError::Disconnected) => {
                    bail!("the server closed stdout; stderr:\n{}", self.stderr())
                }
            };
            if line.trim().is_empty() {
                continue;
            }
            let frame: Value = serde_json::from_str(&line)
                .with_context(|| format!("stdout holds a line that is not JSON-RPC: {line}"))?;
            ensure!(
                frame.get("jsonrpc").and_then(Value::as_str) == Some("2.0"),
                "stdout holds a frame that is not JSON-RPC 2.0: {line}"
            );
            if frame.get("id") == Some(id) {
                return Ok(Some(frame));
            }
        }
    }

    /// Closes stdin, waits for the server to exit, and checks that stdout
    /// held nothing but JSON-RPC.
    fn finish(mut self) -> Result<()> {
        drop(self.stdin.take());
        let status = self.child.wait()?;
        while let Ok(line) = self.lines.recv_timeout(Duration::from_secs(10)) {
            if line.trim().is_empty() {
                continue;
            }
            let frame: Value = serde_json::from_str(&line)
                .with_context(|| format!("stdout holds a line that is not JSON-RPC: {line}"))?;
            ensure!(
                frame.get("jsonrpc").and_then(Value::as_str) == Some("2.0"),
                "stdout holds a frame that is not JSON-RPC 2.0: {line}"
            );
        }
        ensure!(
            status.success(),
            "the server exited with {status}; stderr:\n{}",
            self.stderr()
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_json_text_block_is_compared_as_its_document() {
        let left = json!({"content": [{"type": "text", "text": "{\"b\": 1, \"a\": [1, 2]}"}]});
        let right = json!({"content": [{"text": "{\"a\":[1,2],\"b\":1}", "type": "text"}]});
        assert_eq!(canonical(&left), canonical(&right));
        let other = json!({"content": [{"type": "text", "text": "{\"a\":[2,1],\"b\":1}"}]});
        assert_ne!(canonical(&left), canonical(&other));
    }

    #[test]
    fn a_reports_wall_time_is_hidden_and_nothing_else() {
        let left = json!({"stats": {"wall_ms": 65.0, "objects_checked": 1}});
        let right = json!({"stats": {"wall_ms": 738.87, "objects_checked": 1}});
        assert_eq!(canonical(&left), canonical(&right));
        let other = json!({"stats": {"wall_ms": 65.0, "objects_checked": 2}});
        assert_ne!(canonical(&left), canonical(&other));
    }

    #[test]
    fn a_plain_text_block_stays_text() {
        let block = json!({"type": "text", "text": "Unknown tool: x"});
        assert_eq!(canonical(&block), block);
        // A number or a string that parses as JSON is still text.
        let block = json!({"type": "text", "text": "42"});
        assert_eq!(canonical(&block), block);
    }

    #[test]
    fn resource_texts_are_parsed_and_other_text_fields_are_not() {
        let contents = json!({"uri": "opentide://x", "text": "[1]", "mimeType": "text/plain"});
        assert_eq!(canonical(&contents)["text"], json!({"json": [1]}));
        // A tool's own "text" field is data, not a block.
        let payload = json!({"text": "[1]", "other": 1});
        assert_eq!(canonical(&payload)["text"], json!("[1]"));
    }

    #[test]
    fn normalise_hides_the_workspace_and_the_version_only() {
        let answer = json!({
            "result": {
                "serverInfo": {"name": "opentide", "version": "1.2.3"},
                "path": "/tmp/opentide-mcp-x/ws/objects/a.yaml",
                "other": "1.2.3",
            }
        });
        let normalised = normalise(answer, &[("/tmp/opentide-mcp-x/ws".into(), "<WS>".into())]);
        assert_eq!(normalised["result"]["serverInfo"]["version"], "<VERSION>");
        assert_eq!(normalised["result"]["path"], "<WS>/objects/a.yaml");
        assert_eq!(normalised["result"]["other"], "1.2.3");
    }

    #[test]
    fn the_package_directory_reads_package_wherever_the_checkout_is() {
        // resources/index names the bundled data's directories: a recording
        // made in one checkout must replay in another (CI's).
        let scratch = tempfile::tempdir().unwrap();
        let ws = scratch.path().join("tmp/opentide-mcp-x/ws");
        let package = scratch.path().join("checkout/src/opentide");
        std::fs::create_dir_all(&ws).unwrap();
        std::fs::create_dir_all(&package).unwrap();
        let roots = roots(&ws, &package);
        let index = format!(
            r#"{{"vocabularies": "{}/data/vocabulary", "file": "{}/objects/a.yaml"}}"#,
            package.display(),
            ws.display()
        );
        let answer = json!({"result": {"contents": [{"uri": "opentide://index", "text": index}]}});
        let normalised = normalise(answer, &roots);
        let text = normalised["result"]["contents"][0]["text"]
            .as_str()
            .unwrap();
        let document: Value = serde_json::from_str(text).unwrap();
        assert_eq!(document["vocabularies"], "<PACKAGE>/data/vocabulary");
        assert_eq!(document["file"], "<WS>/objects/a.yaml");
        assert!(!text.contains(&scratch.path().display().to_string()));
    }

    #[test]
    fn the_longest_root_is_replaced_first() {
        let scratch = tempfile::tempdir().unwrap();
        // A package inside the workspace must read <PACKAGE>, not <WS>/...
        let ws = scratch.path().join("ws");
        let package = ws.join("venv/opentide");
        std::fs::create_dir_all(&package).unwrap();
        let roots = roots(&ws, &package);
        let answer = json!({"result": format!("{}/data", package.display())});
        assert_eq!(normalise(answer, &roots)["result"], "<PACKAGE>/data");
    }

    #[test]
    fn a_recording_round_trips() {
        let recording = Recording {
            session: "s".into(),
            fixture: "f".into(),
            launch: Launch::Workspace,
            exchanges: vec![
                Exchange {
                    step: "initialized".into(),
                    request: json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
                    response: None,
                },
                Exchange {
                    step: "ping".into(),
                    request: json!({"jsonrpc": "2.0", "id": 1, "method": "ping"}),
                    response: Some(json!({"jsonrpc": "2.0", "id": 1, "result": {}})),
                },
            ],
        };
        assert_eq!(Recording::parse(&recording.to_jsonl()).unwrap(), recording);
        assert!(!recording.to_jsonl().contains("launch"));
        let mut outside = recording.clone();
        outside.launch = Launch::RepoOption;
        assert!(
            outside
                .to_jsonl()
                .starts_with(r#"{"fixture":"f","launch":"repo-option","session":"s"}"#)
        );
        assert_eq!(Recording::parse(&outside.to_jsonl()).unwrap(), outside);
        assert!(Recording::parse(r#"{"session":"s","fixture":"f","launch":"x"}"#).is_err());
    }

    #[test]
    fn messages_frame_each_step_after_the_handshake() {
        let session = SessionSpec {
            name: "s".into(),
            fixture: "f".into(),
            protocol_version: Some("2024-11-05".into()),
            launch: Launch::Workspace,
            steps: vec![Step {
                id: "ping".into(),
                message: r#"{"method": "ping"}"#.into(),
            }],
        };
        let sent = messages(&session).unwrap();
        assert_eq!(sent[0].1["params"]["protocolVersion"], "2024-11-05");
        assert_eq!(sent[1].1.get("id"), None);
        assert_eq!(
            sent[2].1,
            json!({"jsonrpc": "2.0", "id": 1, "method": "ping"})
        );
    }

    #[test]
    fn a_difference_is_reported_unless_the_ledger_approves_it() {
        let expected = json!({"jsonrpc": "2.0", "id": 1, "result": {"a": 1}});
        let got = json!({"jsonrpc": "2.0", "id": 1, "result": {"a": 2}});
        let mut usage = Usage::default();
        let report = compare_answers("s/x", Some(&expected), Some(&got), None, &mut usage);
        assert!(!report.equal);
        let ledger = Ledger::parse(
            r#"
[[diff]]
command = "mcp start"
case = "s/x"
target = "stdout"
rule = "json:/result/a"
oracle = '1'
candidate = '2'
reason = "r"
issue = "https://github.com/opentidehq/opentide/issues/829"
changelog = "c"
"#,
        )
        .unwrap();
        let report = compare_answers(
            "s/x",
            Some(&expected),
            Some(&got),
            Some(&ledger),
            &mut usage,
        );
        assert!(report.equal, "{report:?}");
        assert!(usage.is_used(0));
    }

    #[test]
    fn the_replay_owns_its_sessions_entries_and_not_the_golden_cases() {
        let ledger = Ledger::parse(
            r#"
[[diff]]
command = "mcp start"
case = "tools-explain/explain-bad-type"
target = "stdout"
rule = "json:/a"
oracle = '1'
candidate = '2'
reason = "r"
issue = "https://github.com/opentidehq/opentide/issues/829"
changelog = "c"

[[diff]]
command = "mcp start"
case = "mcp.start/json/none/help"
target = "stdout"
rule = "json:/a"
oracle = '1'
candidate = '2'
reason = "r"
issue = "https://github.com/opentidehq/opentide/issues/829"
changelog = "c"

[[diff]]
command = "explain"
case = "tools-explain/x"
target = "stdout"
rule = "json:/a"
oracle = '1'
candidate = '2'
reason = "r"
issue = "https://github.com/opentidehq/opentide/issues/829"
changelog = "c"
"#,
        )
        .unwrap();
        let owned: Vec<bool> = ledger.entries.iter().map(owns).collect();
        assert_eq!(owned, [true, false, false]);
    }

    const APPROVAL: &str = r#"
[[diff]]
command = "mcp start"
case = "s/x"
target = "stdout"
rule = "json:/result/a"
oracle = '1'
candidate = '2'
reason = "r"
issue = "https://github.com/opentidehq/opentide/issues/829"
changelog = "c"
"#;

    fn answered(step: &str, a: i64) -> Vec<Exchange> {
        vec![Exchange {
            step: step.into(),
            request: json!({"jsonrpc": "2.0", "id": 1, "method": "m"}),
            response: Some(json!({"jsonrpc": "2.0", "id": 1, "result": {"a": a}})),
        }]
    }

    #[test]
    fn the_replay_passes_on_equal_answers_and_fails_on_a_difference() {
        let ledger = Ledger::default();
        let mut tally = Tally::new(&ledger, false);
        tally.judge("rust", "s", &answered("x", 1), &answered("x", 1));
        let (passed, lines) = tally.finish(true, &["rust"]);
        assert!(passed, "{lines:?}");
        let mut tally = Tally::new(&ledger, false);
        tally.judge("rust", "s", &answered("x", 1), &answered("x", 2));
        let (passed, lines) = tally.finish(true, &["rust"]);
        assert!(!passed);
        assert_eq!(lines[0], "DIFFERENT rust s/x");
        assert!(lines.last().unwrap().contains("1 different"), "{lines:?}");
        // A server that answered fewer messages than were recorded fails too.
        let mut tally = Tally::new(&ledger, false);
        tally.judge("rust", "s", &answered("x", 1), &[]);
        assert!(!tally.finish(true, &["rust"]).0);
    }

    #[test]
    fn a_rust_approval_never_excuses_the_python_server() {
        let ledger = Ledger::parse(APPROVAL).unwrap();
        let mut tally = Tally::new(&ledger, true);
        tally.judge("rust", "s", &answered("x", 1), &answered("x", 2));
        let (passed, lines) = tally.finish(true, &["rust"]);
        assert!(passed, "{lines:?}");
        assert_eq!(lines[0], "APPROVED rust s/x");
        let mut tally = Tally::new(&ledger, false);
        tally.judge("python", "s", &answered("x", 1), &answered("x", 2));
        let (passed, lines) = tally.finish(true, &["python"]);
        assert!(!passed);
        assert_eq!(lines[0], "DIFFERENT python s/x");
    }

    #[test]
    fn an_approval_unused_by_a_complete_rust_replay_is_stale() {
        let ledger = Ledger::parse(APPROVAL).unwrap();
        let mut tally = Tally::new(&ledger, false);
        tally.judge("rust", "s", &answered("x", 1), &answered("x", 1));
        let (passed, lines) = tally.finish(true, &["python", "rust"]);
        assert!(!passed);
        assert!(
            lines[0].starts_with("STALE ledger entry 1 (s/x "),
            "{lines:?}"
        );
        // Only a complete replay of the Rust server can tell.
        let mut tally = Tally::new(&ledger, false);
        tally.judge("rust", "s", &answered("x", 1), &answered("x", 1));
        assert!(tally.finish(false, &["rust"]).0);
        let mut tally = Tally::new(&ledger, false);
        tally.judge("python", "s", &answered("x", 1), &answered("x", 1));
        assert!(tally.finish(true, &["python"]).0);
    }

    #[test]
    fn the_committed_sessions_are_well_formed() {
        let repo = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let sessions = load_sessions(repo).unwrap();
        assert!(!sessions.session.is_empty());
    }
}
