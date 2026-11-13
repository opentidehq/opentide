//! One `run`: which implementation runs it, and the document it answers with.
//!
//! [`HostRunner`] runs a request as `opentide --json <argv>` would in a new
//! process: every run is Rust's, in this process
//! ([`crate::embed::run_captured`]), with the run's environment and working
//! directory (UC-6.0d, #841: the Rust core is opentide's one implementation).
//! A read-only run keeps its workspace warm in the
//! session ([`opentide_workspace::session`]) for the next one.

use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

use crate::envelope::{Failure, INTERRUPTED_EXIT_CODE, Outcome, USAGE_EXIT_CODE, code};
use crate::json::Json;

/// `failure.code` of a run that never started (a missing `cwd`) or printed nothing.
pub const COMMAND_FAILED: &str = "command_failed";
/// `failure.code` of a cancelled run.
pub const INTERRUPTED: &str = "interrupted";

/// Commands that never write the workspace, by their first word: the
/// workspace a run of one loads is kept for the next run.
pub const READ_ONLY_COMMANDS: &[&str] = &["validate", "lint", "info", "explain", "commands"];
/// Options that make a read-only command write (`validate --fix`).
pub const WRITING_OPTIONS: &[&str] = &["--fix"];
/// Variables a run resolving its workspace from `cwd` must not inherit.
const WORKSPACE_VARIABLES: &[&str] = &["OPENTIDE_REPO_ROOT", "OPENTIDE_TIDE_WORKSPACE"];

/// A `run` request's parameters, checked.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RunRequest {
    /// The command line, without `opentide` and the leading `--json`.
    pub argv: Vec<String>,
    /// The working directory, when the request names one.
    pub cwd: Option<String>,
    /// Variables over the server's own, in order (a later one wins).
    pub env: Option<Vec<(String, String)>>,
}

/// What `run` answers with.
#[derive(Clone, Debug, PartialEq)]
pub enum RunOutcome {
    /// A document this process built, and the exit code.
    Built {
        /// The document.
        document: Json,
        /// The exit code.
        exit_code: i32,
    },
}

impl RunOutcome {
    /// `run`'s result as JSON text.
    pub fn result_text(&self) -> String {
        match self {
            RunOutcome::Built {
                document,
                exit_code,
            } => format!(
                "{{\"document\":{},\"exit_code\":{exit_code}}}",
                compact(document)
            ),
        }
    }

    /// The document.
    pub fn document(&self) -> Json {
        match self {
            RunOutcome::Built { document, .. } => document.clone(),
        }
    }
}

/// `json` on one line, as the protocol writes it.
pub fn compact(json: &Json) -> String {
    let mut text = crate::json::document_text(json, false);
    text.pop();
    text
}

/// Where a run's progress events go, each as JSON text.
pub type EventSink = Arc<dyn Fn(String) + Send + Sync>;

/// One run in flight, and what a cancel needs to reach it.
#[derive(Debug, Default)]
pub struct Job {
    state: Mutex<JobState>,
}

#[derive(Debug, Default)]
struct JobState {
    cancelled: bool,
    finished: bool,
}

impl Job {
    /// Records a cancel; whether the run is still going (its command has
    /// not returned), so that it must be interrupted.
    pub fn cancel(&self) -> bool {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let going = !state.finished && !state.cancelled;
        state.cancelled = true;
        going
    }

    /// The command has returned: a cancel from now on changes nothing.
    /// Whether it was cancelled before.
    pub fn finish(&self) -> bool {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        state.finished = true;
        state.cancelled
    }

    /// Whether a cancel came.
    pub fn cancelled(&self) -> bool {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .cancelled
    }
}

/// A run's variables and directory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RustRun {
    /// Every variable the run sees.
    pub env: Vec<(String, String)>,
    /// Its working directory.
    pub cwd: String,
}

/// How a run goes, before it starts.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Plan {
    /// The command path (`["validate", "query"]`).
    pub words: Vec<String>,
    /// Why the server cannot run it (a protocol command, `tui`).
    pub refused: Option<String>,
    /// Whether it only reads, so its workspace stays warm.
    pub keep: bool,
    /// Its run; [`HostRunner`] always plans one, a test's runner may not.
    pub rust: Option<RustRun>,
}

/// What runs the requests: [`HostRunner`], or a test's.
pub trait Runner: Send + Sync {
    /// How `request` goes: its words, a refusal, warm or not.
    fn plan(&self, request: &RunRequest) -> Plan;

    /// Runs `request`, planned as `plan`; never fails for the command's sake.
    /// `job.finish()` is called once the command has returned.
    fn run(
        &self,
        request: &RunRequest,
        plan: &Plan,
        job: &Arc<Job>,
        event: EventSink,
    ) -> RunOutcome;

    /// Interrupts the run in progress.
    fn interrupt(&self);

    /// Drops whatever `paths` may have made stale.
    fn invalidate(&self, paths: &[String]);
}

/// The runner of `opentide serve`.
pub struct HostRunner {
    base_env: Vec<(String, String)>,
    cwd: PathBuf,
    version: String,
    root: clap::Command,
}

impl HostRunner {
    /// A runner whose runs start from `base_env` and `cwd`.
    pub fn new(base_env: Vec<(String, String)>, cwd: PathBuf, version: &str) -> HostRunner {
        HostRunner {
            base_env,
            cwd,
            version: version.to_owned(),
            root: crate::catalog::root(),
        }
    }

    /// The variables a run sees: the server's own, then the request's.
    pub fn run_environment(&self, request: &RunRequest) -> Vec<(String, String)> {
        run_environment(&self.base_env, request)
    }

    /// How `request` goes: with the request's environment over the server's,
    /// and progress events on stderr.
    fn own_plan(&self, request: &RunRequest) -> Plan {
        let words = crate::hoist::command_words(&self.root, &request.argv);
        let mut env = self.run_environment(request);
        env.retain(|(name, _)| name != "OPENTIDE_PROGRESS");
        env.push(("OPENTIDE_PROGRESS".into(), "json".into()));
        let cwd = request
            .cwd
            .clone()
            .filter(|cwd| !cwd.is_empty())
            .unwrap_or_else(|| self.cwd.display().to_string());
        Plan {
            refused: refusal(&words),
            keep: keeps_workspace(&words, &request.argv),
            rust: Some(RustRun { env, cwd }),
            words,
        }
    }

    fn run_rust(
        &self,
        request: &RunRequest,
        plan: &Plan,
        rust: &RustRun,
        job: &Job,
        event: &EventSink,
    ) -> RunOutcome {
        let directory = normalised(&rust.cwd);
        if !directory.is_dir() {
            let message = format!(
                "[Errno 2] No such file or directory: {:?}",
                directory.display().to_string()
            );
            return failure(&plan.words, &message, 1);
        }
        let mut argv = vec!["--json".to_owned()];
        argv.extend(request.argv.iter().cloned());
        let env = crate::env::Env::from_pairs(rust.env.iter().cloned());
        let captured = if job.cancelled() {
            None
        } else {
            let run = std::panic::AssertUnwindSafe(|| {
                crate::embed::run_captured(&argv, &env, &directory, &self.version, plan.keep)
            });
            Some(std::panic::catch_unwind(run))
        };
        let cancelled = job.finish();
        if !plan.keep {
            // It may have written any workspace (`--repo` names one): keep none.
            crate::embed::clear_workspaces();
        }
        let captured = match captured {
            Some(Ok(captured)) if !cancelled => captured,
            Some(Err(_)) => {
                let problem = Failure::new(code::INTERNAL, "the Rust run panicked");
                let outcome = Outcome::failed(&plan.words.join(" "), 1, problem);
                return RunOutcome::Built {
                    document: outcome.document(0),
                    exit_code: 1,
                };
            }
            _ => return failure(&plan.words, "Interrupted", INTERRUPTED_EXIT_CODE),
        };
        forward_stderr(&captured.stderr, event);
        let text = String::from_utf8_lossy(&captured.stdout);
        document(&plan.words, &text, captured.exit_code)
    }
}

impl Runner for HostRunner {
    fn plan(&self, request: &RunRequest) -> Plan {
        self.own_plan(request)
    }

    fn run(
        &self,
        request: &RunRequest,
        plan: &Plan,
        job: &Arc<Job>,
        event: EventSink,
    ) -> RunOutcome {
        if let Some(message) = &plan.refused {
            return usage(&plan.words, message);
        }
        match &plan.rust {
            Some(rust) => self.run_rust(request, plan, rust, job, &event),
            None => {
                job.finish();
                failure(&plan.words, "No implementation runs this command", 1)
            }
        }
    }

    fn interrupt(&self) {
        crate::embed::interrupt();
    }

    fn invalidate(&self, paths: &[String]) {
        if paths.is_empty() {
            return;
        }
        let resolved: Vec<PathBuf> = paths.iter().map(PathBuf::from).collect();
        // Taken into account at each warm workspace's next run.
        crate::embed::invalidate_workspaces(&resolved);
    }
}

/// The variables a run sees: `base`, then the request's `env`. A run that
/// names its `cwd` resolves its workspace from it, not from an inherited
/// `OPENTIDE_REPO_ROOT` (an explicit `--repo` still wins over both).
pub fn run_environment(base: &[(String, String)], request: &RunRequest) -> Vec<(String, String)> {
    let cwd_given = request.cwd.as_deref().is_some_and(|cwd| !cwd.is_empty());
    let mut values: Vec<(String, String)> = base
        .iter()
        .filter(|(name, _)| !(cwd_given && WORKSPACE_VARIABLES.contains(&name.as_str())))
        .cloned()
        .collect();
    let env = request.env.as_deref().unwrap_or_default();
    for (name, value) in env {
        values.retain(|(existing, _)| existing != name);
        values.push((name.clone(), value.clone()));
    }
    if cwd_given && env.iter().any(|(name, _)| name == "OPENTIDE_REPO_ROOT") {
        values.retain(|(name, _)| name != "OPENTIDE_REPO_ROOT");
    }
    values
}

/// Why the server refuses a run of `words`: a protocol command would read
/// its stdin, `tui` would draw on a terminal it has not got.
pub fn refusal(words: &[String]) -> Option<String> {
    let first_two: Vec<&str> = words.iter().take(2).map(String::as_str).collect();
    let protocol = crate::mode::PROTOCOL_COMMANDS.contains(&first_two.as_slice());
    (protocol || words.first().map(String::as_str) == Some("tui"))
        .then(|| format!("opentide {} cannot run under serve", words.join(" ")))
}

/// Whether a run of `argv` (path `words`) only reads its workspace.
pub fn keeps_workspace(words: &[String], argv: &[String]) -> bool {
    if !words
        .first()
        .is_some_and(|word| READ_ONLY_COMMANDS.contains(&word.as_str()))
    {
        return false;
    }
    let options = argv.split(|token| token == "--").next().unwrap_or_default();
    !options.iter().any(|option| {
        let name = option.split('=').next().unwrap_or_default();
        WRITING_OPTIONS.contains(&name)
    })
}

/// `path` as Python's `Path` prints it: no `.` parts, no repeated or
/// trailing separator.
fn normalised(path: &str) -> PathBuf {
    let mut out = PathBuf::new();
    for component in Path::new(path).components() {
        if component != Component::CurDir {
            out.push(component);
        }
    }
    if out.as_os_str().is_empty() {
        out.push(".");
    }
    out
}

/// A Rust run's stderr: progress events to `event`, every other line to
/// this process's stderr.
pub fn forward_stderr(stderr: &[u8], event: &EventSink) {
    use std::io::Write;
    let text = String::from_utf8_lossy(stderr);
    let mut rest = String::new();
    for line in text.split_inclusive('\n') {
        let parsed = if line.starts_with('{') {
            Json::parse(line.trim_end()).ok()
        } else {
            None
        };
        match parsed {
            Some(object @ Json::Object(_)) if object.get("event").is_some() => {
                event(compact(&object));
            }
            _ => rest.push_str(line),
        }
    }
    if !rest.is_empty() {
        let mut err = std::io::stderr().lock();
        let _ignored = err.write_all(rest.as_bytes());
        let _ignored = err.flush();
    }
}

/// The document `text` holds, or one built for a run that printed none.
pub fn document(words: &[String], text: &str, exit_code: i32) -> RunOutcome {
    let stripped = text.trim();
    if !stripped.is_empty() {
        return match Json::parse(stripped) {
            Ok(document @ Json::Object(_)) => RunOutcome::Built {
                document,
                exit_code,
            },
            // Help or a version line: text, not a document.
            _ => text_document(words, text, exit_code),
        };
    }
    if exit_code == INTERRUPTED_EXIT_CODE {
        failure(words, "Interrupted", exit_code)
    } else {
        failure(words, "The command printed no document", exit_code)
    }
}

/// The envelope's own keys after `payload`, as the Python CLI's `envelope` adds them.
fn envelope(
    mut payload: Vec<(String, Json)>,
    words: &[String],
    exit_code: i32,
    failure: Option<Failure>,
) -> Json {
    payload.push((
        "schema_version".into(),
        Json::Int(crate::envelope::SCHEMA_VERSION),
    ));
    payload.push(("command".into(), Json::str(words.join(" "))));
    payload.push(("duration_ms".into(), Json::Int(0)));
    payload.push(("exit_code".into(), Json::Int(i64::from(exit_code))));
    payload.push(("summary".into(), Json::Object(Vec::new())));
    payload.push(("next_actions".into(), Json::Array(Vec::new())));
    payload.push((
        "failure".into(),
        failure.as_ref().map_or(Json::Null, Failure::to_json),
    ));
    Json::Object(payload)
}

fn text_document(words: &[String], text: &str, exit_code: i32) -> RunOutcome {
    let ok = exit_code == 0;
    let message = text
        .lines()
        .find(|line| !line.trim().is_empty())
        .unwrap_or_default()
        .trim()
        .to_owned();
    let status = if ok { "completed" } else { "failed" };
    let mut payload = vec![
        ("ok".to_owned(), Json::Bool(ok)),
        ("status".to_owned(), Json::str(status)),
        ("message".to_owned(), Json::str(&message)),
        ("text".to_owned(), Json::str(text)),
    ];
    let failure = (!ok).then(|| Failure::new(COMMAND_FAILED, message.clone()));
    if !ok {
        payload.push(("error".to_owned(), Json::str(&message)));
    }
    RunOutcome::Built {
        document: envelope(payload, words, exit_code, failure),
        exit_code,
    }
}

/// A run that failed before or without its command's document.
pub fn failure(words: &[String], message: &str, exit_code: i32) -> RunOutcome {
    let code = if exit_code == INTERRUPTED_EXIT_CODE {
        INTERRUPTED
    } else {
        COMMAND_FAILED
    };
    let payload = vec![
        ("error".to_owned(), Json::str(message)),
        ("ok".to_owned(), Json::Bool(false)),
        ("status".to_owned(), Json::str("failed")),
        ("message".to_owned(), Json::str(message)),
    ];
    RunOutcome::Built {
        document: envelope(payload, words, exit_code, Some(Failure::new(code, message))),
        exit_code,
    }
}

/// A run the server refuses: a usage error, exit 2.
pub fn usage(words: &[String], message: &str) -> RunOutcome {
    let payload = vec![
        ("error".to_owned(), Json::str(message)),
        ("ok".to_owned(), Json::Bool(false)),
        ("status".to_owned(), Json::str("failed")),
        ("message".to_owned(), Json::str(message)),
    ];
    RunOutcome::Built {
        document: envelope(
            payload,
            words,
            USAGE_EXIT_CODE,
            Some(Failure::new(code::USAGE_ERROR, message)),
        ),
        exit_code: USAGE_EXIT_CODE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(line: &str) -> Vec<String> {
        line.split_whitespace().map(str::to_owned).collect()
    }

    #[test]
    fn a_fix_is_not_read_only() {
        assert!(keeps_workspace(
            &words("validate"),
            &words("validate --file x")
        ));
        assert!(keeps_workspace(&words("lint"), &words("--repo r lint")));
        assert!(!keeps_workspace(
            &words("validate"),
            &words("validate --fix")
        ));
        assert!(!keeps_workspace(&words("lint"), &words("lint --fix=true")));
        assert!(keeps_workspace(
            &words("validate"),
            &words("validate -- --fix")
        ));
        assert!(!keeps_workspace(&words("generate"), &words("generate")));
        assert!(!keeps_workspace(
            &words("deploy"),
            &words("deploy --dry-run")
        ));
    }

    /// A request runs in the server's directory, its variables over the
    /// server's, with progress events on stderr whatever the request asks.
    #[test]
    fn every_run_is_planned_with_progress_events() {
        let runner = HostRunner::new(
            vec![("NO_COLOR".into(), "1".into())],
            PathBuf::from("/w"),
            "0.0.0",
        );
        let request = RunRequest {
            argv: words("--repo r validate --file x"),
            env: Some(vec![
                ("NO_COLOR".into(), "0".into()),
                ("OPENTIDE_PROGRESS".into(), "off".into()),
            ]),
            ..RunRequest::default()
        };
        let plan = runner.plan(&request);
        assert_eq!(plan.words, words("validate"));
        assert!(plan.keep);
        let rust = plan.rust.unwrap();
        assert_eq!(rust.cwd, "/w");
        let named = |variable: &str| -> Vec<&str> {
            rust.env
                .iter()
                .filter(|(name, _)| name == variable)
                .map(|(_, value)| value.as_str())
                .collect()
        };
        assert_eq!(named("NO_COLOR"), ["0"]);
        assert_eq!(named("OPENTIDE_PROGRESS"), ["json"]);
        let refused = runner.plan(&RunRequest {
            argv: words("tui"),
            ..RunRequest::default()
        });
        assert!(refused.refused.is_some());
    }

    #[test]
    fn protocol_commands_and_tui_are_refused() {
        for line in ["serve", "mcp start", "lsp start", "tui"] {
            assert_eq!(
                refusal(&words(line)).as_deref(),
                Some(format!("opentide {line} cannot run under serve").as_str())
            );
        }
        assert!(refusal(&words("mcp")).is_none());
        assert!(refusal(&words("info")).is_none());
    }

    #[test]
    fn a_cwd_drops_the_inherited_workspace() {
        let base = vec![
            ("OPENTIDE_REPO_ROOT".to_owned(), "/a".to_owned()),
            ("OPENTIDE_TIDE_WORKSPACE".to_owned(), "/a".to_owned()),
            ("HOME".to_owned(), "/h".to_owned()),
        ];
        let plain = RunRequest {
            argv: words("info"),
            ..RunRequest::default()
        };
        assert_eq!(run_environment(&base, &plain), base);
        let elsewhere = RunRequest {
            argv: words("info"),
            cwd: Some("/b".into()),
            env: Some(vec![("OPENTIDE_REPO_ROOT".into(), "/c".into())]),
        };
        assert_eq!(
            run_environment(&base, &elsewhere),
            vec![("HOME".to_owned(), "/h".to_owned())]
        );
        let named = RunRequest {
            argv: words("info"),
            env: Some(vec![("OPENTIDE_REPO_ROOT".into(), "/c".into())]),
            ..RunRequest::default()
        };
        assert_eq!(run_environment(&base, &named)[2].1, "/c");
    }

    #[test]
    fn documents_are_built_as_the_python_host_built_them() {
        let interrupted = failure(&words("validate"), "Interrupted", 130);
        assert_eq!(
            interrupted.result_text(),
            "{\"document\":{\"error\":\"Interrupted\",\"ok\":false,\"status\":\"failed\",\
             \"message\":\"Interrupted\",\"schema_version\":1,\"command\":\"validate\",\
             \"duration_ms\":0,\"exit_code\":130,\"summary\":{},\"next_actions\":[],\
             \"failure\":{\"code\":\"interrupted\",\"message\":\"Interrupted\",\"argument\":null,\
             \"suggestion\":null,\"crash_log\":null}},\"exit_code\":130}"
        );
        let help = document(&words("info"), "\nUsage: opentide info\n", 0);
        let help = help.document();
        assert_eq!(
            help.get("message"),
            Some(&Json::str("Usage: opentide info"))
        );
        assert_eq!(help.get("failure"), Some(&Json::Null));
        let refused = usage(&words("tui"), "opentide tui cannot run under serve").document();
        assert_eq!(
            refused.get("failure").and_then(|f| f.get("code")),
            Some(&Json::str("usage_error"))
        );
        let silent = document(&words("info"), "  \n", 1).document();
        assert_eq!(
            silent.get("message"),
            Some(&Json::str("The command printed no document"))
        );
    }

    #[test]
    fn stderr_is_split_into_events_and_lines() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let into = Arc::clone(&seen);
        let sink: EventSink = Arc::new(move |event| {
            into.lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(event);
        });
        forward_stderr(
            b"{\"event\":\"progress\",\"done\":1}\n12:00 debug: x\n{\"not\":\"an event\"}\n",
            &sink,
        );
        assert_eq!(
            *seen.lock().unwrap_or_else(PoisonError::into_inner),
            vec!["{\"event\":\"progress\",\"done\":1}".to_owned()]
        );
    }
}
