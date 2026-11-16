//! The setup wizards (UC-3.6c, #951) at a pseudo-terminal: the `opentide`
//! binary started on a pty (ConPTY on Windows) through portable-pty, its
//! questions answered with the keys a person presses, and the files it
//! writes and the way it ends checked.

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "a test: a session that does not go as scripted is a failure"
)]

use std::io::{Read as _, Write};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use portable_pty::{Child, CommandBuilder, MasterPty, PtySize, native_pty_system};

const ENTER: &str = "\r";
const SPACE: &str = " ";
const DOWN: &str = "\u{1b}[B";
const CTRL_C: &str = "\u{3}";

/// How long a question may take to appear.
const TIMEOUT: Duration = Duration::from_secs(60);

/// A run on a pseudo-terminal: what it printed so far, read on a thread of
/// its own, and the keys typed into it.
struct Session {
    child: Box<dyn Child + Send + Sync>,
    writer: Arc<Mutex<Box<dyn Write + Send>>>,
    printed: Arc<Mutex<Vec<u8>>>,
    /// The reader saw the end of the output.
    ended: Arc<AtomicBool>,
    /// How much of `printed` an expectation has consumed.
    seen: usize,
    /// The pseudo-terminal, closed once the run has exited: a pseudo
    /// console on Windows ends its output only then.
    master: Option<Box<dyn MasterPty + Send>>,
}

/// `opentide <args>` in `cwd` on a pseudo-terminal, in `human` mode
/// whatever agent or CI the test runs under.
fn spawn(cwd: &Path, args: &[&str]) -> Session {
    spawn_with(cwd, args, &[])
}

/// [`spawn`], with the variables `env` set: the network the run reaches.
fn spawn_with(cwd: &Path, args: &[&str], env: &[(String, String)]) -> Session {
    let pair = native_pty_system()
        .openpty(PtySize {
            rows: 40,
            cols: 100,
            pixel_width: 0,
            pixel_height: 0,
        })
        .expect("open a pseudo-terminal");
    let mut command = CommandBuilder::new(env!("CARGO_BIN_EXE_opentide-cli"));
    command.args(args);
    command.cwd(cwd);
    command.env("OPENTIDE_OUTPUT", "human");
    command.env("TERM", "xterm");
    command.env("GIT_CEILING_DIRECTORIES", cwd);
    for name in [
        "OPENTIDE_REPO_ROOT",
        "OPENTIDE_TIDE_WORKSPACE",
        "NO_PROXY",
        "no_proxy",
    ] {
        command.env_remove(name);
    }
    // No run reaches a real host: a refused proxy unless `env` names one.
    for (name, value) in offline().iter().chain(env) {
        command.env(name, value);
    }
    let child = pair
        .slave
        .spawn_command(command)
        .expect("spawn opentide on a pseudo-terminal");
    drop(pair.slave);
    let mut reader = pair.master.try_clone_reader().unwrap();
    let writer = Arc::new(Mutex::new(pair.master.take_writer().unwrap()));
    let printed = Arc::new(Mutex::new(Vec::new()));
    let ended = Arc::new(AtomicBool::new(false));
    let (sink, answers, end) = (
        Arc::clone(&printed),
        Arc::clone(&writer),
        Arc::clone(&ended),
    );
    std::thread::spawn(move || {
        let mut chunk = [0_u8; 4096];
        while let Ok(read) = reader.read(&mut chunk) {
            if read == 0 {
                break;
            }
            let bytes = &chunk[..read];
            // A pseudo console asks where the cursor is before it draws:
            // answer as a terminal would.
            if bytes.windows(4).any(|window| window == b"\x1b[6n") {
                let mut writer = answers.lock().unwrap();
                let _ = writer.write_all(b"\x1b[1;1R");
                let _ = writer.flush();
            }
            sink.lock().unwrap().extend_from_slice(bytes);
        }
        end.store(true, Ordering::SeqCst);
    });
    Session {
        child,
        writer,
        printed,
        ended,
        seen: 0,
        master: Some(pair.master),
    }
}

impl Drop for Session {
    /// A failed expectation panics with the run still going: it must not
    /// outlive the test.
    fn drop(&mut self) {
        let _ = self.child.kill();
        // Reaped, not left a zombie until the test binary exits.
        let _ = self.child.wait();
    }
}

impl Session {
    /// Waits until the run prints `text` after what was last expected;
    /// everything it printed up to there.
    fn expect(&mut self, text: &str) -> String {
        let started = Instant::now();
        loop {
            {
                let printed = self.printed.lock().unwrap();
                let shown = String::from_utf8_lossy(&printed[self.seen..]).into_owned();
                if let Some(at) = shown.find(text) {
                    let upto = shown[..at + text.len()].len();
                    self.seen += upto;
                    return String::from_utf8_lossy(&printed[..self.seen]).into_owned();
                }
                assert!(
                    started.elapsed() < TIMEOUT,
                    "waiting for {text:?}; printed:\n{}",
                    String::from_utf8_lossy(&printed)
                );
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// The exit code, once the run has exited; killed, and a failure, past
    /// [`TIMEOUT`].
    fn wait(&mut self) -> i64 {
        let started = Instant::now();
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return i64::from(status.exit_code());
            }
            if started.elapsed() > TIMEOUT {
                let _ = self.child.kill();
                let _ = self.child.wait();
                panic!(
                    "the run did not exit in {TIMEOUT:?}; printed:\n{}",
                    String::from_utf8_lossy(&self.printed.lock().unwrap())
                );
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Types `keys`.
    fn send(&self, keys: &str) {
        let mut writer = self.writer.lock().unwrap();
        writer.write_all(keys.as_bytes()).unwrap();
        writer.flush().unwrap();
    }
}

/// The proxy variables of a network that refuses every connection.
fn offline() -> Vec<(String, String)> {
    [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ]
    .iter()
    .map(|name| ((*name).to_owned(), "http://127.0.0.1:9".to_owned()))
    .collect()
}

/// A proxy replaying `tests/cassettes/<name>.json`, and the variables that
/// send a run through it (its CA written to `ca`).
fn cassette(name: &str, ca: &Path) -> (opentide_cassette::Proxy, Vec<(String, String)>) {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/cassettes")
        .join(format!("{name}.json"));
    let text = std::fs::read_to_string(path).unwrap();
    let proxy = opentide_cassette::Proxy::start(
        opentide_cassette::Mode::Replay {
            cassette: opentide_cassette::Cassette::parse(&text).unwrap(),
        },
        opentide_cassette::Redaction::default(),
    )
    .unwrap();
    std::fs::write(ca, proxy.ca_pem()).unwrap();
    let env = proxy.client_env(&ca.to_string_lossy());
    (proxy, env)
}

/// Waits for `text`, then types `keys`.
fn answer(session: &mut Session, text: &str, keys: &[&str]) {
    session.expect(text);
    for key in keys {
        session.send(key);
    }
}

/// What the session prints up to `last`, the end of its output, and its
/// exit code. The run is awaited, not the end of its output, which a
/// pseudo console on Windows does not signal while it is open.
fn finish(mut session: Session, last: &str) -> (String, i64) {
    let printed = session.expect(last);
    (printed, session.wait())
}

/// Everything the session printed, its escapes removed and its lines ending
/// `\n`, and its exit code, once it has exited and its output has ended: the
/// pseudo-terminal is closed first, which ends a Windows pseudo console's
/// output. Output that has not ended by [`TIMEOUT`] is a failure, not a
/// partial result.
fn everything(mut session: Session) -> (String, i64) {
    let code = session.wait();
    drop(session.master.take());
    let started = Instant::now();
    while !session.ended.load(Ordering::SeqCst) {
        assert!(
            started.elapsed() < TIMEOUT,
            "the output did not end in {TIMEOUT:?}; printed:\n{}",
            String::from_utf8_lossy(&session.printed.lock().unwrap())
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    let printed = String::from_utf8_lossy(&session.printed.lock().unwrap()).into_owned();
    (plain(&printed), code)
}

/// `text` without its terminal escapes (CSI and OSC), lines ending `\n`.
fn plain(text: &str) -> String {
    let mut out = String::new();
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match (c, chars.peek()) {
            ('\u{1b}', Some('[')) => {
                chars.next();
                // Parameters and intermediates, then one final byte.
                while chars.next_if(|c| !('@'..='~').contains(c)).is_some() {}
                chars.next();
            }
            ('\u{1b}', Some(']')) => {
                // To BEL or ST (ESC \).
                while let Some(c) = chars.next() {
                    if c == '\u{7}' || (c == '\u{1b}' && chars.next_if_eq(&'\\').is_some()) {
                        break;
                    }
                }
            }
            ('\u{1b}', Some(_)) => {
                chars.next();
            }
            ('\r', Some('\n')) => {}
            _ => out.push(c),
        }
    }
    out
}

/// The one JSON document a `--json` run printed, and its exit code.
fn document(session: Session) -> (serde_json::Value, i64) {
    let (printed, code) = everything(session);
    let document = serde_json::from_str(printed.trim())
        .unwrap_or_else(|error| panic!("not one JSON document ({error}): {printed}"));
    (document, code)
}

/// The `setup` wizard: each question answered as a person would, then the
/// repository it scaffolds, the platform it enables and the MCP
/// configuration it writes.
#[test]
fn the_setup_wizard_scaffolds_what_was_answered() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("detections");
    std::fs::create_dir(&repo).unwrap();
    let mut session = spawn(&repo, &["setup"]);
    answer(&mut session, "Repository name", &[ENTER]);
    answer(&mut session, "Organisation / team", &["SOC team", ENTER]);
    answer(&mut session, "Description (optional)", &[ENTER]);
    // Splunk: the third platform.
    answer(
        &mut session,
        "Detection platforms",
        &[DOWN, DOWN, SPACE, ENTER],
    );
    answer(&mut session, "CI/CD platform", &[ENTER]);
    answer(&mut session, "Configure opentide MCP?", &["y", ENTER]);
    answer(&mut session, "MCP hosts", &[SPACE, ENTER]);
    answer(&mut session, "Install agent skills?", &[ENTER]);
    answer(&mut session, "Setup plan", &[]);
    answer(&mut session, "Apply this setup plan?", &[ENTER]);
    let (printed, code) = finish(session, "check every object before you commit");
    assert_eq!(code, 0, "{printed}");
    assert!(printed.contains("Created detections here"), "{printed}");
    assert!(printed.contains("opentide generate"), "{printed}");
    assert!(repo.join("objects/rules").is_dir());
    let readme = std::fs::read_to_string(repo.join("README.md")).unwrap();
    assert!(readme.contains("SOC team"), "{readme}");
    let splunk =
        std::fs::read_to_string(repo.join(".opentide/configurations/platforms/splunk.toml"))
            .unwrap();
    assert!(splunk.contains("enabled = true"), "{splunk}");
    assert!(repo.join(".vscode/mcp.json").is_file());
    assert!(!repo.join(".github").exists(), "CI was left for later");
}

/// Declining the plan writes nothing.
#[test]
fn a_declined_plan_writes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let mut session = spawn(dir.path(), &["setup"]);
    answer(&mut session, "Repository name", &[ENTER]);
    answer(&mut session, "Organisation / team", &[ENTER]);
    answer(&mut session, "Description (optional)", &[ENTER]);
    answer(&mut session, "Detection platforms", &[SPACE, ENTER]);
    answer(&mut session, "CI/CD platform", &[DOWN, ENTER]);
    answer(&mut session, "CI workflow features", &[ENTER]);
    answer(&mut session, "Configure opentide MCP?", &[ENTER]);
    answer(&mut session, "Install agent skills?", &[ENTER]);
    answer(&mut session, "Apply this setup plan?", &["n", ENTER]);
    let (printed, code) = finish(session, "no files were written");
    assert_eq!(code, 0, "{printed}");
    assert!(
        printed.contains("Setup cancelled; no files were written"),
        "{printed}"
    );
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
}

/// Ctrl-C at a question stops the run as Ctrl-C does elsewhere.
#[test]
fn ctrl_c_at_a_question_is_an_interruption() {
    let dir = tempfile::tempdir().unwrap();
    let mut session = spawn(dir.path(), &["setup"]);
    answer(&mut session, "Repository name", &[CTRL_C]);
    let (printed, code) = everything(session);
    assert_eq!(code, 130, "{printed}");
    // One line says so, and nothing follows it: no outcome, no next steps
    // (D25; questionary's `Cancelled by user` once came first).
    assert_eq!(
        printed.matches("error: interrupted").count(),
        1,
        "{printed}"
    );
    assert!(!printed.contains("Cancelled by user"), "{printed}");
    assert!(!printed.contains("panicked"), "{printed}");
    assert!(
        printed.trim_end().ends_with("error: interrupted"),
        "{printed}"
    );
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
}

/// The `setup mcp` wizard: the hosts, the target, the confirmation.
#[test]
fn the_mcp_wizard_writes_the_hosts_chosen() {
    let dir = tempfile::tempdir().unwrap();
    let mut session = spawn(dir.path(), &["setup", "mcp"]);
    // Cursor: the second host. An empty selection is refused first.
    answer(&mut session, "MCP hosts", &[ENTER]);
    answer(
        &mut session,
        "Select at least one option",
        &[DOWN, SPACE, ENTER],
    );
    // `Hosts:` is bold, the host after it.
    answer(&mut session, "Hosts:", &[]);
    answer(&mut session, "cursor", &[]);
    answer(&mut session, "Write these MCP configurations?", &[ENTER]);
    let (printed, code) = finish(session, "Wrote .cursor/mcp.json");
    assert_eq!(code, 0, "{printed}");
    assert!(printed.contains("Wrote .cursor/mcp.json"), "{printed}");
    assert!(dir.path().join(".cursor/mcp.json").is_file());
    assert!(!dir.path().join(".vscode").exists());
}

/// The `setup skills` wizard (UC-4.4d, #834): the agent environments, the
/// target, the confirmation, then the starter skills and `AGENTS.md`, the
/// catalogue read from its cassette. The catalogue lists
/// `detection-engineering`, so its copy is downloaded (opentide 0.28.1).
#[test]
fn the_skills_wizard_installs_for_the_environments_chosen() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    std::fs::create_dir(&repo).unwrap();
    let (proxy, env) = cassette("skills/catalogue-first", &dir.path().join("ca.pem"));
    let mut session = spawn_with(&repo, &["setup", "skills"], &env);
    // Generic: the third environment.
    answer(
        &mut session,
        "Agent environments",
        &[DOWN, DOWN, SPACE, ENTER],
    );
    answer(&mut session, "Agent environments:", &[]);
    answer(&mut session, "generic", &[]);
    answer(&mut session, "Install these agent skills?", &[ENTER]);
    let (printed, code) = finish(session, "Wrote 4 files");
    assert_eq!(code, 0, "{printed}");
    assert!(repo.join("AGENTS.md").is_file());
    assert!(
        repo.join(".agents/skills/opentide-detection-rule/SKILL.md")
            .is_file()
    );
    assert!(
        repo.join(".agents/skills/detection-engineering/references/kql.md")
            .is_file()
    );
    assert!(!repo.join("CLAUDE.md").exists());
    assert!(proxy.verify().is_empty(), "{:?}", proxy.verify());
}

/// The `setup` wizard's skills question, offline: the skills are skipped
/// with the catalogue's error as a warning, and the rest is set up.
#[test]
fn the_setup_wizard_skips_skills_it_cannot_fetch() {
    let dir = tempfile::tempdir().unwrap();
    let mut session = spawn(dir.path(), &["setup"]);
    answer(&mut session, "Repository name", &[ENTER]);
    answer(&mut session, "Organisation / team", &[ENTER]);
    answer(&mut session, "Description (optional)", &[ENTER]);
    answer(&mut session, "Detection platforms", &[SPACE, ENTER]);
    answer(&mut session, "CI/CD platform", &[ENTER]);
    answer(&mut session, "Configure opentide MCP?", &[ENTER]);
    answer(&mut session, "Install agent skills?", &["y", ENTER]);
    answer(&mut session, "Agent environments", &[SPACE, ENTER]);
    answer(
        &mut session,
        "Agent skills skipped: Could not fetch skills catalogue",
        &[],
    );
    answer(&mut session, "Apply this setup plan?", &[ENTER]);
    let (printed, code) = finish(session, "check every object before you commit");
    assert_eq!(code, 0, "{printed}");
    assert!(dir.path().join("README.md").is_file());
    assert!(!dir.path().join(".agents").exists());
    assert!(!dir.path().join(".cursor").exists());
}

/// The `setup skills` wizard, offline: the catalogue's error, nothing written.
#[test]
fn the_skills_wizard_fails_without_the_catalogue() {
    let dir = tempfile::tempdir().unwrap();
    let mut session = spawn(dir.path(), &["setup", "skills"]);
    answer(&mut session, "Agent environments", &[SPACE, ENTER]);
    let (printed, code) = finish(session, "publicly reachable");
    assert_eq!(code, 1, "{printed}");
    assert!(
        printed.contains("Could not fetch skills catalogue from opentidehq/skills@main"),
        "{printed}"
    );
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
}

/// A workspace that enables Sentinel and Splunk.
fn enabled_workspace(dir: &Path) {
    let platforms = dir.join(".opentide/configurations/platforms");
    std::fs::create_dir_all(&platforms).unwrap();
    for platform in ["sentinel", "splunk"] {
        std::fs::write(
            platforms.join(format!("{platform}.toml")),
            "[platform]\nenabled = true\n",
        )
        .unwrap();
    }
    std::fs::create_dir_all(dir.join("objects")).unwrap();
}

/// `new rule` at a terminal (UC-6.0d): the name and the platform blocks
/// are asked for, as `_ask_name` and `_ask_platforms` ask, and the rule has
/// the blocks picked.
#[test]
fn new_asks_for_the_name_and_the_platform_blocks() {
    let dir = tempfile::tempdir().unwrap();
    enabled_workspace(dir.path());
    let mut session = spawn(dir.path(), &["new", "rule"]);
    answer(&mut session, "Rule name", &["Served Rule", ENTER]);
    session.expect("Platform blocks");
    session.expect("Splunk Enterprise Security");
    session.expect("(space selects, enter for none, arrows move)");
    for key in [DOWN, SPACE, ENTER] {
        session.send(key);
    }
    let (printed, code) = finish(session, "opentide validate --file");
    assert_eq!(code, 0, "{printed}");
    let rules = dir.path().join("objects/rules");
    let written: Vec<_> = std::fs::read_dir(&rules).unwrap().collect();
    assert_eq!(written.len(), 1, "{printed}");
    let text = std::fs::read_to_string(written[0].as_ref().unwrap().path()).unwrap();
    assert!(text.contains("name: Served Rule"), "{text}");
    assert!(text.contains("  splunk:"), "{text}");
    assert!(!text.contains("  sentinel:"), "{text}");
}

/// Ctrl-C at `new`'s question is an interruption: exit 130, nothing written.
#[test]
fn ctrl_c_at_news_question_is_an_interruption() {
    let dir = tempfile::tempdir().unwrap();
    enabled_workspace(dir.path());
    let mut session = spawn(dir.path(), &["new", "threat"]);
    answer(&mut session, "Threat name", &[CTRL_C]);
    let (printed, code) = finish(session, "interrupted");
    assert_eq!(code, 130, "{printed}");
    assert!(!dir.path().join("objects/threats").exists(), "{printed}");
}

/// #255: `--json setup` at a terminal never asks a question and then prints
/// JSON: it refuses at once, its one document saying how to script it.
#[test]
fn json_setup_at_a_terminal_refuses_in_one_document() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("json-detections");
    std::fs::create_dir(&repo).unwrap();
    let path = repo.to_str().unwrap();
    let session = spawn(
        dir.path(),
        &["--json", "--no-color", "setup", "--path", path],
    );
    let (document, code) = document(session);
    assert_ne!(code, 0, "{document}");
    assert_eq!(document["ok"], false, "{document}");
    let message = document["message"].as_str().unwrap();
    assert!(
        message.contains("--json") && message.contains("--yes"),
        "{message}"
    );
    assert!(!repo.join("objects").exists());
}

/// `--json setup` without `--yes` does not ask to confirm the write either.
#[test]
fn json_setup_at_a_terminal_does_not_ask_to_confirm() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("confirm-detections");
    let path = repo.to_str().unwrap();
    let args = [
        "--json",
        "--no-color",
        "setup",
        "--platform",
        "sentinel",
        "--path",
        path,
    ];
    let (document, code) = document(spawn(dir.path(), &args));
    assert_ne!(code, 0, "{document}");
    assert_eq!(document["ok"], false, "{document}");
    assert!(
        document["message"].as_str().unwrap().contains("--yes"),
        "{document}"
    );
    assert!(!repo.join("objects").exists());
}

/// The documented scripted run still works at a terminal.
#[test]
fn json_setup_at_a_terminal_works_when_scripted() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("scripted-detections");
    let path = repo.to_str().unwrap();
    let args = [
        "--json",
        "--no-color",
        "setup",
        "--yes",
        "--platform",
        "sentinel",
        "--path",
        path,
    ];
    let (document, code) = document(spawn(dir.path(), &args));
    assert_eq!(code, 0, "{document}");
    assert_eq!(document["ok"], true, "{document}");
    assert!(repo.join("objects").is_dir());
}

/// With no terminal on stdin the wizard refuses rather than waits, whatever
/// `OPENTIDE_*` the test runs under.
#[test]
fn setup_without_a_terminal_refuses() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("no-tty-detections");
    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_opentide-cli"));
    for (name, _) in std::env::vars_os() {
        if name.to_string_lossy().starts_with("OPENTIDE_") || name == "DEPLOYMENT_PLAN" {
            command.env_remove(name);
        }
    }
    let mut child = command
        .args([
            "--json",
            "--no-color",
            "setup",
            "--path",
            repo.to_str().unwrap(),
        ])
        .current_dir(dir.path())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let mut stderr = child.stderr.take().unwrap();
    let out = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = stdout.read_to_end(&mut bytes);
        bytes
    });
    let err = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = stderr.read_to_end(&mut bytes);
        bytes
    });
    // A run that waits for an answer is a failure, not a hung test.
    let started = Instant::now();
    let mut timed_out = false;
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if started.elapsed() > TIMEOUT {
            timed_out = true;
            let _ = child.kill();
            break child.wait().unwrap();
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let (stdout, stderr) = (out.join().unwrap(), err.join().unwrap());
    let (stdout, stderr) = (
        String::from_utf8_lossy(&stdout),
        String::from_utf8_lossy(&stderr),
    );
    assert!(
        !timed_out,
        "the run did not exit in {TIMEOUT:?}\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert_ne!(
        status.code(),
        Some(0),
        "exit {status}\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let document: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|error| panic!("{error}\nstdout:\n{stdout}\nstderr:\n{stderr}"));
    assert_eq!(document["ok"], false, "{document}\nstderr:\n{stderr}");
    assert!(!repo.join("objects").exists());
}

/// The branded wizard: the logo and tagline, an emptied name refused on
/// screen, and the end: what it wrote, the outcome and the next steps.
#[test]
fn the_branded_wizard_refuses_an_empty_name_and_ends_with_next_steps() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("branded-detections");
    std::fs::create_dir(&repo).unwrap();
    let mut session = spawn(dir.path(), &["setup", "--path", repo.to_str().unwrap()]);
    session.expect("Spec-driven development for agentic detection engineering");
    // The suggested name (the folder's) erased with Backspace.
    let erase = "\u{7f}".repeat("branded-detections".len());
    answer(&mut session, "Repository name", &[&erase, ENTER]);
    answer(
        &mut session,
        "cannot be empty",
        &["Branded Detections", ENTER],
    );
    answer(&mut session, "Organisation / team", &[ENTER]);
    answer(&mut session, "Description (optional)", &[ENTER]);
    answer(&mut session, "Detection platforms", &[SPACE, ENTER]);
    answer(&mut session, "CI/CD platform", &[ENTER]);
    answer(&mut session, "Configure opentide MCP?", &[ENTER]);
    answer(&mut session, "Install agent skills?", &[ENTER]);
    answer(&mut session, "Apply this setup plan?", &[ENTER]);
    session.expect("Created Branded Detections in");
    session.expect("Next steps");
    let (printed, code) = everything(session);
    assert_eq!(code, 0, "{printed}");
    assert!(printed.contains("▄▄████"), "the logo: {printed}");
    assert!(
        printed.contains("objects/{threats,objectives,rules}/"),
        "{printed}"
    );
    assert!(printed.contains("opentide generate"), "{printed}");
    let readme = std::fs::read_to_string(repo.join("README.md")).unwrap();
    assert!(readme.starts_with("# Branded Detections"), "{readme}");
}

/// A bare `opentide` at a terminal shows the home screen, not the usage.
#[test]
fn bare_opentide_at_a_terminal_shows_the_home_screen() {
    let dir = tempfile::tempdir().unwrap();
    let (printed, code) = everything(spawn(dir.path(), &[]));
    assert_eq!(code, 0, "{printed}");
    assert!(
        printed.contains("Spec-driven development for agentic detection engineering"),
        "{printed}"
    );
    assert!(printed.contains("Suggested next"), "{printed}");
    assert!(printed.contains("opentide setup"), "{printed}");
    assert!(!printed.contains("Usage:"), "{printed}");
}
