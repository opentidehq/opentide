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
    /// How much of `printed` an expectation has consumed.
    seen: usize,
    _master: Box<dyn MasterPty + Send>,
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
        "OPENTIDE_MCP_SERVER",
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
    let (sink, answers) = (Arc::clone(&printed), Arc::clone(&writer));
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
    });
    Session {
        child,
        writer,
        printed,
        seen: 0,
        _master: pair.master,
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
    let status = session.child.wait().unwrap();
    (printed, i64::from(status.exit_code()))
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
    // Splunk: the second platform.
    answer(&mut session, "Detection platforms", &[DOWN, SPACE, ENTER]);
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
    let (printed, code) = finish(session, "error: interrupted");
    assert_eq!(code, 130, "{printed}");
    assert!(printed.contains("error: interrupted"), "{printed}");
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
/// catalogue read from its cassette.
#[test]
fn the_skills_wizard_installs_for_the_environments_chosen() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    std::fs::create_dir(&repo).unwrap();
    let (proxy, env) = cassette("skills/manifest", &dir.path().join("ca.pem"));
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
    let (printed, code) = finish(session, "Wrote 3 files");
    assert_eq!(code, 0, "{printed}");
    assert!(repo.join("AGENTS.md").is_file());
    assert!(
        repo.join(".agents/skills/opentide-detection-rule/SKILL.md")
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
