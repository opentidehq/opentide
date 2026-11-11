//! The setup wizards (UC-3.6c, #951) at a pseudo-terminal: the `opentide`
//! binary started on a pty (ConPTY on Windows) through expectrl, its
//! questions answered with the keys a person presses, and the files it
//! writes and the way it ends checked.

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "a test: a session that does not go as scripted is a failure"
)]

use std::path::Path;
use std::process::Command;
use std::time::Duration;

use expectrl::{Expect, Session};

const ENTER: &str = "\r";
const SPACE: &str = " ";
const DOWN: &str = "\u{1b}[B";
const CTRL_C: &str = "\u{3}";

/// `opentide <args>` in `cwd` on a pseudo-terminal, in `human` mode
/// whatever agent or CI the test runs under.
fn spawn(cwd: &Path, args: &[&str]) -> expectrl::session::OsSession {
    let mut command = Command::new(env!("CARGO_BIN_EXE_opentide"));
    command.args(args).current_dir(cwd);
    command
        .env("OPENTIDE_OUTPUT", "human")
        .env("TERM", "xterm")
        .env("GIT_CEILING_DIRECTORIES", cwd)
        .env_remove("OPENTIDE_REPO_ROOT")
        .env_remove("OPENTIDE_TIDE_WORKSPACE")
        .env_remove("OPENTIDE_MCP_SERVER");
    let mut session = Session::spawn(command).expect("spawn opentide on a pseudo-terminal");
    session.set_expect_timeout(Some(Duration::from_secs(60)));
    session
}

/// Waits for `text`, then types `keys`.
fn answer(session: &mut expectrl::session::OsSession, text: &str, keys: &[&str]) {
    session
        .expect(text)
        .unwrap_or_else(|error| panic!("waiting for {text:?}: {error}"));
    for key in keys {
        session.send(key).unwrap();
    }
}

/// What the session prints up to `last`, the end of its output, and its
/// exit code. The run is awaited, not the end of its output, which a
/// pseudo console on Windows does not signal while it is open.
fn finish(mut session: expectrl::session::OsSession, last: &str) -> (String, i64) {
    let found = session
        .expect(last)
        .unwrap_or_else(|error| panic!("waiting for {last:?}: {error}"));
    let mut printed = String::from_utf8_lossy(found.before()).into_owned();
    printed.push_str(last);
    (printed, exit_code(&session))
}

#[cfg(unix)]
fn exit_code(session: &expectrl::session::OsSession) -> i64 {
    match session.get_process().wait().unwrap() {
        expectrl::process::unix::WaitStatus::Exited(_, code) => i64::from(code),
        other => panic!("{other:?}"),
    }
}

#[cfg(windows)]
fn exit_code(session: &expectrl::session::OsSession) -> i64 {
    i64::from(session.get_process().wait(None).unwrap())
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
    // `Target:` and `Hosts:` are bold.
    session
        .expect(expectrl::Regex("Hosts:[^\n]* cursor"))
        .expect("the hosts chosen");
    answer(&mut session, "Write these MCP configurations?", &[ENTER]);
    let (printed, code) = finish(session, "Wrote .cursor/mcp.json");
    assert_eq!(code, 0, "{printed}");
    assert!(printed.contains("Wrote .cursor/mcp.json"), "{printed}");
    assert!(dir.path().join(".cursor/mcp.json").is_file());
    assert!(!dir.path().join(".vscode").exists());
}
