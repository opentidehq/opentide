//! `cargo xtask mcp`'s command line and `replay` end to end, against a
//! stand-in server: a shell script in the place of the package's
//! interpreter, which answers every request with the package's directory
//! (Unix only). The real server's replay is CI's `Golden compare` job.
#![cfg(unix)]
#![expect(
    clippy::unwrap_used,
    reason = "an integration test file: its helpers sit outside #[test]"
)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use serde_json::json;
use xtask::mcp::{Exchange, Launch, Recording, run};

/// A stand-in interpreter in `dir`: `-c` prints the package directory,
/// `-m opentide ... mcp start` answers each request on stdout, after
/// `prelude` (shell, run before the first line is read), and runs `coda`
/// once stdin closes.
fn stand_in(dir: &Path, name: &str, prelude: &str, coda: &str) -> PathBuf {
    let package = dir.join("package");
    std::fs::create_dir_all(&package).unwrap();
    let script = format!(
        r#"#!/bin/sh
if [ "$1" = "-c" ]; then
    printf '%s\n' '{package}'
    exit 0
fi
{prelude}
while IFS= read -r line; do
    id=$(printf '%s\n' "$line" | sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p')
    if [ -n "$id" ]; then
        printf '{{"jsonrpc":"2.0","id":%s,"result":{{"data":"{package}/data"}}}}\n' "$id"
    fi
done
{coda}
"#,
        package = package.display()
    );
    let path = dir.join(name);
    std::fs::write(&path, script).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    path
}

/// A recording on `fixture`: `initialize`, a notification and `ping`, each
/// request answered with `data` (the notification with nothing).
fn recording(dir: &Path, name: &str, launch: Launch, data: &str) -> PathBuf {
    let request = |id: u64, method: &str| json!({"jsonrpc": "2.0", "id": id, "method": method});
    let answer = |id: u64| Some(json!({"jsonrpc": "2.0", "id": id, "result": {"data": data}}));
    let recording = Recording {
        session: name.to_owned(),
        fixture: "agent-plugin".to_owned(),
        launch,
        exchanges: vec![
            Exchange {
                step: "initialize".to_owned(),
                request: request(0, "initialize"),
                response: answer(0),
            },
            Exchange {
                step: "initialized".to_owned(),
                request: json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
                response: None,
            },
            Exchange {
                step: "ping".to_owned(),
                request: request(1, "ping"),
                response: answer(1),
            },
        ],
    };
    let path = dir.join(format!("{name}.jsonl"));
    std::fs::write(&path, recording.to_jsonl()).unwrap();
    path
}

fn args(python: &Path, rest: &[&Path]) -> Vec<String> {
    ["replay", "--engine", "rust", "--show-approved", "--python"]
        .iter()
        .map(|arg| (*arg).to_owned())
        .chain(std::iter::once(python.display().to_string()))
        .chain(rest.iter().map(|path| path.display().to_string()))
        .collect()
}

#[test]
fn every_answer_equal_to_the_recording_passes_whatever_the_launch() {
    let dir = tempfile::tempdir().unwrap();
    let python = stand_in(dir.path(), "python", "", "");
    let files = [
        recording(dir.path(), "a", Launch::Workspace, "<PACKAGE>/data"),
        recording(dir.path(), "b", Launch::RepoOption, "<PACKAGE>/data"),
        recording(dir.path(), "c", Launch::PluginRoot, "<PACKAGE>/data"),
    ];
    let files: Vec<&Path> = files.iter().map(PathBuf::as_path).collect();
    assert_eq!(run(&args(&python, &files)).unwrap(), 0);
}

#[test]
fn a_different_answer_fails_the_replay() {
    let dir = tempfile::tempdir().unwrap();
    let python = stand_in(dir.path(), "python", "", "");
    let file = recording(dir.path(), "a", Launch::Workspace, "<PACKAGE>/other");
    // `--gate`: the difference fails whether or not the repository is
    // report-only (tests/golden/REPORT_ONLY, the catch-up train).
    let mut gated = args(&python, &[&file]);
    gated.insert(1, "--gate".to_owned());
    assert_eq!(run(&gated).unwrap(), 1);
}

#[test]
fn a_report_only_repository_reports_a_difference_and_passes() {
    let dir = tempfile::tempdir().unwrap();
    let python = stand_in(dir.path(), "python", "", "");
    let file = recording(dir.path(), "a", Launch::Workspace, "<PACKAGE>/other");
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf();
    let expected = u8::from(!xtask::golden::report_only::enabled(&repo));
    assert_eq!(run(&args(&python, &[&file])).unwrap(), expected);
}

#[test]
fn a_server_that_writes_anything_but_json_rpc_or_fails_cannot_be_replayed() {
    let dir = tempfile::tempdir().unwrap();
    let file = recording(dir.path(), "a", Launch::Workspace, "<PACKAGE>/data");
    let error = |python: &Path| format!("{:#}", run(&args(python, &[&file])).unwrap_err());

    let noisy = stand_in(dir.path(), "noisy", "echo hello", "");
    assert!(
        error(&noisy).contains("stdout holds a line that is not JSON-RPC: hello"),
        "{}",
        error(&noisy)
    );
    let other = stand_in(dir.path(), "other", r#"echo '{"id":0}'"#, "");
    assert!(
        error(&other).contains("not JSON-RPC 2.0"),
        "{}",
        error(&other)
    );
    let late = stand_in(dir.path(), "late", "", "echo late");
    assert!(
        error(&late).contains("not JSON-RPC: late"),
        "{}",
        error(&late)
    );
    let failing = stand_in(dir.path(), "failing", "", "echo broken >&2; exit 3");
    let message = error(&failing);
    assert!(
        message.contains("the server exited with exit status: 3"),
        "{message}"
    );
    let silent = stand_in(dir.path(), "silent", "exec 1>&-; cat >/dev/null", "");
    assert!(
        error(&silent).contains("the server closed stdout"),
        "{}",
        error(&silent)
    );
}

#[test]
fn a_recording_must_name_a_fixture_of_the_sessions() {
    let dir = tempfile::tempdir().unwrap();
    let python = stand_in(dir.path(), "python", "", "");
    let file = recording(dir.path(), "a", Launch::Workspace, "x");
    let text = std::fs::read_to_string(&file)
        .unwrap()
        .replace("agent-plugin", "nowhere");
    std::fs::write(&file, text).unwrap();
    let error = format!("{:#}", run(&args(&python, &[&file])).unwrap_err());
    assert!(
        error.ends_with("no fixture `nowhere` in sessions.toml"),
        "{error}"
    );
    let missing = dir.path().join("missing.jsonl");
    let error = format!("{:#}", run(&args(&python, &[&missing])).unwrap_err());
    assert!(error.starts_with("read "), "{error}");
}

#[test]
fn the_command_line_replays_against_rust_and_records_from_a_release() {
    let strings = |args: &[&str]| -> Vec<String> { args.iter().map(|a| (*a).to_owned()).collect() };
    let error = |args: &[&str]| format!("{:#}", run(&strings(args)).unwrap_err());
    assert_eq!(run(&[]).unwrap(), 2);
    assert_eq!(run(&strings(&["help"])).unwrap(), 0);
    assert_eq!(run(&strings(&["replay", "--help"])).unwrap(), 0);
    assert!(error(&["play"]).starts_with("unknown command `play`"));
    assert!(error(&["replay", "--fast"]).starts_with("unknown option --fast"));
    assert!(error(&["replay", "--engine"]).starts_with("--engine NAME"));
    assert!(error(&["replay", "a.jsonl"]).starts_with("replay needs --engine rust"));
    assert!(
        error(&["replay", "--engine", "python", "a.jsonl"])
            .starts_with("--engine python: the Rust server is opentide's only one")
    );
    assert!(error(&["replay", "--engine", "rust"]).starts_with("replay needs recordings"));
    assert!(error(&["record"]).starts_with("record needs --python PATH"));
    // A session that does not exist records nothing.
    let dir = tempfile::tempdir().unwrap();
    let python = stand_in(dir.path(), "python", "", "");
    let python = python.display().to_string();
    assert_eq!(
        error(&["record", "--python", &python, "--only", "nope"]),
        "no session `nope`"
    );
}

#[test]
fn the_package_directory_is_what_the_interpreter_finds() {
    let dir = tempfile::tempdir().unwrap();
    let python = stand_in(dir.path(), "python", "", "");
    assert_eq!(
        xtask::mcp::package_dir(&python).unwrap(),
        dir.path().join("package")
    );
    let missing = dir.path().join("no-python");
    assert!(xtask::mcp::package_dir(&missing).is_err());
    let elsewhere = dir.path().join("elsewhere");
    std::fs::write(&elsewhere, "#!/bin/sh\necho /no/such/dir\n").unwrap();
    std::fs::set_permissions(&elsewhere, std::fs::Permissions::from_mode(0o755)).unwrap();
    let message = format!("{:#}", xtask::mcp::package_dir(&elsewhere).unwrap_err());
    assert!(message.contains("is not a directory"), "{message}");
    let failing = dir.path().join("failing");
    std::fs::write(&failing, "#!/bin/sh\nexit 1\n").unwrap();
    std::fs::set_permissions(&failing, std::fs::Permissions::from_mode(0o755)).unwrap();
    let message = format!("{:#}", xtask::mcp::package_dir(&failing).unwrap_err());
    assert!(
        message.contains("could not find the opentide package"),
        "{message}"
    );
}
