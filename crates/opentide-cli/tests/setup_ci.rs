//! `opentide setup ci` with a provider it does not know (0.24.1, #882): the
//! value and the three providers are named, the closest one is suggested,
//! the run exits 2 and writes nothing. `none` is the wizard's choice
//! (`setup --ci none`), not a provider of this argument (0.28.0's
//! `test_setup_ci_none_is_rejected`).

#![cfg(unix)]
#![expect(
    clippy::unwrap_used,
    reason = "a test helper: a broken fixture is a failure"
)]

#[path = "common/replay.rs"]
mod replay;

use std::path::Path;
use std::sync::{Arc, Mutex};

use opentide_cli::env::Env;
use opentide_cli::logging::Sink;
use opentide_cli::{Host, run};

/// `opentide <words>` in plain mode from `cwd`: the exit code, stdout and
/// stderr.
fn opentide(cwd: &Path, words: &[&str]) -> (i32, String, String) {
    let host = Host {
        version: "0.28.1".into(),
        stdout_tty: false,
        stderr_tty: false,
        log_sink: Arc::new(Mutex::new(replay::Buffer::default())) as Sink,
        cwd: Some(cwd.to_path_buf()),
        width: None,
        interrupt: opentide_cli::app::Interrupt::default(),
    };
    let argv: Vec<String> = words.iter().map(|word| (*word).to_owned()).collect();
    let home = cwd.with_file_name("home");
    std::fs::create_dir_all(&home).unwrap();
    let env = Env::from_pairs([("HOME".to_owned(), home.display().to_string())]);
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code = run(&argv, &env, &host, &mut out, &mut err);
    (
        code,
        String::from_utf8(out).unwrap(),
        String::from_utf8(err).unwrap(),
    )
}

fn tide_corpus() -> (tempfile::TempDir, std::path::PathBuf) {
    let scratch = tempfile::tempdir().unwrap();
    let ws = std::fs::canonicalize(scratch.path()).unwrap().join("ws");
    replay::fixture("tide-corpus", &ws);
    (scratch, ws)
}

#[test]
fn none_is_not_a_provider() {
    let (_scratch, ws) = tide_corpus();
    let before = replay::files(&ws);
    let (code, stdout, stderr) = opentide(&ws, &["setup", "ci", "none", "--yes"]);
    assert_eq!(code, 2, "{stdout}{stderr}");
    assert!(
        stderr.contains(
            "error: Invalid value for 'ci_platform': 'none' is not one of 'github', 'gitlab', \
             'azure'."
        ),
        "{stderr}"
    );
    assert_eq!(replay::files(&ws), before, "setup ci wrote a file");
    assert!(!ws.join(".github").exists());
}

#[test]
fn a_misspelled_provider_suggests_the_closest() {
    let (_scratch, ws) = tide_corpus();
    let (code, stdout, stderr) = opentide(&ws, &["setup", "ci", "gitlb", "--yes"]);
    assert_eq!(code, 2, "{stdout}{stderr}");
    assert!(
        stderr.contains("'gitlb' is not one of 'github', 'gitlab', 'azure'."),
        "{stderr}"
    );
    assert!(stderr.contains("help: did you mean 'gitlab'?"), "{stderr}");
    assert!(!ws.join(".gitlab-ci.yml").exists());
}
