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
        stderr.contains("error: invalid value 'none' for '<ci_platform>'")
            && stderr.contains("[possible values: github, gitlab, azure]"),
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
        stderr.contains("error: invalid value 'gitlb' for '<ci_platform>'"),
        "{stderr}"
    );
    assert!(
        stderr.contains("tip: a similar value exists: 'gitlab'"),
        "{stderr}"
    );
    assert!(!ws.join(".gitlab-ci.yml").exists());
}

/// `--python-version` is written into the pipeline as it is (#1656): a value
/// no provider reads as a supported Python exits 2 and writes nothing, from
/// `setup ci` and from `setup --ci`.
#[test]
fn a_python_version_the_pipeline_cannot_hold_is_refused() {
    let (_scratch, ws) = tide_corpus();
    let before = replay::files(&ws);
    for version in ["2.7", "abc\"; x", "3.12\nevil: true"] {
        let (code, stdout, stderr) = opentide(
            &ws,
            &[
                "setup",
                "ci",
                "gitlab",
                "--python-version",
                version,
                "--yes",
            ],
        );
        assert_eq!(code, 2, "{version:?}: {stdout}{stderr}");
        assert!(stderr.contains("--python-version"), "{stderr}");
        assert!(stderr.contains("use 3.10 or later"), "{stderr}");
    }
    let (code, stdout, stderr) = opentide(
        &ws,
        &[
            "setup",
            "--ci",
            "github",
            "--python-version",
            "3.9",
            "--yes",
        ],
    );
    assert_eq!(code, 2, "{stdout}{stderr}");
    assert_eq!(replay::files(&ws), before, "a refused run wrote a file");
    let (code, stdout, stderr) = opentide(
        &ws,
        &[
            "setup",
            "ci",
            "gitlab",
            "--python-version",
            "3.13.1",
            "--yes",
        ],
    );
    assert_eq!(code, 0, "{stdout}{stderr}");
    let pipeline = std::fs::read_to_string(ws.join(".gitlab-ci.yml")).unwrap();
    assert!(
        pipeline.contains("image: python:3.13.1-slim\n"),
        "{pipeline}"
    );
}

/// `setup ci` never writes over a pipeline it did not write, and says so
/// when it replaces one that was edited (#1656).
#[test]
fn a_pipeline_the_user_wrote_is_kept_and_an_edited_one_is_replaced_with_a_warning() {
    let (_scratch, ws) = tide_corpus();
    let own = "stages: [test]\ntest:\n  script: [make test]\n";
    std::fs::write(ws.join(".gitlab-ci.yml"), own).unwrap();

    let (code, stdout, stderr) = opentide(&ws, &["--json", "setup", "ci", "gitlab", "--plan"]);
    assert_eq!(code, 0, "{stdout}{stderr}");
    let plan: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(plan["steps"][0]["files"][0]["action"], "skip", "{stdout}");
    assert!(stdout.contains("was not written by opentide"), "{stdout}");

    let (code, stdout, stderr) = opentide(&ws, &["setup", "ci", "gitlab", "--yes"]);
    assert_eq!(code, 0, "{stdout}{stderr}");
    assert!(
        stderr.contains(".gitlab-ci.yml was not written by opentide"),
        "{stderr}"
    );
    assert_eq!(
        std::fs::read_to_string(ws.join(".gitlab-ci.yml")).unwrap(),
        own
    );

    let (code, stdout, stderr) = opentide(
        &ws,
        &["setup", "ci", "github", "--default-branch", "main", "--yes"],
    );
    assert_eq!(code, 0, "{stdout}{stderr}");
    assert!(!stderr.contains("is replaced"), "{stderr}");
    let path = ws.join(".github/workflows/opentide.yml");
    let generated = std::fs::read_to_string(&path).unwrap();
    std::fs::write(&path, format!("{generated}# my custom edit\n")).unwrap();
    let (code, stdout, stderr) = opentide(
        &ws,
        &["setup", "ci", "github", "--default-branch", "main", "--yes"],
    );
    assert_eq!(code, 0, "{stdout}{stderr}");
    assert!(
        stderr.contains(".github/workflows/opentide.yml is replaced by the pipeline this opentide writes; lines changed in it by hand are not kept"),
        "{stderr}"
    );
    assert_eq!(std::fs::read_to_string(&path).unwrap(), generated);
}
