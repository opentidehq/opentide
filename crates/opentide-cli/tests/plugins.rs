//! Platform plugins without a plugin host (UC-4.5, #835): the command line as
//! the native binary and the npm package run it. A workspace that enables a
//! platform that is not built in is told that plugins load only from the
//! Python package, and `--platform` takes none but the built-in platforms.
//! The sample plugin's workspace files are `tests/fixtures/plugin_platform/`;
//! the plugin itself runs in `tests/test_platforms/test_plugin_hook.py`.

#![cfg(unix)]
#![expect(
    clippy::unwrap_used,
    reason = "a test helper: a broken fixture is a failure"
)]

#[path = "common/replay.rs"]
mod replay;

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use opentide_cli::env::Env;
use opentide_cli::logging::Sink;
use opentide_cli::{Host, run};
use serde_json::Value;

/// The tide corpus with the sample plugin's platform enabled and its rules.
fn workspace() -> (tempfile::TempDir, PathBuf) {
    let scratch = tempfile::tempdir().unwrap();
    let ws = std::fs::canonicalize(scratch.path()).unwrap().join("ws");
    replay::fixture("tide-corpus", &ws);
    let sample = replay::repo().join("tests/fixtures/plugin_platform/workspace");
    let platforms = ws.join(".opentide/configurations/platforms");
    std::fs::create_dir_all(&platforms).unwrap();
    std::fs::copy(sample.join("acme.toml"), platforms.join("acme.toml")).unwrap();
    let rules = ws.join("Objects/Detection Rules");
    std::fs::copy(
        sample.join("rule-acme-process.yaml"),
        rules.join("rule-acme-process.yaml"),
    )
    .unwrap();
    (scratch, ws)
}

/// `opentide --json <words>` from *cwd*: the exit code and the document.
fn opentide(cwd: &Path, words: &[&str]) -> (i32, Value) {
    let host = Host {
        version: "0.23.0".into(),
        stdout_tty: false,
        stderr_tty: false,
        log_sink: Arc::new(Mutex::new(replay::Buffer::default())) as Sink,
        cwd: Some(cwd.to_path_buf()),
        width: None,
        interrupt: opentide_cli::app::Interrupt::default(),
    };
    let mut argv = vec!["--json".to_owned()];
    argv.extend(words.iter().map(|word| (*word).to_owned()));
    let home = cwd.with_file_name("home");
    std::fs::create_dir_all(&home).unwrap();
    let env = Env::from_pairs([("HOME".to_owned(), home.display().to_string())]);
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code = run(&argv, &env, &host, &mut out, &mut err);
    let stdout = String::from_utf8(out).unwrap();
    let document = serde_json::from_str(&stdout).unwrap_or_else(|_| panic!("{stdout}"));
    (code, document)
}

#[test]
fn validate_says_a_plugin_platform_needs_the_python_package() {
    let (_scratch, ws) = workspace();
    let (code, document) = opentide(&ws, &["validate"]);
    assert_eq!(code, 1, "{document}");
    let warnings: Vec<&str> = document["warnings"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(
        warnings.contains(&opentide_connectors::plugin::unavailable("acme").as_str()),
        "{warnings:?}"
    );
    // Without the plugin, its block is not checked: the schema has no such
    // platform.
    let issues = document["report"]["issues"].as_array().unwrap();
    assert!(
        issues
            .iter()
            .any(|issue| issue["field_path"] == serde_json::json!(["configurations", "acme"])),
        "{issues:?}"
    );
}

#[test]
fn platform_takes_only_the_builtin_platforms_without_plugins() {
    let (_scratch, ws) = workspace();
    for words in [
        &["query", "--platform", "acme", "x"][..],
        &["deploy", "--platform", "acme", "--all"][..],
        &["validate", "query", "--live", "--platform", "acme"][..],
    ] {
        let (code, document) = opentide(&ws, words);
        assert_eq!(code, 2, "{words:?}: {document}");
        assert_eq!(
            document["failure"]["code"], "usage_invalid_choice",
            "{words:?}"
        );
    }
    let (_, sentinel) = opentide(&ws, &["deploy", "--platform", "sentinel", "--dry-run"]);
    assert_ne!(sentinel["failure"]["code"], "usage_invalid_choice");
}
