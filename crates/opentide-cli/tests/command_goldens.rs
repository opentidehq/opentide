//! The commands of UC-3.5 (#827) against the oracle's recordings: every
//! recorded case on the static fixtures, replayed in-process
//! (`common/replay.rs`) and compared under `APPROVED_DIFFS.toml`. The
//! generated fixtures (`fault`, `heavy-small`) are `cargo xtask golden check
//! --engine compare`'s. `OPENTIDE_REPLAY_FILTER=<part of a case id>` narrows a
//! run while debugging.

#![cfg(unix)]
#![expect(
    clippy::unwrap_used,
    reason = "a test helper: a broken recording is a failure"
)]

#[path = "common/replay.rs"]
mod replay;

fn check(commands: &[&str], at_least: usize) {
    let (problems, ran) = replay::replay_commands(commands, true);
    assert!(ran >= at_least, "only {ran} cases found");
    assert!(
        problems.is_empty(),
        "{} problem(s):\n\n{}",
        problems.len(),
        problems.join("\n\n")
    );
}

#[test]
fn explain_cases_are_the_oracles() {
    check(&["explain"], 12);
}

#[test]
fn validate_cases_are_the_oracles() {
    check(&["validate"], 100);
}

/// `validate --watch` in `plain` mode: one pass's frames and outcome line,
/// then Ctrl-C (already pressed here) stops it with exit 0 and nothing on
/// stderr.
#[test]
fn a_watch_shows_a_pass_and_ctrl_c_exits_0() {
    use opentide_cli::env::Env;
    use opentide_cli::logging::Sink;
    use opentide_cli::{Host, run};
    use std::sync::{Arc, Mutex};
    let scratch = tempfile::tempdir().unwrap();
    let ws = std::fs::canonicalize(scratch.path()).unwrap().join("ws");
    replay::fixture("tide-corpus-typo", &ws);
    let interrupt = opentide_cli::app::Interrupt::default();
    interrupt.request();
    let sink: Sink = Arc::new(Mutex::new(replay::Buffer::default()));
    let host = Host {
        version: "0.23.0".into(),
        stdout_tty: false,
        stderr_tty: false,
        log_sink: sink,
        cwd: Some(ws.clone()),
        width: None,
        interrupt,
    };
    let argv: Vec<String> = ["validate", "--watch"]
        .into_iter()
        .map(str::to_owned)
        .collect();
    let env = Env::from_pairs([("HOME".to_owned(), ws.display().to_string())]);
    let (mut out, mut err) = (Vec::new(), replay::Buffer::default());
    let code = run(&argv, &env, &host, &mut out, &mut err);
    let stdout = String::from_utf8(out).unwrap();
    assert_eq!(code, 0, "{stdout}");
    assert!(
        stdout.starts_with("error[vocab_unknown]: 'high' is not a alert severity value\n"),
        "{stdout}"
    );
    assert!(
        stdout.contains("\n✗ 1 error in 1 file · 1 fixable with --fix · 12 objects checked · "),
        "{stdout}"
    );
    assert!(err.0.lock().unwrap().is_empty());
}
