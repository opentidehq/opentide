//! `generate` against the oracle's recordings (UC-3.2, #824): every recorded
//! case of the ported generate commands, run in-process through
//! [`opentide_cli::run`] on a fresh copy of its fixture, with the goldens'
//! normalisation (`opentide-compare`), compared with the recording by the
//! goldens' comparator (`opentide_compare::compare`, as `cargo xtask golden
//! check --engine compare` compares them) under `APPROVED_DIFFS.toml`: exit
//! code, stdout, stderr, and every file written.

#![cfg(unix)]
#![expect(
    clippy::unwrap_used,
    reason = "a test helper: a broken recording is a failure"
)]

use std::sync::{Arc, Mutex};

use opentide_cli::env::Env;
use opentide_cli::logging::Sink;
use opentide_cli::{Host, run};

#[path = "common/replay.rs"]
mod replay;
use replay::{Buffer, fixture};

/// The commands whose recordings this test replays.
const COMMANDS: &[&str] = &[
    "generate.exports",
    "generate.exports.navigator",
    "generate.exports.objects",
    "generate.exports.revisions",
];

#[test]
fn generate_cases_are_the_oracles() {
    let (problems, ran) = replay::replay_commands(COMMANDS, true);
    assert!(ran >= 32, "only {ran} cases found");
    assert!(problems.is_empty(), "{}", problems.join("\n\n"));
}

/// The exports that rendered before one failed are on disk, as the oracle,
/// which writes them one after another, leaves them: a threat without
/// `metadata.version` fails the objects table after the Navigator layer.
#[test]
fn exports_before_a_failure_are_written() {
    let scratch = tempfile::tempdir().unwrap();
    let ws = std::fs::canonicalize(scratch.path()).unwrap().join("ws");
    fixture("tide-corpus", &ws);
    let threat = ws.join("Objects/Threat Vectors/threat-0001-simulated-actor.yaml");
    let text = std::fs::read_to_string(&threat).unwrap();
    assert!(text.contains("  version: 1\n"));
    std::fs::write(&threat, text.replace("  version: 1\n", "")).unwrap();
    let sink: Sink = Arc::new(Mutex::new(Buffer::default()));
    let host = Host {
        version: "0.23.0".into(),
        stdout_tty: false,
        stderr_tty: false,
        log_sink: sink,
        cwd: Some(ws.clone()),
        width: None,
        interrupt: opentide_cli::app::Interrupt::default(),
    };
    let argv: Vec<String> = ["--json", "generate", "exports"]
        .into_iter()
        .map(str::to_owned)
        .collect();
    let home = ws.with_file_name("home");
    std::fs::create_dir_all(&home).unwrap();
    let env = Env::from_pairs([("HOME".to_owned(), home.display().to_string())]);
    let (mut out, mut err) = (Vec::new(), Buffer::default());
    let exit_code = run(&argv, &env, &host, &mut out, &mut err);
    let stdout = String::from_utf8(out).unwrap();
    assert_eq!(exit_code, 1, "{stdout}");
    assert!(
        stdout.contains("\"message\":\"exports: KeyError: 'version' while rendering 00000000-0000-4000-8001-000000000001\""),
        "{stdout}"
    );
    let exports = ws.join(".opentide/exports");
    assert!(exports.join("attack-navigator.json").is_file());
    assert!(!exports.join("objects.export.json").exists());
    assert!(!exports.join("revisions.export.json").exists());
}
