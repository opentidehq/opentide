//! A build without the terminal prompts (the `terminal` feature off: the wheel, the WASI
//! module) at a terminal behaves as it does with no terminal at all (#1743 review): it asks
//! no question and refuses none with "cannot ask questions". `cargo test -p opentide-cli
//! --no-default-features --test no_terminal_prompts`; with the feature on, this file is empty.

#![cfg(not(feature = "terminal"))]
#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "a test: a run that does not go as scripted is a failure"
)]

use std::io::Read as _;
use std::path::Path;
use std::process::{Command, Stdio};

use portable_pty::{CommandBuilder, PtySize, native_pty_system};

/// What a run ended with: its exit code and everything it printed.
struct Outcome {
    code: i64,
    printed: String,
}

fn scrub(command: &mut Command, cwd: &Path) {
    command
        .current_dir(cwd)
        .env("OPENTIDE_OUTPUT", "human")
        .env("TERM", "xterm")
        .env("GIT_CEILING_DIRECTORIES", cwd)
        .env_remove("OPENTIDE_REPO_ROOT")
        .env_remove("OPENTIDE_TIDE_WORKSPACE");
}

/// `opentide <args>` with stdin, stdout and stderr not a terminal.
fn piped(cwd: &Path, args: &[&str]) -> Outcome {
    let mut command = Command::new(env!("CARGO_BIN_EXE_opentide-cli"));
    command.args(args).stdin(Stdio::null());
    scrub(&mut command, cwd);
    let output = command.output().expect("run opentide");
    let mut printed = String::from_utf8_lossy(&output.stdout).into_owned();
    printed.push_str(&String::from_utf8_lossy(&output.stderr));
    Outcome {
        code: i64::from(output.status.code().expect("an exit code")),
        printed,
    }
}

/// `opentide <args>` on a pseudo-terminal, nothing typed.
fn at_a_terminal(cwd: &Path, args: &[&str]) -> Outcome {
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
    command.env_remove("OPENTIDE_REPO_ROOT");
    command.env_remove("OPENTIDE_TIDE_WORKSPACE");
    let mut child = pair.slave.spawn_command(command).expect("spawn on a pty");
    drop(pair.slave);
    let mut reader = pair.master.try_clone_reader().unwrap();
    let reading = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = reader.read_to_end(&mut bytes);
        bytes
    });
    let status = child.wait().expect("the run ends by itself");
    drop(pair.master);
    let printed = String::from_utf8_lossy(&reading.join().unwrap()).into_owned();
    Outcome {
        code: i64::from(status.exit_code()),
        printed,
    }
}

#[test]
fn a_build_without_terminal_prompts_never_stops_a_terminal_run_for_them() {
    for args in [
        &["new", "rule", "--name", "X"][..],
        &["new", "rule"][..],
        &["setup"][..],
    ] {
        let dir = tempfile::tempdir().unwrap();
        let alone = piped(dir.path(), args);
        let dir = tempfile::tempdir().unwrap();
        let tty = at_a_terminal(dir.path(), args);
        assert!(
            !tty.printed.contains("cannot ask questions"),
            "{args:?} at a terminal: {}",
            tty.printed
        );
        assert_eq!(
            tty.code, alone.code,
            "{args:?}: at a terminal {}, piped {}\n{}",
            tty.code, alone.code, tty.printed
        );
    }
}
