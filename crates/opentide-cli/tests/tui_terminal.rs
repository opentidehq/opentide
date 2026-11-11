//! `opentide tui` at a terminal (UC-3.6b, #947): the runs the goldens
//! cannot record, in pseudo-terminals. stdin and stdout are terminals here,
//! so the UI would open in `human` mode; a setting that puts the run in
//! `plain` mode is named, with a `help:` that says how to open it anyway.

#![cfg(unix)]
#![expect(
    clippy::unwrap_used,
    reason = "test helpers: a terminal that does not open is a failure"
)]

use std::fs::File;
use std::io::Read;
use std::os::fd::OwnedFd;
use std::process::{Command, Stdio};

use rustix::fs::{Mode, OFlags};
use rustix::pty::{OpenptFlags, grantpt, openpt, ptsname, unlockpt};
use rustix::termios::{OptionalActions, OutputModes, tcgetattr, tcsetattr};

/// A pseudo-terminal: its master, and its slave for the child.
fn terminal() -> (File, OwnedFd) {
    let master = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY).unwrap();
    grantpt(&master).unwrap();
    unlockpt(&master).unwrap();
    let name = ptsname(&master, Vec::new()).unwrap();
    let slave = rustix::fs::open(
        name.as_c_str(),
        OFlags::RDWR | OFlags::NOCTTY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .unwrap();
    // `\n` as written: no carriage return added.
    let mut termios = tcgetattr(&slave).unwrap();
    termios.output_modes.remove(OutputModes::OPOST);
    tcsetattr(&slave, OptionalActions::Now, &termios).unwrap();
    (File::from(master), slave)
}

/// Reads a master until the slave's last holder closed it.
fn drain(mut master: File) -> String {
    let mut bytes = Vec::new();
    let mut chunk = [0; 4096];
    loop {
        match master.read(&mut chunk) {
            Ok(0) | Err(_) => break, // EIO once every slave is closed (Linux)
            Ok(read) => bytes.extend_from_slice(&chunk[..read]),
        }
    }
    String::from_utf8(bytes).unwrap()
}

/// `opentide tui` with stdin, stdout and stderr each a terminal: exit
/// code, stdout, stderr.
fn tui(pairs: &[(&str, &str)], args: &[&str]) -> (i32, String, String) {
    let (input_master, input) = terminal();
    let (out_master, out) = terminal();
    let (err_master, err) = terminal();
    let dir = tempfile::tempdir().unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_opentide"))
        .args(args)
        .arg("tui")
        .current_dir(dir.path())
        .env_clear()
        .env("HOME", dir.path())
        .env("TERM", "xterm-256color")
        .envs(pairs.iter().copied())
        .stdin(Stdio::from(input))
        .stdout(Stdio::from(out))
        .stderr(Stdio::from(err))
        .spawn()
        .unwrap();
    let readers = [out_master, err_master].map(|master| std::thread::spawn(move || drain(master)));
    let code = child.wait().unwrap().code().unwrap();
    drop(child);
    drop(input_master);
    let [stdout, stderr] = readers.map(|reader| reader.join().unwrap());
    (code, stdout, stderr)
}

const NEXT: &str = "→ opentide info · catalogue counts and platforms\n\
                    → opentide validate · diagnostics for every object\n";

#[test]
fn a_setting_that_makes_the_run_plain_is_named_with_how_to_open_it_anyway() {
    for (pairs, args, reason) in [
        (&[("NO_COLOR", "1")][..], &[][..], "NO_COLOR is set"),
        (&[][..], &["--no-color"][..], "--no-color was passed"),
        (
            &[("OPENTIDE_OUTPUT", "plain")][..],
            &[][..],
            "OPENTIDE_OUTPUT is plain",
        ),
        (&[("TERM", "dumb")][..], &[][..], "TERM is dumb"),
        (
            &[("CI", "true")][..],
            &[][..],
            "a CI environment was detected",
        ),
    ] {
        let (code, stdout, stderr) = tui(pairs, args);
        assert_eq!(code, 2, "{pairs:?} {args:?}");
        assert_eq!(stdout, "");
        let expected = format!(
            "error: opentide tui runs only in the human output mode; \
             this run is in plain mode because {reason}\n  \
             help: set OPENTIDE_OUTPUT=human to open it anyway\n{NEXT}"
        );
        // Bold and dim in plain mode at a terminal: compare the words.
        assert_eq!(strip_sgr(&stderr), expected, "{pairs:?} {args:?}");
    }
}

#[test]
fn the_ui_itself_runs_on_python_where_it_would_open() {
    let (code, stdout, stderr) = tui(&[], &[]);
    assert_eq!(code, 2);
    assert_eq!(stdout, "");
    let stderr = strip_sgr(&stderr);
    assert!(
        stderr.starts_with(
            "error: opentide tui's terminal UI has no Rust implementation yet: \
             unset OPENTIDE_ENGINE, or set it to python or compare."
        ),
        "{stderr}"
    );
}

#[test]
fn an_agent_at_a_terminal_is_refused_by_mode() {
    let (code, _, stderr) = tui(&[("AI_AGENT", "test")], &[]);
    assert_eq!(code, 2);
    assert_eq!(
        strip_sgr(&stderr),
        format!(
            "error: opentide tui needs an interactive terminal; this run is in agent mode\n\
             {NEXT}tip: add --json for machine-readable output\n"
        )
    );
}

/// `text` without its SGR sequences (`ESC [ … m`).
fn strip_sgr(text: &str) -> String {
    let mut out = String::new();
    let mut rest = text;
    while let Some(at) = rest.find("\u{1b}[") {
        out.push_str(&rest[..at]);
        let tail = &rest[at + 2..];
        let end = tail.find('m').map_or(tail.len(), |end| end + 1);
        rest = &tail[end..];
    }
    out.push_str(rest);
    out
}
