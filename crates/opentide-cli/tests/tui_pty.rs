//! `opentide tui` in a pseudo-terminal (UC-3.6d, #951): the binary opened as
//! a person at a terminal opens it, driven by key presses through rexpect,
//! what it draws read back into a screen by vt100. Open, run validate, quit.
#![cfg(unix)]
#![expect(
    clippy::unwrap_used,
    reason = "test helpers: every workspace here is written to a fresh folder"
)]

#[path = "common/tutorial.rs"]
mod tutorial;

use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

use rexpect::process::WaitStatus;
use rexpect::session::PtySession;

const ROWS: u16 = 40;
const COLUMNS: u16 = 120;

/// `opentide tui` in `repo`, at a terminal of [`COLUMNS`] × [`ROWS`], in a
/// clean environment: no CI variable, no colour setting.
fn spawn(repo: &Path, home: &Path, extra: &[(&str, &str)]) -> PtySession {
    let mut command = Command::new("sh");
    command
        .arg("-c")
        .arg(format!(
            "stty cols {COLUMNS} rows {ROWS} && exec \"$0\" tui"
        ))
        .arg(env!("CARGO_BIN_EXE_opentide-cli"))
        .current_dir(repo)
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", home)
        .env("TERM", "xterm-256color");
    for (name, value) in extra {
        command.env(name, value);
    }
    rexpect::session::spawn_command(command, Some(60_000)).unwrap()
}

/// An empty screen of [`COLUMNS`] × [`ROWS`].
fn screen() -> vt100::Parser {
    let size = |cells: u16| std::num::NonZeroU16::new(cells).unwrap();
    vt100::Parser::new(size(ROWS), size(COLUMNS), 0)
}

/// Reads what the UI writes into `screen` until it shows `text`.
fn wait_for(session: &mut PtySession, screen: &mut vt100::Parser, text: &str) {
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        // rexpect hands the stream out a byte at a time, each as a `char`.
        while let Some(byte) = session.try_read() {
            screen.process(&[u8::try_from(byte).unwrap()]);
        }
        let contents = screen.screen().contents();
        if contents.contains(text) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "{text} never showed:\n{contents}"
        );
        assert!(
            session.process().status() == Some(WaitStatus::StillAlive),
            "{text} never showed, and the UI ended:\n{contents}"
        );
        std::thread::sleep(Duration::from_millis(25));
    }
}

/// Types `keys`: rexpect's writer buffers a line, so each press is flushed.
fn press(session: &mut PtySession, keys: &str) {
    session.send(keys).unwrap();
    session.flush().unwrap();
}

#[test]
fn open_run_validate_and_quit() {
    let (base, repo) = tutorial::tutorial();
    let mut session = spawn(&repo, base.path(), &[]);
    let mut screen = screen();
    wait_for(
        &mut session,
        &mut screen,
        "Simulated Actor  1 objective · 1 rule",
    );
    wait_for(&mut session, &mut screen, "1 threat · 1 objective · 1 rule");
    press(&mut session, "v");
    wait_for(
        &mut session,
        &mut screen,
        "opentide validate: ✓ 3 objects valid",
    );
    press(&mut session, "3");
    wait_for(&mut session, &mut screen, "$ opentide validate");
    press(&mut session, "q");
    session.exp_eof().unwrap();
    let status = session.process().wait().unwrap();
    assert!(matches!(status, WaitStatus::Exited(_, 0)), "{status:?}");
}

#[test]
fn quit_waits_for_validate_then_closes() {
    let (base, repo) = tutorial::tutorial();
    let mut session = spawn(&repo, base.path(), &[]);
    let mut screen = screen();
    wait_for(&mut session, &mut screen, "1 threat · 1 objective · 1 rule");
    press(&mut session, "vq");
    // The UI closes once validate is done, with nothing left behind.
    session.exp_eof().unwrap();
    let status = session.process().wait().unwrap();
    assert!(matches!(status, WaitStatus::Exited(_, 0)), "{status:?}");
}

#[test]
fn a_terminal_in_plain_mode_is_refused_with_the_setting_named() {
    let (base, repo) = tutorial::tutorial();
    let mut session = spawn(&repo, base.path(), &[("NO_COLOR", "1")]);
    session
        .exp_string("opentide tui runs only in the human output mode; this run is in plain mode because NO_COLOR is set")
        .unwrap();
    session
        .exp_string("set OPENTIDE_OUTPUT=human to open it anyway")
        .unwrap();
    session.exp_eof().unwrap();
    let status = session.process().wait().unwrap();
    assert!(matches!(status, WaitStatus::Exited(_, 2)), "{status:?}");
}
