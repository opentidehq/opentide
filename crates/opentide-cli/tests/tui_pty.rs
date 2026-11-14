//! `opentide tui` in a pseudo-terminal (UC-3.6d, #951): the binary opened as
//! a person at a terminal opens it, driven by key presses through
//! portable-pty, what it draws read back into a screen by vt100. Open, run
//! validate, quit.

// The terminal UI is the `terminal` feature (off in the WASI build).
#![cfg(feature = "terminal")]
#![cfg(unix)]
#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test helpers: every workspace here is written to a fresh folder"
)]

#[path = "common/tutorial.rs"]
mod tutorial;

use std::io::{Read as _, Write};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use portable_pty::{Child, CommandBuilder, MasterPty, PtySize, SlavePty, native_pty_system};

const ROWS: u16 = 40;
const COLUMNS: u16 = 120;

/// How long the UI may take to draw what a step waits for, or to end.
const TIMEOUT: Duration = Duration::from_secs(120);

/// `opentide tui` on a pseudo-terminal: what it wrote so far, read on a
/// thread of its own, whether that thread saw the end of its output, and the
/// keys typed into it.
struct Session {
    child: Box<dyn Child + Send + Sync>,
    writer: Box<dyn Write + Send>,
    printed: Arc<Mutex<Vec<u8>>>,
    /// The end of the output: every holder of the terminal closed it.
    ended: Arc<AtomicBool>,
    /// How much of `printed` [`Session::expect`] has consumed.
    seen: usize,
    /// The test's own handle on the terminal's other end, held until the
    /// child has exited ([`Session::finish`]). macOS discards what the child
    /// wrote and the master has not read yet once every holder of that end
    /// has closed it, so a child that prints and exits at once (a refusal)
    /// could leave nothing to read; Linux keeps it. Held, the output stays
    /// readable whenever the reader gets to it.
    slave: Option<Box<dyn SlavePty + Send>>,
    _master: Box<dyn MasterPty + Send>,
}

/// `opentide tui` in `repo`, at a terminal of [`COLUMNS`] × [`ROWS`], in a
/// clean environment: no CI variable, no colour setting.
fn spawn(repo: &Path, home: &Path, extra: &[(&str, &str)]) -> Session {
    let pair = native_pty_system()
        .openpty(PtySize {
            rows: ROWS,
            cols: COLUMNS,
            pixel_width: 0,
            pixel_height: 0,
        })
        .expect("open a pseudo-terminal");
    let mut command = CommandBuilder::new(env!("CARGO_BIN_EXE_opentide-cli"));
    command.arg("tui");
    command.cwd(repo);
    command.env_clear();
    command.env("PATH", std::env::var("PATH").unwrap_or_default());
    command.env("HOME", home);
    command.env("TERM", "xterm-256color");
    for (name, value) in extra {
        command.env(name, value);
    }
    let child = pair
        .slave
        .spawn_command(command)
        .expect("spawn opentide tui on a pseudo-terminal");
    // The test keeps its handle on the terminal's other end until the child
    // has exited (`Session::slave`); the output then ends when anything the
    // child left behind closes it too.
    let mut reader = pair.master.try_clone_reader().unwrap();
    let printed = Arc::new(Mutex::new(Vec::new()));
    let ended = Arc::new(AtomicBool::new(false));
    let (sink, end) = (Arc::clone(&printed), Arc::clone(&ended));
    std::thread::spawn(move || {
        let mut chunk = [0_u8; 4096];
        // EIO once every holder of the other end closed it (Linux).
        while let Ok(read) = reader.read(&mut chunk) {
            if read == 0 {
                break;
            }
            sink.lock().unwrap().extend_from_slice(&chunk[..read]);
        }
        end.store(true, Ordering::SeqCst);
    });
    Session {
        child,
        writer: pair.master.take_writer().unwrap(),
        printed,
        ended,
        seen: 0,
        slave: Some(pair.slave),
        _master: pair.master,
    }
}

impl Session {
    /// Whether the UI's process is still running.
    fn alive(&mut self) -> bool {
        self.child.try_wait().unwrap().is_none()
    }

    /// Reads what the UI writes into `screen` until it shows `text`.
    fn wait_for(&mut self, screen: &mut vt100::Parser, text: &str) {
        let deadline = Instant::now() + TIMEOUT;
        loop {
            {
                let printed = self.printed.lock().unwrap();
                screen.process(&printed[self.seen..]);
                self.seen = printed.len();
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
                self.alive(),
                "{text} never showed, and the UI ended:\n{contents}"
            );
            std::thread::sleep(Duration::from_millis(25));
        }
    }

    /// Waits until the run writes `text` after what was last expected, read
    /// as the bytes it wrote (not a screen).
    fn expect(&mut self, text: &str) {
        let deadline = Instant::now() + TIMEOUT;
        loop {
            {
                let printed = self.printed.lock().unwrap();
                let shown = String::from_utf8_lossy(&printed[self.seen..]).into_owned();
                if let Some(at) = shown.find(text) {
                    self.seen += shown[..at + text.len()].len();
                    return;
                }
                assert!(
                    Instant::now() < deadline,
                    "waiting for {text:?}; printed:\n{}",
                    String::from_utf8_lossy(&printed)
                );
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Types `keys`, each press flushed.
    fn press(&mut self, keys: &str) {
        self.writer.write_all(keys.as_bytes()).unwrap();
        self.writer.flush().unwrap();
    }

    /// Waits for the process to exit, closes the test's end of the terminal,
    /// then waits for the end of the output (nothing the run left behind
    /// still holds the terminal): the exit code.
    fn finish(mut self) -> u32 {
        let deadline = Instant::now() + TIMEOUT;
        let status = loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                break status;
            }
            assert!(
                Instant::now() < deadline,
                "the UI never exited; printed:\n{}",
                String::from_utf8_lossy(&self.printed.lock().unwrap())
            );
            std::thread::sleep(Duration::from_millis(20));
        };
        drop(self.slave.take());
        while !self.ended.load(Ordering::SeqCst) {
            assert!(
                Instant::now() < deadline,
                "the output never ended; printed:\n{}",
                String::from_utf8_lossy(&self.printed.lock().unwrap())
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        status.exit_code()
    }
}

/// An empty screen of [`COLUMNS`] × [`ROWS`].
fn screen() -> vt100::Parser {
    let size = |cells: u16| std::num::NonZeroU16::new(cells).unwrap();
    vt100::Parser::new(size(ROWS), size(COLUMNS), 0)
}

#[test]
fn open_run_validate_and_quit() {
    let (base, repo) = tutorial::tutorial();
    let mut session = spawn(&repo, base.path(), &[]);
    let mut screen = screen();
    session.wait_for(&mut screen, "Simulated Actor  1 objective · 1 rule");
    session.wait_for(&mut screen, "1 threat · 1 objective · 1 rule");
    session.press("v");
    session.wait_for(&mut screen, "opentide validate: ✓ 3 objects valid");
    session.press("3");
    session.wait_for(&mut screen, "$ opentide validate");
    session.press("q");
    assert_eq!(session.finish(), 0);
}

#[test]
fn quit_waits_for_validate_then_closes() {
    let (base, repo) = tutorial::tutorial();
    let mut session = spawn(&repo, base.path(), &[]);
    let mut screen = screen();
    session.wait_for(&mut screen, "1 threat · 1 objective · 1 rule");
    session.press("vq");
    // The UI closes once validate is done, with nothing left behind.
    assert_eq!(session.finish(), 0);
}

#[test]
fn a_terminal_in_plain_mode_is_refused_with_the_setting_named() {
    let (base, repo) = tutorial::tutorial();
    let mut session = spawn(&repo, base.path(), &[("NO_COLOR", "1")]);
    session.expect(
        "opentide tui runs only in the human output mode; this run is in plain mode because NO_COLOR is set",
    );
    session.expect("set OPENTIDE_OUTPUT=human to open it anyway");
    assert_eq!(session.finish(), 2);
}
