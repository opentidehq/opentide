//! Pseudo-terminals for human mode (Unix only).

use anyhow::{Context, Result};
use rustix::fs::{Mode, OFlags};
use rustix::pty::{OpenptFlags, grantpt, openpt, ptsname, unlockpt};
use rustix::termios::{
    LocalModes, OptionalActions, OutputModes, Winsize, tcgetattr, tcsetattr, tcsetwinsize,
};
use std::fs::File;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread::JoinHandle;

/// The terminal size human mode records at.
pub const COLUMNS: u16 = 100;
/// Rows of the recorded terminal.
pub const ROWS: u16 = 40;

/// A pseudo-terminal pair: the program gets `slave`, the runner keeps `master`.
pub struct Pty {
    /// The side the runner reads and writes.
    pub master: File,
    /// The side that becomes the program's stdin, stdout or stderr.
    pub slave: File,
}

/// What a pseudo-terminal is for.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Standard input: no echo, so typed input is not printed back.
    Input,
    /// Standard output or error: no output processing, so the recording
    /// holds the bytes the program wrote (no `\n` to `\r\n`).
    Output,
}

/// Opens a pseudo-terminal of [`COLUMNS`] × [`ROWS`] for `role`.
pub fn open(role: Role) -> Result<Pty> {
    let master =
        openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY).context("open a pseudo-terminal")?;
    grantpt(&master).context("grantpt")?;
    unlockpt(&master).context("unlockpt")?;
    let name = ptsname(&master, Vec::new()).context("ptsname")?;
    let slave = rustix::fs::open(
        name.as_c_str(),
        OFlags::RDWR | OFlags::NOCTTY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .context("open the pseudo-terminal's slave")?;
    let mut termios = tcgetattr(&slave).context("tcgetattr")?;
    match role {
        Role::Input => termios.local_modes.remove(LocalModes::ECHO),
        Role::Output => termios.output_modes.remove(OutputModes::OPOST),
    }
    tcsetattr(&slave, OptionalActions::Now, &termios).context("tcsetattr")?;
    tcsetwinsize(
        &slave,
        Winsize {
            ws_row: ROWS,
            ws_col: COLUMNS,
            ws_xpixel: 0,
            ws_ypixel: 0,
        },
    )
    .context("set the terminal size")?;
    let master = File::from(master);
    rustix::io::fcntl_setfd(&master, rustix::io::FdFlags::CLOEXEC).context("close-on-exec")?;
    Ok(Pty {
        master,
        slave: File::from(slave),
    })
}

/// What a program writes to an output terminal, read without losing its end.
///
/// macOS discards what is still queued on a terminal when the last process
/// holding its slave closes it, so a reader that stops at the slave's close
/// races the program's exit and can lose its last (or only) writes. A capture
/// keeps a copy of the slave open until its reader has drained the terminal:
/// once the program is over, [`Capture::finish`] writes an end marker through
/// that copy, and since a terminal hands its bytes over in order, the reader
/// holds everything the program wrote once it reads the marker.
pub struct Capture {
    /// The runner's copy of the slave, closed only after the reader is done.
    slave: Option<File>,
    marker: Vec<u8>,
    reader: JoinHandle<Vec<u8>>,
}

impl Capture {
    /// Starts reading `pty`'s master. Returns the capture and the slave to
    /// give the program.
    pub fn start(pty: Pty) -> Result<(Self, File)> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let marker = format!(
            "<opentide-golden-end {} {}>",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        )
        .into_bytes();
        let held = pty
            .slave
            .try_clone()
            .context("keep the pseudo-terminal's slave")?;
        let master = pty.master;
        let end = marker.clone();
        let reader = std::thread::spawn(move || read_until(master, &end));
        Ok((
            Self {
                slave: Some(held),
                marker,
                reader,
            },
            pty.slave,
        ))
    }

    /// Everything written to the terminal before now. Call it once the
    /// program (and anything it left holding the terminal) is gone.
    pub fn finish(mut self) -> Result<Vec<u8>> {
        let marked = match self.slave.as_mut() {
            Some(slave) => slave.write_all(&self.marker).is_ok(),
            None => false,
        };
        if !marked {
            // No marker: the reader stops when the slave closes instead.
            self.slave = None;
        }
        let out = self
            .reader
            .join()
            .map_err(|_| anyhow::anyhow!("a terminal reader panicked"))?;
        drop(self.slave);
        Ok(out)
    }
}

/// Reads `master` up to `marker` (dropped from the result), or to the end of
/// the terminal.
fn read_until(mut master: File, marker: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = vec![0u8; 65536];
    loop {
        match master.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                let from = out.len().saturating_sub(marker.len() - 1);
                out.extend_from_slice(&buf[..n]);
                if let Some(at) = out[from..]
                    .windows(marker.len())
                    .position(|window| window == marker)
                {
                    out.truncate(from + at);
                    break;
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What the program wrote survives its slave closing before the reader
    /// gets to it (macOS drops a terminal's queue at the slave's last close).
    #[test]
    fn a_capture_keeps_what_was_written_before_the_program_closed_its_terminal() {
        for _ in 0..50 {
            let (capture, slave) = Capture::start(open(Role::Output).unwrap()).unwrap();
            let mut program = slave;
            program.write_all(b"tty took 1s\n").unwrap();
            drop(program);
            assert_eq!(capture.finish().unwrap(), b"tty took 1s\n");
        }
    }

    /// The marker is found across reads and nothing after it is kept.
    #[test]
    fn the_end_marker_is_found_across_reads_and_cut_with_what_follows() {
        let marker = b"<end 1 2>";
        let Pty { master, slave } = open(Role::Output).unwrap();
        let mut writer = slave;
        let handle = std::thread::spawn(move || read_until(master, marker));
        writer.write_all(b"abc<end").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(100));
        writer.write_all(b" 1 2>late").unwrap();
        assert_eq!(handle.join().unwrap(), b"abc");
        drop(writer);
    }

    /// A program that wrote nothing gives an empty capture, not a hang.
    #[test]
    fn an_empty_terminal_gives_an_empty_capture() {
        let (capture, slave) = Capture::start(open(Role::Output).unwrap()).unwrap();
        drop(slave);
        assert_eq!(capture.finish().unwrap(), b"");
    }
}
