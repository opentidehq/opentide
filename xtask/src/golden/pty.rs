//! Pseudo-terminals for human mode (Unix only).

use anyhow::{Context, Result};
use rustix::fs::{Mode, OFlags};
use rustix::pty::{OpenptFlags, grantpt, openpt, ptsname, unlockpt};
use rustix::termios::{
    LocalModes, OptionalActions, OutputModes, Winsize, tcgetattr, tcsetattr, tcsetwinsize,
};
use std::fs::File;

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
