//! The command line (`cli` feature): the `opentide` program as a function.
//!
//! [`main`] is the program: the PyPI console script, npm's `bin` and the
//! `opentide` binary this crate carries all call it (ADR 0003), so they
//! share one command tree, one JSON envelope and one set of exit codes.
//! [`run_json`] runs one command in this process for its `--json`
//! document, without touching the process's streams.

use std::sync::{Arc, Mutex};

use opentide_cli::env::Env;
use opentide_cli::logging::Sink;

use crate::{Document, Error};

/// The version the command line reports (`opentide --version`, the
/// `version` of `opentide --json commands`): `OPENTIDE_VERSION` when the
/// build sets it (the release builds, to the package's version), otherwise
/// the crate's.
pub const VERSION: &str = match option_env!("OPENTIDE_VERSION") {
    Some(version) => version,
    None => env!("CARGO_PKG_VERSION"),
};

/// Runs `opentide` with `argv` (without the program name) as the process:
/// its environment, working directory, stdin, stdout and stderr, a panic
/// hook and a Ctrl-C handler. Returns the exit code; the caller exits with
/// it.
///
/// ```no_run
/// let argv: Vec<String> = std::env::args().skip(1).collect();
/// std::process::exit(opentide::cli::main(&argv));
/// ```
pub fn main(argv: &[String]) -> i32 {
    opentide_cli::main(argv, VERSION)
}

/// [`main`] as the whole process: runs `opentide` with `argv`, then exits
/// with its status. The run leaves what it built (a workspace's index, a
/// large document) to the exit to reclaim, which is faster than freeing it;
/// a host that goes on after the run calls [`main`] instead.
pub fn exit(argv: &[String]) -> ! {
    opentide_cli::exit(argv, VERSION)
}

/// Runs `opentide --json <argv>` in this process and returns its document:
/// the envelope (`ok`, `command`, `result`, `failure`, ...) or, for
/// `commands`, the command tree. A command that fails still writes its
/// document, with `ok: false` and `failure.code`.
///
/// It reads the process's environment and working directory as the command
/// line does (`--repo` names a workspace elsewhere), and writes nothing to
/// the process's streams: the log lines go to [`Error::NoDocument`] when no
/// document comes.
///
/// ```
/// let tree = opentide::cli::run_json(["commands"])?;
/// assert_eq!(tree.value()["program"], "opentide");
/// # Ok::<(), opentide::Error>(())
/// ```
///
/// # Errors
///
/// [`Error::NoDocument`] when the command wrote no JSON document.
pub fn run_json<I, S>(argv: I) -> Result<Document, Error>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let argv: Vec<String> = std::iter::once("--json".to_owned())
        .chain(argv.into_iter().map(Into::into))
        .collect();
    let log = Arc::new(Mutex::new(Vec::<u8>::new()));
    let sink: Sink = log.clone();
    let host = opentide_cli::Host {
        version: VERSION.to_owned(),
        stdout_tty: false,
        stderr_tty: false,
        log_sink: sink,
        cwd: std::env::current_dir().ok(),
        width: None,
        interrupt: opentide_cli::app::Interrupt::default(),
    };
    let env = Env::from_process();
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let exit_code = opentide_cli::run(&argv, &env, &host, &mut out, &mut err);
    let text = String::from_utf8_lossy(&out).into_owned();
    Document::parse(text).map_err(|_| {
        let logged = log
            .lock()
            .map(|log| String::from_utf8_lossy(&log).into_owned())
            .unwrap_or_default();
        Error::NoDocument {
            exit_code,
            stderr: format!("{}{logged}", String::from_utf8_lossy(&err)),
        }
    })
}
