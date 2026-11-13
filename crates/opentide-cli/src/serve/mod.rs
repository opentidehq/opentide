//! `opentide serve` (UC-3.8, #830): CLI commands in one warm process, for editors.
//!
//! JSON-RPC 2.0, one message per line, on stdin and stdout (the contract is
//! `docs/cli/serve.md`). `initialize` names the protocol, the version and
//! the digest of the command tree; `run` executes a command as
//! `opentide --json <argv>` would in a new process, with the request's
//! `cwd` and `env`, and answers with the document it prints and its exit
//! code; `invalidate` drops what an edit made stale; `progress`
//! notifications carry a run's events; `$/cancelRequest` stops a run (it
//! answers 130 and the `interrupted` document); `shutdown` and `exit` end
//! the session. Requests are handled one at a time, in order
//! ([`server::Server`]). Every command runs on Rust in this process, its
//! workspace kept warm between read-only runs ([`runner::HostRunner`]); no
//! Python runs any request (UC-6.0d, #841). This is the host the Python
//! package's `opentide.cli.services.serve` was until UC-3.8: the payloads
//! are its.

pub mod decode;
pub mod fetch;
pub mod runner;
pub mod server;

use std::io::Read;
use std::path::PathBuf;
use std::sync::Arc;

pub use runner::{EventSink, HostRunner, Job, Plan, RunOutcome, RunRequest, Runner, RustRun};
pub use server::{Server, Writer, commands_digest};

/// The root options `serve` was given.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Launch {
    /// The server's working directory.
    pub cwd: Option<PathBuf>,
    /// `--repo`, resolved, when given on the command line.
    pub repo: Option<String>,
    /// `--data`, resolved.
    pub data: Option<String>,
    /// `--proxy` (or `OPENTIDE_PROXY`).
    pub proxy: Option<String>,
    /// `--debug` (or `OPENTIDE_DEBUG`).
    pub debug: bool,
}

impl Launch {
    /// Every run's starting environment: the process's, then what the root
    /// options given to `serve` itself set, which are every run's defaults.
    pub fn base_environment(&self, process: &crate::env::Env) -> Vec<(String, String)> {
        let mut values: Vec<(String, String)> = process
            .iter()
            .map(|(name, value)| (name.to_owned(), value.to_owned()))
            .collect();
        let mut put = |name: &str, value: &str| {
            values.retain(|(existing, _)| existing != name);
            values.push((name.to_owned(), value.to_owned()));
        };
        if let Some(repo) = &self.repo {
            put("OPENTIDE_REPO_ROOT", repo);
            put("OPENTIDE_TIDE_WORKSPACE", repo);
        }
        if let Some(data) = &self.data {
            put("OPENTIDE_DATA_ROOT", data);
        }
        if let Some(proxy) = &self.proxy {
            put("OPENTIDE_PROXY", proxy);
        }
        if self.debug {
            put("OPENTIDE_DEBUG", "1");
        }
        values
    }
}

/// The lines read from `source` until the end of input, each handed to `server`.
pub fn read_lines(mut source: impl Read, server: &Server) {
    let mut pending: Vec<u8> = Vec::new();
    let mut chunk = vec![0_u8; 65536];
    loop {
        let read = match source.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(read) => read,
        };
        pending.extend_from_slice(&chunk[..read]);
        while let Some(end) = pending.iter().position(|byte| *byte == b'\n') {
            let line: Vec<u8> = pending.drain(..=end).collect();
            server.receive(&line[..line.len() - 1]);
        }
    }
    if !pending.is_empty() {
        server.receive(&pending);
    }
    server.close_input();
}

/// Serves on this process's stdin and stdout until `exit`, the end of
/// input or a termination signal; the exit code (`128 + n` for signal `n`,
/// 130 for Ctrl-C).
///
/// The protocol keeps a duplicate of descriptor 1, which then points at
/// stderr: nothing a command or a child process writes to stdout reaches
/// the client. In the same way it reads a duplicate of descriptor 0, which
/// then reads the null device: a run that reads stdin (`query -`) reads
/// nothing of the client's requests.
///
/// # Errors
///
/// An I/O error setting up stdio.
pub fn serve(
    launch: &Launch,
    version: &str,
    interrupt: &crate::app::Interrupt,
) -> std::io::Result<i32> {
    use std::io::Write;
    let process = crate::env::Env::from_process();
    let base_env = launch.base_environment(&process);
    let cwd = launch
        .cwd
        .clone()
        .or_else(|| std::env::current_dir().ok())
        .unwrap_or_default();
    let runner = Arc::new(HostRunner::new(base_env, cwd, version));
    std::io::stdout().flush()?;
    let rpc = crate::mcp::stdio::reserve_stdout()?;
    let requests = stdio::reserve_stdin()?;
    let output = std::sync::Mutex::new(rpc.writer()?);
    let write: Writer = Box::new(move |message: &str| {
        let mut output = output
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut line = Vec::with_capacity(message.len() + 1);
        line.extend_from_slice(message.as_bytes());
        line.push(b'\n');
        output.write_all(&line)?;
        output.flush()
    });
    let server = Server::new(write, runner, version);
    let reader = server.clone();
    std::thread::Builder::new()
        .name("opentide-serve-stdin".into())
        .spawn(move || read_lines(requests, &reader))?;
    let signals = signals::Termination::install(&server)?;
    let ended = server.serve(&|| interrupt.requested());
    let signalled = signals.finish();
    rpc.restore()?;
    if !ended {
        return Ok(interrupt.report(&mut std::io::stderr()));
    }
    Ok(signalled.map_or(0, |signal| 128 + signal))
}

mod stdio {
    //! stdin for JSON-RPC alone.

    use std::fs::File;

    /// A duplicate of stdin for the requests; on Unix descriptor 0 then
    /// reads the null device.
    #[cfg(unix)]
    pub fn reserve_stdin() -> std::io::Result<File> {
        use std::os::fd::AsFd;
        let stdin = std::io::stdin();
        let requests = File::from(stdin.as_fd().try_clone_to_owned()?);
        let null = File::open("/dev/null")?;
        rustix::stdio::dup2_stdin(null.as_fd())?;
        Ok(requests)
    }

    /// A duplicate of stdin for the requests (Windows: the standard handle stays).
    #[cfg(windows)]
    pub fn reserve_stdin() -> std::io::Result<File> {
        use std::os::windows::io::AsHandle;
        Ok(File::from(
            std::io::stdin().as_handle().try_clone_to_owned()?,
        ))
    }
}

mod signals {
    //! SIGTERM and SIGHUP as the end of input while the server serves.
    //!
    //! A run in progress is cancelled, as by `exit`, so its cleanup runs (a
    //! `setup --plan` copy is removed); a second signal ends the process at
    //! once, as the signal's default does.

    use super::Server;

    #[cfg(unix)]
    pub struct Termination {
        handle: signal_hook::iterator::Handle,
        ids: Vec<signal_hook::SigId>,
        received: std::sync::Arc<std::sync::Mutex<Option<i32>>>,
        /// Each signal with a flag its handler sets: what `finish` reports
        /// when the watcher had not read the signal before the input ended
        /// on its own (#974).
        arrived: Vec<(i32, std::sync::Arc<std::sync::atomic::AtomicBool>)>,
        watcher: Option<std::thread::JoinHandle<()>>,
    }

    #[cfg(unix)]
    impl Termination {
        pub fn install(server: &Server) -> std::io::Result<Termination> {
            use signal_hook::consts::{SIGHUP, SIGTERM};
            use std::sync::atomic::AtomicBool;
            use std::sync::{Arc, Mutex};
            let seen = Arc::new(AtomicBool::new(false));
            let mut ids = Vec::new();
            let mut arrived = Vec::new();
            for signal in [SIGTERM, SIGHUP] {
                // Registered first: on the second signal it finds the flag set.
                ids.push(signal_hook::flag::register_conditional_default(
                    signal,
                    Arc::clone(&seen),
                )?);
                ids.push(signal_hook::flag::register(signal, Arc::clone(&seen))?);
                let flag = Arc::new(AtomicBool::new(false));
                ids.push(signal_hook::flag::register(signal, Arc::clone(&flag))?);
                arrived.push((signal, flag));
            }
            let mut signals = signal_hook::iterator::Signals::new([SIGTERM, SIGHUP])?;
            let handle = signals.handle();
            let received = Arc::new(Mutex::new(None));
            let record = Arc::clone(&received);
            let server = server.clone();
            let watcher = std::thread::Builder::new()
                .name("opentide-serve-stop".into())
                .spawn(move || {
                    if let Some(signal) = signals.forever().next() {
                        *record
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(signal);
                        server.close_input();
                    }
                })?;
            Ok(Termination {
                handle,
                ids,
                received,
                arrived,
                watcher: Some(watcher),
            })
        }

        /// Puts the signals back; the one received, if any.
        pub fn finish(mut self) -> Option<i32> {
            self.handle.close();
            if let Some(watcher) = self.watcher.take() {
                let _ignored = watcher.join();
            }
            for id in self.ids.drain(..) {
                signal_hook::low_level::unregister(id);
            }
            let received = *self
                .received
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            // Closing the iterator drops a signal the watcher had not read
            // yet: its handler's flag still says it came.
            received.or_else(|| {
                self.arrived
                    .iter()
                    .find(|(_, flag)| flag.load(std::sync::atomic::Ordering::SeqCst))
                    .map(|(signal, _)| *signal)
            })
        }
    }

    #[cfg(not(unix))]
    pub struct Termination;

    #[cfg(not(unix))]
    impl Termination {
        pub fn install(_server: &Server) -> std::io::Result<Termination> {
            Ok(Termination)
        }

        pub fn finish(self) -> Option<i32> {
            None
        }
    }

    #[cfg(all(test, unix))]
    mod tests {
        use super::Termination;
        use crate::serve::runner::{EventSink, Job, Plan, RunOutcome, RunRequest, Runner};
        use crate::serve::{Server, Writer};
        use std::sync::Arc;

        struct NoRuns;
        impl Runner for NoRuns {
            fn plan(&self, _: &RunRequest) -> Plan {
                Plan::default()
            }
            fn run(&self, _: &RunRequest, plan: &Plan, job: &Arc<Job>, _: EventSink) -> RunOutcome {
                job.finish();
                crate::serve::runner::document(&plan.words, "{}", 0)
            }
            fn interrupt(&self) {}
            fn invalidate(&self, _: &[String]) {}
        }

        /// #974: a SIGTERM the watcher has not read when the input ends on its
        /// own is still the signal the server reports (exit 143).
        #[test]
        fn a_signal_not_yet_read_when_serving_ends_is_still_reported() {
            let write: Writer = Box::new(|_: &str| Ok(()));
            let server = Server::new(write, Arc::new(NoRuns), "0.0.0");
            let signals = Termination::install(&server).unwrap();
            // The handler runs before raise returns; the iterator closes next,
            // before the watcher can be relied on to have read the signal.
            signal_hook::low_level::raise(signal_hook::consts::SIGTERM).unwrap();
            assert_eq!(signals.finish(), Some(signal_hook::consts::SIGTERM));
        }
    }
}
