//! `opentide mcp start` (UC-3.7, #829; UC-6.0c, #841): the MCP server on
//! rmcp, the official Rust MCP SDK, over stdio.
//!
//! What the server says of itself (its name, instructions, capabilities, the
//! protocol version it falls back to, every tool's description and schemas,
//! every resource and template) is `data/mcp/manifest.json`, edited by hand:
//! MCP shapes are a plan §3 invariant.
//!
//! Every tool ([`TOOLS`]) and every resource runs here, on the workspace
//! crates: no Python is needed.
//! The tools that reach a tenant (`validate_query` and `run_query` with
//! `live`, `deploy_rule` without `dry_run`) run the command line's own
//! commands in this process.
//!
//! stdout carries JSON-RPC alone: the server writes its frames to a duplicate
//! of descriptor 1, and descriptor 1 itself points at stderr while it serves
//! (Unix), so nothing else in the process (a log line, a child process) can
//! corrupt a frame. Logging is the run's: WARNING and above on stderr,
//! everything with `--debug`.

mod args;
mod catalog;
mod deploy;
#[cfg(any(target_os = "wasi", test))]
pub(crate) mod fetch;
mod graph;
mod plugin;
mod queries;
mod resources;
mod server;
#[cfg(test)]
mod tests;
mod tools;

use std::path::PathBuf;

pub use server::{Answer, Server};

#[cfg(test)]
mod launch_tests {
    use super::Launch;

    #[test]
    fn the_root_options_export_what_the_python_root_callback_does() {
        assert!(Launch::default().environment().is_empty());
        let launch = Launch {
            cwd: None,
            repo: Some("/ws".into()),
            data: Some("/data".into()),
            proxy: Some("http://p:3128".into()),
            debug: true,
        };
        let environment = launch.environment();
        let get = |name: &str| {
            environment
                .iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.as_str())
        };
        assert_eq!(get("OPENTIDE_REPO_ROOT"), Some("/ws"));
        assert_eq!(get("OPENTIDE_TIDE_WORKSPACE"), Some("/ws"));
        assert_eq!(get("OPENTIDE_DATA_ROOT"), Some("/data"));
        for name in ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"] {
            assert_eq!(get(name), Some("http://p:3128"), "{name}");
        }
        assert_eq!(get("OPENTIDE_DEBUG"), Some("1"));
        assert_eq!(get("DEBUG_ENABLED"), Some("1"));
        assert_eq!(environment.len(), 9);
    }
}

/// Every tool the server answers, in the manifest's order.
pub const TOOLS: &[&str] = &[
    "search",
    "get_chaining",
    "coverage",
    "graph",
    "validate_rule",
    "validation_report",
    "explain",
    "validate_query",
    "run_query",
    "deploy_rule",
    "deployment_status",
];

/// The root options `mcp start` runs with.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Launch {
    /// The server's working directory.
    pub cwd: Option<PathBuf>,
    /// `--repo`, resolved.
    pub repo: Option<String>,
    /// `--data`, resolved.
    pub data: Option<String>,
    /// `--proxy` (or `OPENTIDE_PROXY`).
    pub proxy: Option<String>,
    /// `--debug` (or `OPENTIDE_DEBUG`).
    pub debug: bool,
}

impl Launch {
    /// The variables the command line's root exports for these
    /// options (`CliContext.apply_environment`), which the tools and the
    /// commands they run read the workspace, the data and the proxy from:
    /// only what an option names, the rest is the process's own.
    pub fn environment(&self) -> Vec<(String, String)> {
        let mut out = Vec::new();
        let mut put = |name: &str, value: &str| out.push((name.to_owned(), value.to_owned()));
        if let Some(repo) = &self.repo {
            put("OPENTIDE_REPO_ROOT", repo);
            put("OPENTIDE_TIDE_WORKSPACE", repo);
        }
        if let Some(data) = &self.data {
            put("OPENTIDE_DATA_ROOT", data);
        }
        if let Some(proxy) = &self.proxy {
            for name in ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"] {
                put(name, proxy);
            }
        }
        if self.debug {
            put("OPENTIDE_DEBUG", "1");
            put("DEBUG_ENABLED", "1");
        }
        out
    }
}

/// Serves MCP on stdio until the client closes stdin; the exit code.
///
/// # Errors
///
/// An I/O error setting up stdio or the runtime.
pub fn serve(launch: &Launch, version: &str) -> std::io::Result<i32> {
    use std::io::Write;
    let environment = launch.environment();
    let process = crate::env::Env::from_process();
    let env = crate::env::Env::from_pairs(
        process
            .iter()
            .filter(|(name, _)| !environment.iter().any(|(set, _)| set == name))
            .chain(
                environment
                    .iter()
                    .map(|(name, value)| (name.as_str(), value.as_str())),
            )
            .map(|(name, value)| (name.to_owned(), value.to_owned()))
            .collect::<Vec<_>>(),
    );
    let cwd = launch
        .cwd
        .clone()
        .or_else(|| std::env::current_dir().ok())
        .unwrap_or_default();
    // Started by an Agent Plugin client, the cwd is the plugin, not the catalogue (#431).
    let (env, workspace_problem) = plugin::served(env, &cwd);
    // WASI only (no sockets): the client makes the tenant requests, over stdio.
    // Natively the variable is ignored: opentide's own HTTP client makes them.
    #[cfg(target_os = "wasi")]
    let bridged = fetch::requested(&env);
    std::io::stdout().flush()?;
    let rpc = stdio::reserve_stdout()?;
    let server = Server::new(
        env,
        launch.cwd.clone(),
        launch.repo.clone(),
        version,
        workspace_problem,
    );
    // The server's tasks run on the process's runtime's threads, not this
    // one: they log to this command's subscriber (`--debug`) as the process
    // default, the server being the process's one command until it exits.
    let _ = tracing::dispatcher::set_global_default(tracing::dispatcher::get_default(Clone::clone));
    #[cfg(not(target_os = "wasi"))]
    // On the process's one runtime (#1558): a tool's network work, on one of
    // its `spawn_blocking` threads, blocks on it there.
    let outcome =
        opentide_connectors::runtime::block_on(server.run(tokio::io::stdin(), rpc.file()?));
    // WASI: tokio has no standard streams and the module no threads, so the
    // client is read with blocking reads, a message at a time, each answered
    // before the next read (`interactive`).
    #[cfg(target_os = "wasi")]
    let outcome = {
        let (jobs, queue) = tokio::sync::mpsc::unbounded_channel();
        let server = server.offloading(jobs);
        if bridged {
            // Tenant requests are lines on the same two streams, so the reader
            // that takes the client's messages is the bridge's.
            // `Stdin` itself, not its lock: the bridge reads inside a tool call.
            let bridge =
                fetch::Bridge::new(std::io::BufReader::new(std::io::stdin()), rpc.writer()?);
            let _fetching = bridge.install();
            offloaded(
                interactive::serve_lines(server, interactive::Bridged(bridge), rpc.writer()?),
                queue,
            )
        } else {
            offloaded(
                interactive::serve(server, std::io::stdin().lock(), rpc.writer()?),
                queue,
            )
        }
    };
    rpc.restore()?;
    outcome.map_err(std::io::Error::other)??;
    Ok(0)
}

/// Drives *session* on the process's runtime and runs the calls' work it hands
/// over (`Server::offloading`) between its polls, outside the runtime.
#[cfg(any(target_os = "wasi", test))]
fn offloaded<F: std::future::Future<Output = std::io::Result<()>>>(
    session: F,
    mut queue: tokio::sync::mpsc::UnboundedReceiver<server::Job>,
) -> Result<std::io::Result<()>, String> {
    enum Step {
        Done(std::io::Result<()>),
        Work(server::Job),
    }
    let mut session = Box::pin(session);
    loop {
        let step = opentide_connectors::runtime::block_on(async {
            tokio::select! {
                outcome = &mut session => Step::Done(outcome),
                Some(work) = queue.recv() => Step::Work(work),
            }
        })?;
        match step {
            Step::Done(outcome) => return Ok(outcome),
            Step::Work(work) => work(),
        }
    }
}

#[cfg(test)]
mod offload_tests {
    use super::{offloaded, server};

    /// The WASI build's tool calls run on the thread that drives the session,
    /// between two polls of it: outside the runtime, where a tenant call may
    /// block on the process's runtime. Run inside the session's own future the
    /// same call is refused.
    #[test]
    fn a_calls_work_runs_outside_the_runtime_that_drives_the_session() {
        let (jobs, queue) = tokio::sync::mpsc::unbounded_channel::<server::Job>();
        let session = async move {
            // Inside the session: refused, as the WASI build's tenant calls were.
            assert_eq!(
                opentide_connectors::runtime::block_on(async { 1 }),
                Err(opentide_connectors::runtime::INSIDE_THE_RUNTIME.to_owned())
            );
            // Handed over: runs outside it, and may block on the runtime.
            let (done, result) = tokio::sync::oneshot::channel();
            let job: server::Job = Box::new(move || {
                let outside = tokio::runtime::Handle::try_current().is_err();
                let blocked = opentide_connectors::runtime::block_on(async { 7 });
                let _sent = done.send((outside, blocked));
            });
            jobs.send(job).unwrap();
            let (outside, blocked) = result.await.unwrap();
            assert!(outside, "the work ran inside a runtime");
            assert_eq!(blocked, Ok(7));
            // And more than one, one after the other.
            for expected in 0..3_u32 {
                let (done, result) = tokio::sync::oneshot::channel();
                let job: server::Job = Box::new(move || {
                    let _sent = done.send(expected);
                });
                jobs.send(job).unwrap();
                assert_eq!(result.await.unwrap(), expected);
            }
            Ok(())
        };
        offloaded(session, queue).unwrap().unwrap();
    }
}

pub(crate) mod stdio {
    //! stdout for JSON-RPC alone.

    #[cfg(not(target_os = "wasi"))]
    use std::fs::File;

    /// The stream the server writes frames to, and what restores descriptor 1.
    pub struct Reserved {
        #[cfg(not(target_os = "wasi"))]
        rpc: File,
        #[cfg(unix)]
        saved: std::os::fd::OwnedFd,
    }

    impl Reserved {
        /// A handle on the frames' stream for the transport.
        #[cfg(not(target_os = "wasi"))]
        pub fn file(&self) -> std::io::Result<tokio::fs::File> {
            Ok(tokio::fs::File::from_std(self.rpc.try_clone()?))
        }

        /// A handle on the frames' stream for a blocking writer (`serve`).
        #[cfg(not(target_os = "wasi"))]
        pub fn writer(&self) -> std::io::Result<File> {
            self.rpc.try_clone()
        }

        /// The frames' stream for a blocking writer (`serve`): stdout itself
        /// under WASI.
        #[cfg(target_os = "wasi")]
        pub fn writer(&self) -> std::io::Result<std::io::Stdout> {
            Ok(std::io::stdout())
        }

        /// Points descriptor 1 back at the stream it was.
        pub fn restore(self) -> std::io::Result<()> {
            #[cfg(unix)]
            rustix::stdio::dup2_stdout(&self.saved)?;
            Ok(())
        }
    }

    /// A duplicate of stdout for the frames; on Unix descriptor 1 then points
    /// at stderr, so whatever else writes to stdout lands there instead.
    #[cfg(unix)]
    pub fn reserve_stdout() -> std::io::Result<Reserved> {
        use std::os::fd::AsFd;
        let stdout = std::io::stdout();
        let saved = stdout.as_fd().try_clone_to_owned()?;
        let rpc = File::from(stdout.as_fd().try_clone_to_owned()?);
        rustix::stdio::dup2_stdout(std::io::stderr().as_fd())?;
        Ok(Reserved { rpc, saved })
    }

    /// A duplicate of stdout for the frames (Windows: the standard handle stays).
    #[cfg(windows)]
    pub fn reserve_stdout() -> std::io::Result<Reserved> {
        use std::os::windows::io::AsHandle;
        let rpc = File::from(std::io::stdout().as_handle().try_clone_to_owned()?);
        Ok(Reserved { rpc })
    }

    /// stdout itself for the frames (WASI: no descriptor can be duplicated or
    /// moved aside, so the commands a server runs write to buffers, never to
    /// stdout).
    #[cfg(target_os = "wasi")]
    pub fn reserve_stdout() -> std::io::Result<Reserved> {
        Ok(Reserved {})
    }
}

/// The server on a blocking reader and writer (WASI: no `io-std`, no threads).
///
/// A blocking read stops the one thread, and with it every task: read inside
/// the transport's `poll_read`, it held the answer to a message until the
/// client sent more input or closed it, so a client waiting for each answer
/// before sending its next request (any interactive one) hung after
/// `initialize`. Here the client is read a line (one JSON-RPC message) at a
/// time outside the transport, which gets each line through an in-memory
/// pipe; after a request the next read waits until its answer is written, so
/// a read blocks only when nothing the client sent is still unanswered.
#[cfg(any(target_os = "wasi", test))]
pub(crate) mod interactive {
    use std::io::{BufRead, Write};
    use std::pin::Pin;
    use std::sync::{Arc, Mutex, PoisonError};
    use std::task::{Context, Poll};

    use rmcp::model::NumberOrString;
    use serde_json::Value;
    use tokio::io::{AsyncWrite, AsyncWriteExt};
    use tokio::sync::Notify;

    use super::Server;

    /// Where the client's lines come from.
    pub trait Lines {
        /// The next line, its newline included or not; `None` at the end of
        /// input.
        ///
        /// # Errors
        ///
        /// An I/O error reading.
        fn next_line(&mut self, line: &mut Vec<u8>) -> std::io::Result<bool>;

        /// The request the server hands over next (`None` for a notification
        /// or an answer).
        fn begin(&mut self, _id: Option<&NumberOrString>) {}
    }

    /// A reader as the client's lines.
    struct Reader<R>(R);

    impl<R: BufRead> Lines for Reader<R> {
        fn next_line(&mut self, line: &mut Vec<u8>) -> std::io::Result<bool> {
            Ok(self.0.read_until(b'\n', line)? != 0)
        }
    }

    /// The client's lines from a bridge that also carries its answers to the
    /// server's tenant requests (`OPENTIDE_FETCH=stdio`).
    pub struct Bridged(pub std::sync::Arc<super::fetch::Bridge>);

    impl Lines for Bridged {
        fn next_line(&mut self, line: &mut Vec<u8>) -> std::io::Result<bool> {
            match self.0.next_line() {
                Some(next) => {
                    line.extend_from_slice(&next);
                    Ok(true)
                }
                None => Ok(false),
            }
        }

        fn begin(&mut self, id: Option<&NumberOrString>) {
            self.0.begin(id.cloned());
        }
    }

    /// Room for the pipe's unread bytes; a longer message waits for the
    /// transport to read the first part, as it does on a real pipe.
    const PIPE: usize = 64 * 1024;

    /// What the writer has written since the reader last handed a request
    /// over (one is in flight at a time), and whether the session ended.
    #[derive(Default)]
    struct Seen {
        state: Mutex<State>,
        changed: Notify,
    }

    #[derive(Default)]
    struct State {
        /// The ids answered, as rmcp reads them (`1.0` is `1`).
        answered: Vec<NumberOrString>,
        /// An answer without an id: a request rmcp could not read as one (an id
        /// out of range, bad params) is refused so, never by its id.
        refused: bool,
        /// A request to the client: its answer is the client's next message.
        asked: bool,
        ended: bool,
    }

    impl Seen {
        fn update(&self, change: impl FnOnce(&mut State)) {
            change(&mut self.state.lock().unwrap_or_else(PoisonError::into_inner));
            self.changed.notify_one();
        }

        fn ended(&self) -> bool {
            self.state
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .ended
        }

        /// Forgets what was written for the requests before this one.
        fn expect(&self) {
            let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            state.answered.clear();
            state.refused = false;
            state.asked = false;
        }

        /// Until *id* is answered, refused, the server asks the client
        /// something, or the session ends.
        async fn settled(&self, id: &NumberOrString) {
            loop {
                {
                    let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
                    if state.answered.contains(id) || state.refused || state.asked || state.ended {
                        return;
                    }
                }
                self.changed.notified().await;
            }
        }
    }

    /// A UTF-8 byte-order mark, which rmcp's transport skips.
    const BOM: &[u8] = b"\xEF\xBB\xBF";

    /// The id of a request rmcp answers by its id: a method that is not a
    /// notification's, and an id it reads (an integer, also in float form, or
    /// a string). Anything else is answered without an id, or not at all.
    fn request_id(line: &[u8]) -> Option<NumberOrString> {
        let message: Value = serde_json::from_slice(line.strip_prefix(BOM).unwrap_or(line)).ok()?;
        let method = message.get("method")?.as_str()?;
        if method.starts_with("notifications/") {
            return None;
        }
        serde_json::from_value(message.get("id")?.clone()).ok()
    }

    /// Serves *server* until *input* ends.
    ///
    /// # Errors
    ///
    /// An I/O error reading *input* or writing *output*.
    pub async fn serve<R, W>(server: Server, input: R, output: W) -> std::io::Result<()>
    where
        R: BufRead,
        W: Write + Send + Unpin + 'static,
    {
        serve_lines(server, Reader(input), output).await
    }

    /// Serves *server* until *input* ends.
    ///
    /// # Errors
    ///
    /// An I/O error reading *input* or writing *output*.
    pub async fn serve_lines<L, W>(server: Server, mut input: L, output: W) -> std::io::Result<()>
    where
        L: Lines,
        W: Write + Send + Unpin + 'static,
    {
        let seen = Arc::new(Seen::default());
        let (mut feed, transport) = tokio::io::duplex(PIPE);
        let writer = Output {
            inner: output,
            line: Vec::new(),
            seen: Arc::clone(&seen),
        };
        let session = async {
            let outcome = server.run(transport, writer).await;
            seen.update(|state| state.ended = true);
            outcome
        };
        let reader = async {
            let mut line = Vec::new();
            // Once the session ends, nothing more is read: the process exits
            // as the native one does, without waiting for the client.
            while !seen.ended() {
                line.clear();
                // Blocks every task: whatever the client sent is answered.
                if !input.next_line(&mut line)? {
                    break;
                }
                // A last message without its newline is framed now: the
                // transport would add it only once the pipe ends, after this
                // message's answer, which it would never write.
                if line.last() != Some(&b'\n') {
                    line.push(b'\n');
                }
                let id = request_id(&line);
                input.begin(id.as_ref());
                seen.expect();
                if feed.write_all(&line).await.is_err() {
                    break; // the session ended: nothing reads the pipe
                }
                match id {
                    Some(id) => seen.settled(&id).await,
                    // A notification or an answer: let the session take it in.
                    None => {
                        for _ in 0..16 {
                            tokio::task::yield_now().await;
                        }
                    }
                }
            }
            drop(feed); // end of input
            Ok::<_, std::io::Error>(())
        };
        let (outcome, input_read) = tokio::join!(session, reader);
        input_read?;
        outcome
    }

    /// The frames' writer: writes through, and notes each answer and each
    /// request the server sends.
    struct Output<W> {
        inner: W,
        line: Vec<u8>,
        seen: Arc<Seen>,
    }

    impl<W> Output<W> {
        fn note(&mut self, data: &[u8]) {
            self.line.extend_from_slice(data);
            while let Some(end) = self.line.iter().position(|&byte| byte == b'\n') {
                let frame: Vec<u8> = self.line.drain(..=end).collect();
                let Ok(message) = serde_json::from_slice::<Value>(&frame) else {
                    continue;
                };
                let id = message.get("id");
                if message.get("method").is_some() {
                    if id.is_some() {
                        self.seen.update(|state| state.asked = true);
                    }
                    continue;
                }
                // An answer: by an id rmcp reads, or a refusal with none (rmcp
                // leaves the key out) that stands for the request in flight.
                match id.and_then(|id| serde_json::from_value::<NumberOrString>(id.clone()).ok()) {
                    Some(id) => self.seen.update(|state| state.answered.push(id)),
                    None => self.seen.update(|state| state.refused = true),
                }
            }
        }
    }

    impl<W: Write + Unpin> AsyncWrite for Output<W> {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            data: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            let this = self.get_mut();
            let written = this.inner.write(data)?;
            this.note(&data[..written]);
            Poll::Ready(Ok(written))
        }

        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(self.get_mut().inner.flush())
        }

        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(self.get_mut().inner.flush())
        }
    }
}
