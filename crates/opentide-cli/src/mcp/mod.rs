//! `opentide mcp start` (UC-3.7, #829; UC-6.0c, #841): the MCP server on
//! rmcp, the official Rust MCP SDK, over stdio.
//!
//! What the server says of itself (its name, instructions, capabilities, the
//! protocol version it falls back to, every tool's description and schemas,
//! every resource and template) is the Python server's
//! (`src/opentide/mcp_server/server.py`), as `scripts/build/mcp_manifest.py`
//! wrote it to `data/mcp/manifest.json`: MCP shapes are a plan §3 invariant.
//!
//! Every tool ([`TOOLS`]) and every resource runs here, on the workspace
//! crates, and answers as the Python server's handlers do
//! (`tests/golden/mcp/`, `cargo xtask mcp replay`): no Python is needed.
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
mod plugin;
mod queries;
mod resources;
mod server;
#[cfg(test)]
mod tests;
mod tools;

use std::path::PathBuf;

pub use server::Server;

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
    std::io::stdout().flush()?;
    let rpc = stdio::reserve_stdout()?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let server = Server::new(
        env,
        launch.cwd.clone(),
        launch.repo.clone(),
        version,
        workspace_problem,
    );
    #[cfg(not(target_os = "wasi"))]
    let outcome = runtime.block_on(server.run(tokio::io::stdin(), rpc.file()?));
    // WASI: tokio has no standard streams and the module no threads, so the
    // client is read with blocking reads, a message at a time, each answered
    // before the next read (`interactive`).
    #[cfg(target_os = "wasi")]
    let outcome = runtime.block_on(interactive::serve(
        server,
        std::io::stdin().lock(),
        rpc.writer()?,
    ));
    rpc.restore()?;
    outcome?;
    Ok(0)
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

    use serde_json::Value;
    use tokio::io::{AsyncWrite, AsyncWriteExt};
    use tokio::sync::Notify;

    use super::Server;

    /// Room for the pipe's unread bytes; a longer message waits for the
    /// transport to read the first part, as it does on a real pipe.
    const PIPE: usize = 64 * 1024;

    /// What the writer has seen: the ids answered, whether the server asked
    /// the client something, whether the session ended.
    #[derive(Default)]
    struct Seen {
        state: Mutex<State>,
        changed: Notify,
    }

    #[derive(Default)]
    struct State {
        answered: Vec<Value>,
        asked: bool,
        ended: bool,
    }

    impl Seen {
        fn update(&self, change: impl FnOnce(&mut State)) {
            change(&mut self.state.lock().unwrap_or_else(PoisonError::into_inner));
            self.changed.notify_one();
        }

        /// Until *id* is answered, the server asks the client something (its
        /// answer is the client's next message), or the session ends.
        async fn settled(&self, id: &Value) {
            loop {
                {
                    let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
                    if let Some(at) = state.answered.iter().position(|answered| answered == id) {
                        state.answered.swap_remove(at);
                        return;
                    }
                    if state.asked || state.ended {
                        state.asked = false;
                        return;
                    }
                }
                self.changed.notified().await;
            }
        }
    }

    /// The id of a request (a message with a method and an id), whose answer
    /// the client may wait for before it writes again.
    fn request_id(line: &[u8]) -> Option<Value> {
        let message: Value = serde_json::from_slice(line).ok()?;
        message.get("method")?;
        message.get("id").cloned()
    }

    /// Serves *server* until *input* ends.
    ///
    /// # Errors
    ///
    /// An I/O error reading *input* or writing *output*.
    pub async fn serve<R, W>(server: Server, mut input: R, output: W) -> std::io::Result<()>
    where
        R: BufRead,
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
            loop {
                line.clear();
                // Blocks every task: whatever the client sent is answered.
                if input.read_until(b'\n', &mut line)? == 0 {
                    break;
                }
                if feed.write_all(&line).await.is_err() {
                    break; // the session ended: nothing reads the pipe
                }
                match request_id(&line) {
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
        let (served, read) = tokio::join!(session, reader);
        read?;
        served
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
                let id = message.get("id").cloned();
                if message.get("method").is_some() {
                    if id.is_some() {
                        self.seen.update(|state| state.asked = true);
                    }
                } else if let Some(id) = id {
                    self.seen.update(|state| state.answered.push(id));
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
