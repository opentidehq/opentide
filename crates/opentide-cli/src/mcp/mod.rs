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
    /// The variables the Python CLI's root callback exports for these
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
    // WASI: tokio has no standard streams there; blocking ones serve, as
    // nothing else runs on the current-thread runtime meanwhile.
    #[cfg(target_os = "wasi")]
    let outcome = runtime.block_on(server.run(
        blocking::Input(std::io::stdin()),
        blocking::Output(rpc.writer()?),
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

/// The standard streams as tokio's async traits, each call blocking (WASI,
/// where tokio has no `io-std`): the MCP server runs alone on a
/// current-thread runtime, so blocking it waits for the client and nothing
/// else.
#[cfg(target_os = "wasi")]
mod blocking {
    use std::io::{Read, Write};
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    /// A blocking reader as an [`AsyncRead`].
    pub struct Input<R>(pub R);

    impl<R: Read + Unpin> AsyncRead for Input<R> {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            let this = self.get_mut();
            let read = this.0.read(buf.initialize_unfilled())?;
            buf.advance(read);
            Poll::Ready(Ok(()))
        }
    }

    /// A blocking writer as an [`AsyncWrite`].
    pub struct Output<W>(pub W);

    impl<W: Write + Unpin> AsyncWrite for Output<W> {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            data: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Poll::Ready(self.get_mut().0.write(data))
        }

        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(self.get_mut().0.flush())
        }

        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(self.get_mut().0.flush())
        }
    }
}
