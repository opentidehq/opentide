//! `opentide mcp start` (UC-3.7, #829): the MCP server on rmcp, the official
//! Rust MCP SDK, over stdio.
//!
//! What the server says of itself (its name, instructions, capabilities, the
//! protocol version it falls back to, every tool's description and schemas,
//! every resource and template) is the Python server's
//! (`src/opentide/mcp_server/server.py`), as `scripts/build/mcp_manifest.py`
//! writes it to `data/mcp/manifest.json`: MCP shapes are a plan §3 invariant,
//! and the Python server stays the oracle until it is deleted.
//!
//! Tools run in this process. Those in [`NATIVE_TOOLS`] run here, on the
//! workspace crates; the others, and every resource, are answered by the
//! Python server's own handlers through the [`Delegate`] the host installs
//! (`opentide._native` installs `opentide.mcp_server.bridge`), until their
//! Rust implementation exists: search, coverage, get_chaining, the resources
//! and the SDK registry objects are UC-5.2's (#837), the tools that reach a
//! tenant UC-4.x's. Without a delegate (the standalone binary), a delegated
//! tool or resource answers with an error that says so.
//!
//! stdout carries JSON-RPC alone: the server writes its frames to a duplicate
//! of descriptor 1, and descriptor 1 itself points at stderr while it serves
//! (Unix), so nothing else in the process (a log line, the Python half, a
//! child process) can corrupt a frame. Logging is the run's: WARNING and above
//! on stderr, everything with `--debug`.

mod server;
mod tools;

use std::path::PathBuf;
use std::sync::OnceLock;

pub use server::Server;

/// The tools that run in Rust; every other tool is the [`Delegate`]'s.
pub const NATIVE_TOOLS: &[&str] = &["explain", "validation_report"];

/// The tools handed to the [`Delegate`], each with the work item that ports it.
pub const DELEGATED_TOOLS: &[(&str, &str)] = &[
    (
        "search",
        "UC-5.2 (#837): the SDK registry's catalogue search",
    ),
    (
        "get_chaining",
        "UC-5.2 (#837): the SDK registry's chaining graph",
    ),
    (
        "coverage",
        "UC-5.2 (#837): the SDK registry's ATT&CK coverage",
    ),
    (
        "validate_rule",
        "UC-5.2 (#837): the rule lookup and its deployment next steps read the SDK registry",
    ),
    (
        "validate_query",
        "UC-4.x: `live` validates on the tenant; offline it stays with it for one answer",
    ),
    ("run_query", "UC-4.x: runs a query on a tenant"),
    (
        "deploy_rule",
        "UC-4.x: deploys to a tenant (dry_run previews it)",
    ),
    (
        "deployment_status",
        "UC-5.2 (#837): reads the rule from the SDK registry",
    ),
];

/// What the host of the Rust server (the Python package) answers for it.
pub trait Delegate: Send + Sync {
    /// The Python server's start-up, before anything is answered: its output
    /// mode, the Agent Plugin launch (which may name the workspace through
    /// the environment), its logging.
    ///
    /// # Errors
    ///
    /// Why the host could not start.
    fn start(&self) -> Result<(), String>;

    /// Why there is no workspace to serve (`workspace_not_found`), or `None`.
    fn workspace_problem(&self) -> Option<String>;

    /// `tools/call` of `name` with `arguments` (a JSON object, as text): the
    /// JSON text of `{"result": ...}` or `{"error": {...}}`.
    ///
    /// # Errors
    ///
    /// Why the host could not answer at all.
    fn call_tool(&self, name: &str, arguments: &str) -> Result<String, String>;

    /// `resources/read` of `uri`, answered as [`Delegate::call_tool`] is.
    ///
    /// # Errors
    ///
    /// Why the host could not answer at all.
    fn read_resource(&self, uri: &str) -> Result<String, String>;
}

static DELEGATE: OnceLock<Box<dyn Delegate>> = OnceLock::new();

/// Installs the host's [`Delegate`]; a second call keeps the first.
pub fn set_delegate(delegate: Box<dyn Delegate>) {
    let _ignored = DELEGATE.set(delegate);
}

fn delegate() -> Option<&'static dyn Delegate> {
    DELEGATE.get().map(AsRef::as_ref)
}

/// Serves MCP on stdio until the client closes stdin; the exit code. `repo`
/// is `--repo`, resolved.
///
/// # Errors
///
/// An I/O error setting up stdio or the runtime.
pub fn serve(cwd: Option<PathBuf>, repo: Option<String>, version: &str) -> std::io::Result<i32> {
    use std::io::Write;
    if let Some(delegate) = delegate()
        && let Err(problem) = delegate.start()
    {
        tracing::error!(problem = %problem, "the MCP server's Python half did not start");
        return Ok(1);
    }
    // The Python half may have named the workspace (an Agent Plugin launch).
    let env = crate::env::Env::from_process();
    std::io::stdout().flush()?;
    let rpc = stdio::reserve_stdout()?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let server = Server::new(env, cwd, repo, version, delegate());
    let outcome = runtime.block_on(server.run(rpc.file()?));
    rpc.restore()?;
    outcome?;
    Ok(0)
}

mod stdio {
    //! stdout for JSON-RPC alone.

    use std::fs::File;

    /// The stream the server writes frames to, and what restores descriptor 1.
    pub struct Reserved {
        rpc: File,
        #[cfg(unix)]
        saved: std::os::fd::OwnedFd,
    }

    impl Reserved {
        /// A handle on the frames' stream for the transport.
        pub fn file(&self) -> std::io::Result<tokio::fs::File> {
            Ok(tokio::fs::File::from_std(self.rpc.try_clone()?))
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
}
