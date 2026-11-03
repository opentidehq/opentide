//! The opentide language server as a library, for hosts that run it in their
//! own process. The `opentide` Python package serves it as `opentide lsp start`
//! through its bindings; the `opentide-lsp` binary is the other host.
//!
//! [`run_stdio`] speaks LSP on the process's stdin and stdout until the client
//! sends `exit` or closes stdin. Nothing else may write to stdout meanwhile.

mod handlers;
mod protocol;
pub mod server;
mod session;
pub mod uri;

pub use handlers::{DIAGNOSTICS_DOCS, SHOW_REFERENCES};
pub use server::{
    WORKSPACE_CATALOGS, host_info, run_listen, run_stdio, run_stdio_status, serve,
    serve_with_status, set_host_info, use_host_catalogs,
};

/// The server's version: the crate version every `opentide-*` crate shares.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
