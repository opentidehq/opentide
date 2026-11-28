//! The opentide language server as a library, for hosts that run it in their
//! own process. The command line (`opentide-cli`) serves it as `opentide lsp
//! start`, in the binary and the Python and npm launchers alike; the
//! `opentide-lsp` binary is the other host.
//!
//! [`run_stdio`] speaks LSP on the process's stdin and stdout until the client
//! sends `exit` or closes stdin. Nothing else may write to stdout meanwhile.
//! [`MessageSession`] is the same server for a host with no stdio (the
//! browser build, `opentide-wasm`): one JSON-RPC message in, its replies out.
//!
//! Internal to opentide, with no stability promise: depend on the
//! [`opentide`](https://docs.rs/opentide) crate, its Rust SDK, instead (its
//! `lsp` feature).

// Slicing a `str` by byte index panics off a char boundary, and this crate
// reads editors' documents: every slice is checked or says why it is safe
// (#1946; the lint moves to `[workspace.lints]` once every crate is clean).
#![warn(clippy::string_slice)]

mod checks;
mod handlers;
mod index;
mod models;
mod protocol;
pub mod server;
mod session;
#[cfg(target_os = "wasi")]
mod stdin;
mod timing;
pub mod uri;

pub use handlers::{DIAGNOSTICS_DOCS, SHOW_REFERENCES};
pub use server::{
    MessageSession, ObjectFindings, host_info, run_listen, run_stdio, run_stdio_status, serve,
    serve_with_status, set_host_info, use_host_catalogs,
};

/// The server's version: the one every `opentide-*` build reports
/// ([`opentide_core::VERSION`]): the crate version, or the release
/// candidate's when the build sets `OPENTIDE_BUILD_VERSION`.
pub const VERSION: &str = opentide_core::VERSION;

/// `text[start..end]`, a range the server computes or the engines give it:
/// an offset from a position (`position_to_offset` returns char bounds), or
/// a span's bound. A range that is not fails a debug assertion and reads as
/// empty.
pub(crate) fn cut(text: &str, start: usize, end: usize) -> &str {
    let piece = text.get(start..end);
    debug_assert!(piece.is_some(), "{start}..{end} in {} bytes", text.len());
    piece.unwrap_or_default()
}
