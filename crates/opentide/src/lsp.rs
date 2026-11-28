//! The language server (`lsp` feature): Tide YAML, the configuration TOML and
//! the query languages, with the findings of `validate` (`opentide lsp
//! start` and the `opentide-lsp` binary run the same server).

use std::io::{BufRead, Write};

use crate::Error;

/// The server's version: the engine crates' lockstep version.
pub const VERSION: &str = opentide_lsp::VERSION;

/// Serves one client on the process's stdin and stdout until it sends
/// `exit` or closes stdin. Nothing else may write to stdout meanwhile.
/// Returns whether the client shut the server down first: the process exits
/// with 0 if so and 1 if not, as LSP asks.
///
/// # Errors
///
/// [`Error::Lsp`] when the transport fails.
pub fn run_stdio() -> Result<bool, Error> {
    opentide_lsp::run_stdio_status().map_err(lsp_error)
}

/// Serves one client over `reader` and `writer` (LSP frames with their
/// `Content-Length` headers) until it sends `exit` or the input ends.
/// Returns whether the client shut the server down first.
///
/// # Errors
///
/// [`Error::Lsp`] when reading or writing a frame fails.
pub fn serve(reader: impl BufRead, writer: impl Write) -> Result<bool, Error> {
    opentide_lsp::serve_with_status(reader, writer).map_err(lsp_error)
}

/// The server driven one JSON-RPC message at a time, for a host with no
/// streams to give it (a browser worker): [`MessageSession::handle`] takes a
/// message's JSON text and returns what the server sends back.
///
/// ```
/// let mut server = opentide::lsp::MessageSession::new();
/// let replies = server.handle(r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"capabilities":{}}}"#);
/// assert!(replies[0].contains("\"capabilities\""));
/// ```
#[derive(Default)]
pub struct MessageSession {
    inner: opentide_lsp::MessageSession,
}

impl MessageSession {
    /// A session before `initialize`, the first message it expects.
    pub fn new() -> Self {
        Self::default()
    }

    /// Handles one message (its JSON text, without the `Content-Length`
    /// header) and returns the messages the server sends back, in order: the
    /// response, the notifications it publishes and the requests it makes of
    /// the client. Text that is not a JSON-RPC message is answered with an
    /// error (-32700 or -32600). After `exit` it handles nothing more.
    pub fn handle(&mut self, message: &str) -> Vec<String> {
        self.inner.handle(message)
    }

    /// Whether the client has sent `exit`.
    pub fn is_closed(&self) -> bool {
        self.inner.is_closed()
    }

    /// Whether the client shut the server down before it sent `exit`.
    pub fn shut_down(&self) -> bool {
        self.inner.shut_down()
    }
}

impl std::fmt::Debug for MessageSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MessageSession")
            .field("closed", &self.is_closed())
            .finish_non_exhaustive()
    }
}

fn lsp_error(error: impl std::fmt::Display) -> Error {
    Error::Lsp {
        message: error.to_string(),
    }
}
