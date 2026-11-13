//! `opentide serve`'s Rust host (UC-3.8, #830), driven from Python.
//!
//! The host is `opentide_cli::serve`: the JSON-RPC loop and the runs, every
//! one on Rust in this process (UC-6.0d, #841: no Python side chooses an
//! engine or runs a request). `opentide serve` starts it from `cli_main`;
//! [`ServeHost`] drives it from Python (the in-process tests, an embedding
//! host).
//!
//! The GIL is never held while a lock of the host is taken: every call into
//! the host releases it first, and the writer attaches only to hand Python
//! a line.

use std::path::PathBuf;
use std::sync::Arc;

use opentide_cli::serve::{HostRunner, Server, Writer};
use pyo3::exceptions::PyKeyboardInterrupt;
use pyo3::prelude::*;

/// The Rust host of `opentide serve`, driven from Python: `write` takes each
/// message (one JSON line, without its newline); each run starts from `env`
/// (the server's environment, in order) and `cwd`.
#[pyclass(frozen, module = "opentide._native")]
pub struct ServeHost {
    server: Server,
}

#[pymethods]
impl ServeHost {
    #[new]
    fn new(write: Py<PyAny>, version: &str, env: Vec<(String, String)>, cwd: PathBuf) -> ServeHost {
        let writer: Writer = Box::new(move |line: &str| {
            Python::attach(|py| write.call1(py, (line,)).map(drop))
                .map_err(|error| std::io::Error::other(error.to_string()))
        });
        let runner = HostRunner::new(env, cwd, version);
        ServeHost {
            server: Server::new(writer, Arc::new(runner), version),
        }
    }

    /// Takes one line from the client, as the reading thread does.
    fn receive(&self, py: Python<'_>, line: Vec<u8>) {
        py.detach(|| self.server.receive(&line));
    }

    /// The client closed its input: as `exit`.
    fn close_input(&self, py: Python<'_>) {
        py.detach(|| self.server.close_input());
    }

    /// Handles the queued messages until `exit` or the end of input; 0.
    /// Ctrl-C on the main thread closes the server and raises
    /// `KeyboardInterrupt`.
    fn serve(&self, py: Python<'_>) -> PyResult<i32> {
        let ended = py.detach(|| {
            self.server
                .serve(&|| Python::attach(|py| py.check_signals().is_err()))
        });
        if ended {
            Ok(0)
        } else {
            Err(PyKeyboardInterrupt::new_err(()))
        }
    }

    /// How many queued runs a cancel named that have not been reached.
    fn pending_cancels(&self) -> usize {
        self.server.pending_cancels()
    }
}
