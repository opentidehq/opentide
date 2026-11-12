//! `opentide serve`'s Rust host (UC-3.8, #830) and its Python side.
//!
//! The host is `opentide_cli::serve`: the JSON-RPC loop, and the runs of the
//! commands with a Rust implementation. What it hands to Python is a
//! `opentide.cli.services.serve_bridge.Bridge` in this process: which
//! implementation runs a request (the engine selection is the Python
//! package's until every command is ported), and the run of each command
//! that has none, as the Python host ran it. [`BridgeFactory`] starts one for
//! `opentide serve` (`cli_main`); [`ServeHost`] drives the host from Python
//! with a bridge the caller made (the in-process tests, an embedding host).
//!
//! The GIL is never held while a lock of the host is taken: every call into
//! the host releases it first, and the callbacks Python makes into the host
//! (a run's progress events, its end) release it before they reach it.

use std::path::PathBuf;
use std::sync::Arc;

use opentide_cli::serve::{
    Delegate, DelegateFactory, EventSink, HostRunner, Plan, RunRequest, RustRun, Server, Writer,
};
use pyo3::exceptions::PyKeyboardInterrupt;
use pyo3::prelude::*;
use pyo3::types::{PyCFunction, PyDict, PyTuple};

/// A `Bridge` object, as the host's [`Delegate`].
struct PyDelegate {
    bridge: Py<PyAny>,
}

/// A run's `argv`, `cwd` and `env`, as the bridge takes them.
type Arguments<'py> = (Vec<String>, Option<String>, Option<Bound<'py, PyDict>>);

/// `request`'s `argv`, `cwd` and `env` as the bridge takes them.
fn arguments<'py>(py: Python<'py>, request: &RunRequest) -> PyResult<Arguments<'py>> {
    let env = match &request.env {
        None => None,
        Some(pairs) => {
            let env = PyDict::new(py);
            for (name, value) in pairs {
                env.set_item(name, value)?;
            }
            Some(env)
        }
    };
    Ok((request.argv.clone(), request.cwd.clone(), env))
}

/// A `dict[str, str]` as its pairs, in order.
fn pairs(dict: &Bound<'_, PyAny>) -> PyResult<Vec<(String, String)>> {
    dict.cast::<PyDict>()?
        .iter()
        .map(|(name, value)| Ok((name.extract()?, value.extract()?)))
        .collect()
}

impl Delegate for PyDelegate {
    fn plan(&self, request: &RunRequest) -> Result<Plan, String> {
        Python::attach(|py| -> PyResult<Plan> {
            let answer = self
                .bridge
                .bind(py)
                .call_method1("plan", arguments(py, request)?)?;
            let rust = answer.get_item("rust")?;
            let rust = if rust.is_none() {
                None
            } else {
                Some(RustRun {
                    env: pairs(&rust.get_item("env")?)?,
                    cwd: rust.get_item("cwd")?.extract()?,
                })
            };
            Ok(Plan {
                words: answer.get_item("words")?.extract()?,
                refused: answer.get_item("refused")?.extract()?,
                keep: answer.get_item("keep")?.extract()?,
                rust,
            })
        })
        .map_err(|error| error.to_string())
    }

    fn run(
        &self,
        request: &RunRequest,
        event: EventSink,
        finished: Arc<dyn Fn() + Send + Sync>,
    ) -> Result<String, String> {
        Python::attach(|py| -> PyResult<String> {
            let on_event = PyCFunction::new_closure(
                py,
                None,
                None,
                move |args: &Bound<'_, PyTuple>, _: Option<&Bound<'_, PyDict>>| -> PyResult<()> {
                    let text: String = args.get_item(0)?.extract()?;
                    let event = Arc::clone(&event);
                    args.py().detach(move || event(text));
                    Ok(())
                },
            )?;
            let on_finished = PyCFunction::new_closure(
                py,
                None,
                None,
                move |args: &Bound<'_, PyTuple>, _: Option<&Bound<'_, PyDict>>| -> PyResult<()> {
                    let finished = Arc::clone(&finished);
                    args.py().detach(move || finished());
                    Ok(())
                },
            )?;
            let (argv, cwd, env) = arguments(py, request)?;
            self.bridge
                .bind(py)
                .call_method1("run", (argv, cwd, env, on_event, on_finished))?
                .extract()
        })
        .map_err(|error| error.to_string())
    }

    fn interrupt(&self) {
        let interrupted =
            Python::attach(|py| self.bridge.bind(py).call_method0("interrupt").map(drop));
        if let Err(error) = interrupted {
            tracing::error!(problem = %error, "serve: the Python run could not be interrupted");
        }
    }

    fn invalidate(&self, paths: &[String]) {
        let done = Python::attach(|py| {
            self.bridge
                .bind(py)
                .call_method1("invalidate", (paths.to_vec(),))
                .map(drop)
        });
        if let Err(error) = done {
            tracing::error!(problem = %error, "serve: the Python side could not invalidate");
        }
    }

    fn forget(&self) {
        let done = Python::attach(|py| self.bridge.bind(py).call_method0("forget").map(drop));
        if let Err(error) = done {
            tracing::error!(problem = %error, "serve: the Python side could not forget");
        }
    }
}

/// Starts `opentide.cli.services.serve_bridge`'s `Bridge` for `opentide serve`.
pub struct BridgeFactory;

impl DelegateFactory for BridgeFactory {
    fn start(&self, base_env: &[(String, String)], cwd: &str) -> Result<Arc<dyn Delegate>, String> {
        Python::attach(|py| -> PyResult<Arc<dyn Delegate>> {
            let env = PyDict::new(py);
            for (name, value) in base_env {
                env.set_item(name, value)?;
            }
            let bridge = py
                .import("opentide.cli.services.serve_bridge")?
                .call_method1("start", (env, cwd))?;
            Ok(Arc::new(PyDelegate {
                bridge: bridge.unbind(),
            }))
        })
        .map_err(|error| error.to_string())
    }
}

/// The Rust host of `opentide serve`, driven from Python: `write` takes each
/// message (one JSON line, without its newline), `bridge` is the Python side.
#[pyclass(frozen, module = "opentide._native")]
pub struct ServeHost {
    server: Server,
}

#[pymethods]
impl ServeHost {
    #[new]
    fn new(write: Py<PyAny>, bridge: Py<PyAny>, version: &str) -> ServeHost {
        let writer: Writer = Box::new(move |line: &str| {
            Python::attach(|py| write.call1(py, (line,)).map(drop))
                .map_err(|error| std::io::Error::other(error.to_string()))
        });
        let delegate: Arc<dyn Delegate> = Arc::new(PyDelegate { bridge });
        let runner = HostRunner::new(Vec::new(), PathBuf::new(), version, Some(delegate));
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
