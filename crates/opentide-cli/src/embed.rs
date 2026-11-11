//! What a host that runs opentide in its own process calls (UC-2.7, #822):
//! the Python package's `serve`, SDK and MCP server, through
//! `opentide._native`.
//!
//! - [`run_captured`]: one run of the command line with its own
//!   environment, working directory and captured streams, as `serve` runs a
//!   request; `warm` keeps its workspace for the next read-only run
//!   ([`opentide_workspace::session`]).
//! - [`interrupt`]: `serve`'s `$/cancelRequest` for the run in progress, as
//!   Ctrl-C is for a terminal's.
//! - [`validate_json`]: `validate`'s report, checks and summary as JSON, for
//!   the SDK's `run_validation` and the MCP validation tools.

use std::io::Write;
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};

use opentide_workspace::validate::{Check, Options, QueriesMode, Selection};
use serde_json::json;

use crate::app::{Host, Interrupt};
use crate::env::Env;
use crate::logging::Sink;
use crate::queries::EngineQueries;

/// The process's warm workspaces ([`opentide_workspace::session`]): `serve`'s
/// `invalidate`, the reset after a run that may have written, and the counts.
pub use opentide_workspace::session::{
    SessionStats, clear as clear_workspaces, invalidate as invalidate_workspaces,
    stats as workspace_stats,
};

/// What a captured run did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Captured {
    /// The exit code.
    pub exit_code: i32,
    /// Everything it wrote on stdout.
    pub stdout: Vec<u8>,
    /// Everything it wrote on stderr, log lines included, in order.
    pub stderr: Vec<u8>,
}

/// The interrupt of the captured run in progress, if any.
static CURRENT: Mutex<Option<Interrupt>> = Mutex::new(None);

/// stderr of a captured run: the buffer its log lines go to as well.
struct Shared(Arc<Mutex<Vec<u8>>>);

impl Write for Shared {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Runs `opentide` with `argv` (without the program name), in `env` and from
/// `cwd`, as a process with its streams on pipes would: neither stream is a
/// terminal. `warm`: a workspace the run opens on the disk comes from, and
/// stays in, the process's session ([`opentide_workspace::session`]); only
/// for a run that writes no workspace file.
pub fn run_captured(argv: &[String], env: &Env, cwd: &Path, version: &str, warm: bool) -> Captured {
    let interrupt = Interrupt::default();
    *CURRENT.lock().unwrap_or_else(PoisonError::into_inner) = Some(interrupt.clone());
    let stderr = Arc::new(Mutex::new(Vec::new()));
    let sink: Sink = Arc::new(Mutex::new(Shared(Arc::clone(&stderr))));
    let host = Host {
        version: version.to_owned(),
        stdout_tty: false,
        stderr_tty: false,
        log_sink: sink,
        cwd: Some(cwd.to_path_buf()),
        width: None,
        interrupt,
    };
    let mut out = Vec::new();
    let mut err = Shared(Arc::clone(&stderr));
    let exit_code = {
        let _active = warm.then(opentide_workspace::session::activate);
        crate::app::run(argv, env, &host, &mut out, &mut err)
    };
    *CURRENT.lock().unwrap_or_else(PoisonError::into_inner) = None;
    let stderr = std::mem::take(&mut *stderr.lock().unwrap_or_else(PoisonError::into_inner));
    Captured {
        exit_code,
        stdout: out,
        stderr,
    }
}

/// Interrupts the captured run in progress, as a first Ctrl-C does: it
/// stops, prints `error: interrupted` and exits 130. Whether one was running.
pub fn interrupt() -> bool {
    CURRENT
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .as_ref()
        .map(Interrupt::request)
        .is_some()
}

/// What a `validate` run reads, as `--repo`, `--check`, `--file`, `--uuid`,
/// `--type`, `--queries` and `--strict` give it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ValidateRequest {
    /// `--repo`.
    pub repo: Option<String>,
    /// `--check`: one check, else the defaults.
    pub check: Option<String>,
    /// `--file`.
    pub files: Vec<String>,
    /// `--uuid`.
    pub uuids: Vec<String>,
    /// `--type`.
    pub types: Vec<String>,
    /// `--queries`: `error`, `warn` or `off`.
    pub queries: String,
    /// `--strict`.
    pub strict: bool,
}

/// `validate`'s result as JSON text: `{"report", "checks", "summary", "failed"}`,
/// the report as `validate --json` writes it; or `{"error": {"code",
/// "message"}}` when the request names no check or mode this CLI has, or
/// the workspace's configuration does not resolve.
pub fn validate_json(request: &ValidateRequest, env: &Env, cwd: &Path) -> String {
    let error = |code: &str, message: String| {
        json!({"error": {"code": code, "message": message}}).to_string()
    };
    let check = match request.check.as_deref() {
        None => None,
        Some(name) => match Check::parse(name) {
            Some(check) => Some(check),
            None => {
                return error(
                    crate::commands::USAGE_INVALID_CHOICE,
                    format!("{name} is not a check"),
                );
            }
        },
    };
    let queries = match request.queries.as_str() {
        "" | "error" => QueriesMode::Error,
        "warn" => QueriesMode::Warn,
        "off" => QueriesMode::Off,
        other => {
            return error(
                crate::commands::USAGE_INVALID_CHOICE,
                format!("{other} is not a queries mode: choose error, warn or off"),
            );
        }
    };
    let (_, roots) = crate::commands::placement(request.repo.as_deref(), env, cwd);
    let workspace = match crate::commands::open(roots) {
        Ok(workspace) => workspace,
        Err(message) => return error(crate::commands::COMMAND_FAILED, message),
    };
    let selection = Selection {
        files: request.files.clone(),
        uuids: request.uuids.clone(),
        types: request.types.clone(),
    };
    let validation = workspace.validate(&Options {
        check,
        selection: Some(&selection),
        strict: request.strict,
        queries,
        query_check: Some(&EngineQueries),
    });
    // Each part serialised on its own: a struct keeps its fields' order (the
    // contract's), where a `serde_json::Value` map would sort them.
    let part = |value: Result<String, serde_json::Error>| value.unwrap_or_else(|_| "null".into());
    let checks = validation
        .checks
        .iter()
        .map(|(check, status)| {
            let name = json!(check.name());
            format!("{name}:{{\"check\":{name},\"status\":{}}}", json!(status))
        })
        .collect::<Vec<_>>()
        .join(",");
    let checks = format!("{{{checks}}}");
    format!(
        "{{\"report\":{},\"checks\":{},\"summary\":{},\"failed\":{}}}",
        part(serde_json::to_string(&validation.report)),
        checks,
        part(serde_json::to_string(&validation.summary)),
        validation.failed,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn current_dir() -> std::path::PathBuf {
        std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."))
    }

    #[test]
    fn a_captured_run_returns_its_streams_and_code() {
        let env = Env::from_pairs([("OPENTIDE_JSON_INDENT", "0")]);
        let run = run_captured(
            &["--json".to_owned(), "nosuchcommand".to_owned()],
            &env,
            &current_dir(),
            "0.0.0",
            false,
        );
        assert_eq!(run.exit_code, 2);
        let text = String::from_utf8_lossy(&run.stdout);
        assert!(text.starts_with('{') && text.ends_with("}\n"), "{text}");
        assert!(text.contains("\"exit_code\":2"), "{text}");
        assert!(!interrupt(), "no run is in progress once it returned");
    }

    #[test]
    fn a_bad_check_or_mode_is_an_error_document() {
        let env = Env::default();
        let cwd = current_dir();
        let parse = |text: String| -> serde_json::Value {
            serde_json::from_str(&text).unwrap_or(serde_json::Value::Null)
        };
        let bad_check = parse(validate_json(
            &ValidateRequest {
                check: Some("nope".into()),
                ..ValidateRequest::default()
            },
            &env,
            &cwd,
        ));
        assert_eq!(bad_check["error"]["code"], "usage_invalid_choice");
        let bad_mode = parse(validate_json(
            &ValidateRequest {
                queries: "loud".into(),
                ..ValidateRequest::default()
            },
            &env,
            &cwd,
        ));
        assert_eq!(bad_mode["error"]["code"], "usage_invalid_choice");
    }
}
