//! `opentide lsp start` (`cli/lsp_app.py`, `cli/services/lsp.py`): the
//! language server of `opentide-lsp` (UC-2.6, #821), hosted by the command
//! line on this process's stdin and stdout until the editor exits or closes
//! stdin.
//!
//! The server is a library the command line hosts (ADR 0003): this crate is
//! the tier above `opentide-lsp` in `xtask/layers.toml`. Before it serves,
//! the host
//!
//! - says on stderr, when a person runs it at a terminal, that an editor
//!   starts it;
//! - names itself, `("opentide", <version>)`, which clients read at
//!   `initialize` (`capabilities.experimental.opentide.host`).
//!
//! It hands the server neither catalogs nor configuration schemas: the
//! server builds both from `opentide-schema` and each root's configuration
//! (#926), so hover and completion include the vocabulary a workspace adds,
//! a catalog a workspace committed is never read (#677), and clients read
//! `catalog: "models"` at `initialize`.
//!
//! The exit code is LSP's: 0 when the editor shut the server down before it
//! exited, 1 otherwise, and 1 when the server stops on an error, which
//! stderr names. Nothing but protocol frames reaches stdout: the run's
//! output mode is `mcp`, in which the framework never writes it.

use std::io::Write;

/// What `lsp start` prints on stderr when a person runs it at a terminal.
pub const TERMINAL_HINT: &str = "opentide lsp start speaks the language server protocol on \
     stdin and stdout: your editor starts it (see https://opentide.org/docs/cli/lsp/). \
     Ctrl-C stops it.";

/// How the host serves: the parts a test replaces.
pub struct Host<'a> {
    /// opentide's version, which the server names its host with.
    pub version: &'a str,
    /// Whether stdin is a terminal: a person, not an editor.
    pub stdin_tty: bool,
}

/// Serves the language server on stdio with `serve`, after preparing the
/// process for it; the exit code.
pub fn start(
    host: &Host<'_>,
    err: &mut dyn Write,
    serve: impl FnOnce() -> anyhow::Result<bool>,
) -> std::io::Result<i32> {
    if host.stdin_tty {
        writeln!(err, "{TERMINAL_HINT}")?;
    }
    opentide_lsp::set_host_info(crate::catalog::PROGRAM, host.version);
    err.flush()?;
    match serve() {
        // 0 after `shutdown` then `exit`, 1 otherwise.
        Ok(clean) => Ok(i32::from(!clean)),
        Err(problem) => {
            writeln!(err, "error: the language server stopped: {problem:#}")?;
            err.flush()?;
            Ok(1)
        }
    }
}

/// [`start`] on this process's stdin and stdout.
pub fn start_stdio(version: &str, err: &mut dyn Write) -> std::io::Result<i32> {
    use std::io::IsTerminal as _;
    let host = Host {
        version,
        stdin_tty: std::io::stdin().is_terminal(),
    };
    start(&host, err, opentide_lsp::run_stdio_status)
}

#[cfg(test)]
mod tests {
    use super::{Host, TERMINAL_HINT, start};

    fn run(stdin_tty: bool, serve: impl FnOnce() -> anyhow::Result<bool>) -> (i32, String) {
        let mut err = Vec::new();
        let host = Host {
            version: "9.9.9",
            stdin_tty,
        };
        let code = start(&host, &mut err, serve).expect("stderr is a buffer");
        (code, String::from_utf8(err).expect("utf-8"))
    }

    #[test]
    fn the_exit_code_is_lsps() {
        assert_eq!(run(false, || Ok(true)), (0, String::new()));
        assert_eq!(run(false, || Ok(false)), (1, String::new()));
    }

    #[test]
    fn a_server_that_stops_on_an_error_exits_1_and_says_why() {
        let (code, err) = run(false, || Err(anyhow::anyhow!("stdin went away")));
        assert_eq!(code, 1);
        assert_eq!(err, "error: the language server stopped: stdin went away\n");
    }

    #[test]
    fn a_person_at_a_terminal_is_told_an_editor_starts_it() {
        let (_, err) = run(true, || Ok(true));
        assert_eq!(err, format!("{TERMINAL_HINT}\n"));
    }

    #[test]
    fn the_server_names_its_host_and_has_the_configuration_schemas() {
        let (code, _) = run(false, || {
            let info = opentide_lsp::host_info();
            assert_eq!(info["host"]["name"], "opentide");
            assert_eq!(info["host"]["version"], "9.9.9");
            assert_eq!(info["configurationSchemas"], true);
            // The server builds its own catalogs (#926); the host keeps none.
            assert_eq!(info["catalog"], "models");
            Ok(true)
        });
        assert_eq!(code, 0);
    }
}
