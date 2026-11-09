//! What an unexpected error prints, and the redacted crash log it leaves.
//!
//! A panic (caught by [`crate::app::run`]) and an error a command did not
//! expect ([`Internal`]) produce the same report: `error[internal]: <Type>:
//! <message>` on stderr, the crash log's path, a pre-filled issue link and,
//! without `--debug`, the hint to add it; with `--debug`, the trace. In `json`
//! mode stdout carries the one document, `failure.code` `internal` and
//! `failure.crash_log`; in `mcp` mode stdout is never written. Exit 1.
//!
//! The crash log goes to the platform's state or log directory, never into the
//! repository: `$XDG_STATE_HOME/opentide` (`~/.local/state/opentide`) on Linux
//! and other Unix systems, `~/Library/Logs/opentide` on macOS,
//! `%LOCALAPPDATA%\opentide\logs` on Windows. Everything written goes through
//! [`crate::redact`] first.

use crate::env::Env;
use crate::envelope::{CRASH_EXIT_CODE, Failure, Outcome, code};
use crate::json::document_text;
use crate::mode::Mode;
use crate::redact::{REDACTED, Redactor, is_secret_name};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

/// Crash logs kept; older ones are deleted.
pub const KEEP_CRASH_LOGS: usize = 10;

/// Where new issues are filed.
pub const ISSUES_URL: &str = "https://github.com/opentidehq/opentide/issues/new";

const LOGGED_ENV_PREFIXES: &[&str] = &["OPENTIDE_"];
const PROXY_VARIABLES: &[&str] = &["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"];

/// An unexpected error: what failed, and how it got there.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Internal {
    /// The error's type (`panic`, `io::Error`).
    pub kind: String,
    /// Its message.
    pub message: String,
    /// Where it happened: the panic's location and backtrace, or the error chain.
    pub trace: String,
}

impl Internal {
    /// An unexpected error from an error value and its sources.
    pub fn from_error(error: &(dyn std::error::Error + 'static)) -> Internal {
        let mut trace = String::new();
        let mut source = error.source();
        while let Some(cause) = source {
            trace.push_str("caused by: ");
            trace.push_str(&cause.to_string());
            trace.push('\n');
            source = cause.source();
        }
        let kind = std::any::type_name_of_val(error)
            .rsplit("::")
            .next()
            .unwrap_or("Error")
            .to_owned();
        Internal {
            kind,
            message: error.to_string(),
            trace,
        }
    }

    /// `Type: first line of the message`, or the type alone.
    pub fn summary(&self) -> String {
        match self.message.trim().lines().next() {
            Some(first) if !first.is_empty() => format!("{}: {first}", self.kind),
            _ => self.kind.clone(),
        }
    }
}

/// The opentide version, the build and the OS that go into an issue.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Facts {
    /// opentide's version.
    pub opentide: String,
    /// The build: `rust (<target triple>)`.
    pub build: String,
    /// `Linux 6.8.0 (x86_64)`.
    pub os: String,
}

impl Facts {
    /// The facts of this process.
    pub fn current(version: &str) -> Facts {
        let release = kernel_release();
        let os = match std::env::consts::OS {
            "linux" => "Linux",
            "macos" => "Darwin",
            "windows" => "Windows",
            other => other,
        };
        Facts {
            opentide: version.to_owned(),
            build: format!("rust ({}-{})", std::env::consts::ARCH, std::env::consts::OS),
            os: if release.is_empty() {
                format!("{os} ({})", std::env::consts::ARCH)
            } else {
                format!("{os} {release} ({})", std::env::consts::ARCH)
            },
        }
    }
}

fn kernel_release() -> String {
    std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|text| text.trim().to_owned())
        .unwrap_or_default()
}

/// The pre-filled issue link: version, build, OS and the command path, never
/// argument values or paths.
pub fn issue_url(command: &str, facts: &Facts) -> String {
    let shown: String = format!("opentide {command}")
        .trim()
        .chars()
        .take(120)
        .collect();
    let body = [
        "### What happened",
        "",
        "<!-- What you ran and what you expected. -->",
        "",
        "### Environment",
        "",
        &format!("- opentide: {}", facts.opentide),
        &format!("- Build: {}", facts.build),
        &format!("- OS: {}", facts.os),
        &format!("- Command: `{shown}`"),
        "",
        "### Crash log",
        "",
        "<!-- Attach the crash log opentide printed. Credentials, tokens and tenant names are \
         redacted; read it before you attach it. -->",
    ]
    .join("\n");
    let query = form_urlencoded::Serializer::new(String::new())
        .append_pair("title", &format!("Crash in {shown}"))
        .append_pair("body", &body)
        .finish();
    format!("{ISSUES_URL}?{query}")
}

/// The directory crash logs go to, or why there is none.
pub fn crash_log_dir(env: &Env) -> Result<PathBuf, String> {
    let home = env
        .get(if cfg!(windows) { "USERPROFILE" } else { "HOME" })
        .map(PathBuf::from)
        .unwrap_or_default();
    let directory = if cfg!(windows) {
        let base = env
            .get("LOCALAPPDATA")
            .filter(|value| !value.is_empty())
            .map_or_else(|| home.join("AppData").join("Local"), PathBuf::from);
        base.join("opentide").join("logs")
    } else if cfg!(target_os = "macos") {
        home.join("Library").join("Logs").join("opentide")
    } else {
        let state = env
            .get("XDG_STATE_HOME")
            .map(PathBuf::from)
            .filter(|path| path.is_absolute())
            .unwrap_or_else(|| home.join(".local").join("state"));
        state.join("opentide")
    };
    if directory.is_absolute() {
        Ok(directory)
    } else {
        Err("no home directory to keep crash logs in".into())
    }
}

/// Writes `text` to a new `crash-<time>-<pid>.log` in `directory`, private
/// (0700 directory, 0600 file), and keeps the last [`KEEP_CRASH_LOGS`].
pub fn write_crash_log(text: &str, directory: &Path, stamp: &str) -> std::io::Result<PathBuf> {
    std::fs::create_dir_all(directory)?;
    private(directory, 0o700);
    let path = directory.join(format!("crash-{stamp}-{}.log", std::process::id()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&path)?;
    file.write_all(text.as_bytes())?;
    let mut logs: Vec<PathBuf> = std::fs::read_dir(directory)?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("crash-"))
                && path
                    .extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("log"))
        })
        .collect();
    logs.sort();
    let excess = logs.len().saturating_sub(KEEP_CRASH_LOGS);
    for old in &logs[..excess] {
        let _ignored = std::fs::remove_file(old);
    }
    Ok(path)
}

#[cfg(unix)]
fn private(directory: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    let _ignored = std::fs::set_permissions(directory, std::fs::Permissions::from_mode(mode));
}

#[cfg(not(unix))]
fn private(_directory: &Path, _mode: u32) {}

/// What a crash report needs to know about the run.
pub struct Report<'a> {
    /// The arguments, without the program name.
    pub argv: &'a [String],
    /// The command path (`validate query`).
    pub command: &'a str,
    /// The output mode.
    pub mode: Mode,
    /// `--debug` or `OPENTIDE_DEBUG`.
    pub debug: bool,
    /// The environment.
    pub env: &'a Env,
    /// Removes credentials and tenant names.
    pub redactor: &'a Redactor,
    /// Version, build, OS.
    pub facts: &'a Facts,
    /// Whether stderr is a terminal (the link becomes a hyperlink in `human` mode).
    pub stderr_tty: bool,
    /// Indent the JSON document.
    pub indent: bool,
    /// The log directory; `None` when there is none.
    pub log_dir: Result<PathBuf, String>,
    /// UTC time: `2026-11-09T10:11:12Z` for the log, and the file name's stamp.
    pub now: (String, String),
}

/// The crash log's text, redacted.
pub fn crash_log_text(error: &Internal, report: &Report<'_>) -> String {
    let mut variables: Vec<(&str, &str)> = report
        .env
        .iter()
        .filter(|(name, _)| {
            LOGGED_ENV_PREFIXES
                .iter()
                .any(|prefix| name.starts_with(prefix))
                || PROXY_VARIABLES.contains(&name.to_uppercase().as_str())
        })
        .collect();
    variables.sort_unstable();
    let arguments = report
        .redactor
        .argv(report.argv)
        .iter()
        .map(|word| shell_quote(word))
        .collect::<Vec<_>>()
        .join(" ");
    let mut lines = vec![
        "opentide crash log".to_owned(),
        String::new(),
        format!("time: {}", report.now.0),
        format!("opentide: {}", report.facts.opentide),
        format!("build: {}", report.facts.build),
        format!("os: {}", report.facts.os),
        format!("command: {}", format!("opentide {}", report.command).trim()),
        format!("arguments: {arguments}"),
        format!("output mode: {}", report.mode.as_str()),
        String::new(),
        "environment:".to_owned(),
    ];
    for (name, value) in variables {
        let shown = if is_secret_name(name) {
            REDACTED
        } else {
            value
        };
        lines.push(format!("  {name}={shown}"));
    }
    lines.push(String::new());
    lines.push(
        format!("{}\n{}", error.summary(), error.trace)
            .trim_end()
            .to_owned(),
    );
    lines.push(String::new());
    report.redactor.redact(&lines.join("\n"))
}

/// A word as a POSIX shell reads it back.
pub fn shell_quote(word: &str) -> String {
    let safe = !word.is_empty()
        && word
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "@%+=:,./-_".contains(c));
    if safe {
        word.to_owned()
    } else {
        format!("'{}'", word.replace('\'', "'\"'\"'"))
    }
}

/// Reports `error`: writes the crash log, prints the report on `err` and, in
/// `json` mode, the document on `out`. Returns the exit code, 1.
pub fn report(
    error: &Internal,
    report: &Report<'_>,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> i32 {
    let summary = report.redactor.redact(&error.summary());
    let text = crash_log_text(error, report);
    let written = match &report.log_dir {
        Ok(directory) => {
            write_crash_log(&text, directory, &report.now.1).map_err(|problem| problem.to_string())
        }
        Err(problem) => Err(problem.clone()),
    };
    if report.debug {
        let trace = report
            .redactor
            .redact(&format!("{}\n{}", error.summary(), error.trace));
        let _ignored = writeln!(err, "{}", trace.trim_end());
    }
    let mut lines = vec![format!("error[{}]: {summary}", code::INTERNAL)];
    match &written {
        Ok(path) => lines.push(format!(
            "  note: crash log, with credentials and tenant names redacted: {}",
            path.display()
        )),
        Err(problem) => lines.push(format!(
            "  note: no crash log written: {}",
            report.redactor.redact(problem)
        )),
    }
    let mut link = issue_url(report.command, report.facts);
    let hyperlinks = !report
        .env
        .get("OPENTIDE_LINKS")
        .unwrap_or_default()
        .trim()
        .eq_ignore_ascii_case("none");
    if report.mode == Mode::Human && hyperlinks && report.stderr_tty {
        link = format!("\u{1b}]8;;{link}\u{1b}\\{ISSUES_URL}\u{1b}]8;;\u{1b}\\");
    }
    lines.push(format!(
        "  help: this is a bug in opentide; report it: {link}"
    ));
    if !report.debug {
        lines.push("  help: add --debug to see the traceback".into());
    }
    let _ignored = writeln!(err, "{}", lines.join("\n"));
    if report.mode == Mode::Json {
        let mut failure = Failure::new(code::INTERNAL, summary.clone());
        failure.crash_log = written.ok().map(|path| path.display().to_string());
        let outcome = Outcome::failed(report.command, CRASH_EXIT_CODE, failure);
        let _ignored = out.write_all(document_text(&outcome.document(0), report.indent).as_bytes());
    }
    let _ignored = out.flush();
    let _ignored = err.flush();
    CRASH_EXIT_CODE
}

/// A panic's payload as text.
pub fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(text) = payload.downcast_ref::<&str>() {
        (*text).to_owned()
    } else if let Some(text) = payload.downcast_ref::<String>() {
        text.clone()
    } else {
        "(no message)".to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)]) -> Env {
        Env::from_pairs(pairs.iter().copied())
    }

    #[test]
    fn framework_crash_dir_per_platform_rules() {
        if cfg!(target_os = "linux") {
            assert_eq!(
                crash_log_dir(&env(&[("HOME", "/h"), ("XDG_STATE_HOME", "/s")])).unwrap(),
                PathBuf::from("/s/opentide")
            );
            assert_eq!(
                crash_log_dir(&env(&[("HOME", "/h"), ("XDG_STATE_HOME", "rel")])).unwrap(),
                PathBuf::from("/h/.local/state/opentide")
            );
            assert!(crash_log_dir(&env(&[])).is_err());
        }
    }

    #[test]
    fn framework_crash_issue_link_names_the_command_only() {
        let facts = Facts::current("1.2.3");
        let url = issue_url("validate query", &facts);
        assert!(url.starts_with("https://github.com/opentidehq/opentide/issues/new?title=Crash+in+opentide+validate+query&body="));
        assert!(url.contains("opentide%3A+1.2.3"));
        assert!(url.len() < 2000);
    }

    #[test]
    fn framework_crash_summary_and_quote() {
        let error = Internal {
            kind: "panic".into(),
            message: "boom\nsecond".into(),
            trace: String::new(),
        };
        assert_eq!(error.summary(), "panic: boom");
        let bare = Internal {
            kind: "panic".into(),
            message: " ".into(),
            trace: String::new(),
        };
        assert_eq!(bare.summary(), "panic");
        assert_eq!(shell_quote("a b"), "'a b'");
        assert_eq!(shell_quote("it's"), "'it'\"'\"'s'");
        assert_eq!(shell_quote("--x=1"), "--x=1");
        assert_eq!(shell_quote(""), "''");
        assert_eq!(panic_message(&"x"), "x");
        assert_eq!(panic_message(&String::from("y")), "y");
        assert_eq!(panic_message(&1_u8), "(no message)");
        let io = std::io::Error::other("disk full");
        let internal = Internal::from_error(&io);
        assert_eq!(internal.summary(), "Error: disk full");
    }

    #[test]
    fn framework_crash_logs_rotate() {
        let dir = std::env::temp_dir().join(format!("opentide-cli-crash-{}", std::process::id()));
        for index in 0..12 {
            write_crash_log("x", &dir, &format!("20260101T0000{index:02}000000Z")).unwrap();
        }
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), KEEP_CRASH_LOGS);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
