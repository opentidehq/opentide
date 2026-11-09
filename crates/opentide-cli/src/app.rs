//! One run of `opentide`: from the command line to the exit code.
//!
//! [`run`] hoists the global flags, resolves the output mode, sets up logging
//! for it, parses the command line with clap, reports usage errors through
//! the contract, runs the command and catches whatever it did not expect
//! ([`crate::crash`]). It writes to the streams it is given, so the binary,
//! the Python and npm launchers and the tests all run the same code.

use crate::catalog;
use crate::crash::{self, Facts, Internal};
use crate::env::Env;
use crate::envelope::{Failure, INTERRUPTED_EXIT_CODE, NextAction, Outcome, USAGE_EXIT_CODE, code};
use crate::hoist;
use crate::json::document_text;
use crate::logging::{self, LogLayer, Sink};
use crate::mode::{self, Inputs, Mode};
use crate::redact::{Redactor, url_secrets, workspace_redactor};
use crate::style::{self, Painter};
use crate::usage;
use clap::parser::ValueSource;
use std::cell::RefCell;
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// Command paths with a Rust implementation; every other one is refused with
/// `engine_not_ported`, as `OPENTIDE_ENGINE=rust` refuses it.
pub const PORTED: &[&str] = &["commands"];

/// What the embedding process tells the run about itself.
pub struct Host {
    /// opentide's version, as `--version` and the catalogue print it.
    pub version: String,
    /// Whether stdout is a terminal.
    pub stdout_tty: bool,
    /// Whether stderr is a terminal.
    pub stderr_tty: bool,
    /// Where log lines go: stderr.
    pub log_sink: Sink,
    /// The working directory, whose workspace the redactor reads.
    pub cwd: Option<PathBuf>,
    /// The terminal's width in columns, when there is a terminal.
    pub width: Option<usize>,
}

/// The parsed root options: what every command shares.
#[expect(
    clippy::struct_excessive_bools,
    reason = "the root's flags, one field each, as the command line has them"
)]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Globals {
    /// `--json`.
    pub json: bool,
    /// `--no-color`.
    pub no_color: bool,
    /// `--debug`.
    pub debug: bool,
    /// `--quiet`.
    pub quiet: bool,
    /// `--version` or `-V`.
    pub version: bool,
    /// `--help` or `-h` among the root's own options.
    pub help: bool,
    /// `--repo`, as typed on the command line (not from the environment).
    pub repo: Option<String>,
    /// `--proxy`, from the command line or `OPENTIDE_PROXY`.
    pub proxy: Option<String>,
}

/// Reads the root's options, before the command, from hoisted arguments.
pub fn globals(root: &clap::Command, args: &[String], env: &Env) -> Globals {
    let end = hoist::root_options_end(root, args);
    let mut globals = Globals::default();
    let mut index = 0;
    while index < end {
        let token = &args[index];
        index += 1;
        let (name, inline) = match token.split_once('=') {
            Some((name, value)) => (name, Some(value.to_owned())),
            None => (token.as_str(), None),
        };
        let mut value = || {
            inline.clone().or_else(|| {
                let next = args.get(index).cloned();
                index += 1;
                next
            })
        };
        match name {
            "--json" => globals.json = true,
            "--no-color" => globals.no_color = true,
            "--debug" => globals.debug = true,
            "--quiet" => globals.quiet = true,
            "--version" | "-V" => globals.version = true,
            "--help" | "-h" => globals.help = true,
            "--repo" => globals.repo = value(),
            "--proxy" => globals.proxy = value(),
            "--data" => {
                let _data = value();
            }
            _ => {}
        }
    }
    if globals.proxy.is_none() {
        globals.proxy = env.get("OPENTIDE_PROXY").map(str::to_owned);
    }
    globals
}

/// What a run resolved before it started the command.
struct Run<'a> {
    args: Vec<String>,
    root: clap::Command,
    globals: Globals,
    mode: Mode,
    indent: bool,
    env: &'a Env,
    host: &'a Host,
    started: Instant,
}

impl Run<'_> {
    fn duration_ms(&self) -> i64 {
        i64::try_from(self.started.elapsed().as_millis()).unwrap_or(i64::MAX)
    }

    /// Prints `outcome` in this run's mode; its exit code.
    fn emit(
        &self,
        outcome: &Outcome,
        notes: &[(String, String)],
        lines: &[String],
        out: &mut dyn Write,
        err: &mut dyn Write,
    ) -> i32 {
        match self.mode {
            Mode::Json => {
                let text = document_text(&outcome.document(self.duration_ms()), self.indent);
                let _ = out.write_all(text.as_bytes());
            }
            _ if outcome.failure.is_some() && outcome.exit_code != 0 => {
                let message = outcome
                    .failure
                    .as_ref()
                    .map_or(outcome.message.as_str(), |failure| failure.message.as_str());
                let painter = self.painter(self.host.stderr_tty);
                let text =
                    style::error_lines(self.mode, painter, message, notes, &outcome.next_actions);
                let _ = err.write_all(text.as_bytes());
            }
            Mode::Mcp => {}
            _ => {
                let painter = self.painter(self.host.stdout_tty);
                for line in lines {
                    let _ = writeln!(out, "{}", painter.paint(style::bold(), line));
                }
                let _ = out.write_all(style::success_line(painter, &outcome.message).as_bytes());
                for action in &outcome.next_actions {
                    let _ = writeln!(out, "{}", style::next_action_line(painter, action));
                }
            }
        }
        let _ = out.flush();
        let _ = err.flush();
        outcome.exit_code
    }

    fn painter(&self, tty: bool) -> Painter {
        let dumb = self
            .env
            .get("TERM")
            .unwrap_or_default()
            .trim()
            .eq_ignore_ascii_case("dumb");
        Painter::for_stream(self.mode, tty, dumb).wrapping(self.host.width)
    }

    fn help(&self, path: &[String], out: &mut dyn Write) -> i32 {
        let mut command = usage::command_at(&self.root, path).clone();
        let mut bin = vec![catalog::PROGRAM.to_owned()];
        bin.extend(path.iter().cloned());
        command = command.bin_name(bin.join(" "));
        let help = command.render_long_help();
        let text = if self.mode == Mode::Human {
            help.ansi().to_string()
        } else {
            help.to_string()
        };
        let _ = out.write_all(text.as_bytes());
        if !text.ends_with('\n') {
            let _ = out.write_all(b"\n");
        }
        let _ = out.flush();
        0
    }

    fn dispatch(&self, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
        if self.globals.version {
            let _ = writeln!(out, "{} {}", catalog::PROGRAM, self.host.version);
            let _ = out.flush();
            return 0;
        }
        if self.args.is_empty() && !self.mode.is_machine() {
            return self.help(&[], out);
        }
        let argv = std::iter::once(catalog::PROGRAM.to_owned()).chain(self.args.iter().cloned());
        let matches = match self.root.clone().try_get_matches_from(argv) {
            Ok(matches) => matches,
            Err(error) => {
                if matches!(error.kind(), clap::error::ErrorKind::DisplayHelp) {
                    let path = hoist::command_words(&self.root, &self.args);
                    return self.help(&path, out);
                }
                let problem = usage::describe(&self.root, &self.args, &error);
                let outcome = Outcome::failed(&problem.command, USAGE_EXIT_CODE, problem.failure);
                return self.emit(&outcome, &problem.notes, &[], out, err);
            }
        };
        let words = command_path(&matches);
        if matches.value_source("repo") == Some(ValueSource::CommandLine)
            && let Some(repo) = &self.globals.repo
            && words.first().map(String::as_str) != Some("setup")
            && !self.resolve(repo).is_dir()
        {
            let problem = if self.resolve(repo).exists() {
                "is not a directory"
            } else {
                "does not exist"
            };
            let message = format!("--repo {repo} {problem}");
            let mut failure = Failure::new(code::USAGE_INVALID_VALUE, message);
            failure.argument = Some("--repo".into());
            let mut outcome = Outcome::failed("", USAGE_EXIT_CODE, failure);
            outcome.next_actions = vec![NextAction::new(
                "opentide --help",
                "--repo takes the folder with .opentide/ in it",
            )];
            return self.emit(&outcome, &[], &[], out, err);
        }
        let path = words.join(" ");
        match path.as_str() {
            "commands" => {
                let (data, summary) = catalog::document(&self.host.version);
                let count = catalog::entries(&self.root).len();
                let outcome = Outcome {
                    command: path.clone(),
                    status: "completed".into(),
                    message: format!("{count} commands"),
                    data,
                    exit_code: 0,
                    summary,
                    next_actions: Vec::new(),
                    failure: None,
                };
                let lines = if self.mode == Mode::Json {
                    Vec::new()
                } else {
                    catalog::tree_lines()
                };
                self.emit(&outcome, &[], &lines, out, err)
            }
            _ => {
                let message = format!(
                    "opentide {path} has no Rust implementation yet: unset OPENTIDE_ENGINE, or set it to python or compare."
                );
                let mut failure = Failure::new(code::ENGINE_NOT_PORTED, message);
                failure.argument = Some("OPENTIDE_ENGINE".into());
                let outcome = Outcome::failed(&path, USAGE_EXIT_CODE, failure);
                self.emit(&outcome, &[], &[], out, err)
            }
        }
    }

    fn resolve(&self, path: &str) -> PathBuf {
        let path = PathBuf::from(path);
        match (&self.host.cwd, path.is_absolute()) {
            (Some(cwd), false) => cwd.join(path),
            _ => path,
        }
    }

    fn workspaces(&self) -> Vec<PathBuf> {
        let mut out = Vec::new();
        if let Some(repo) = &self.globals.repo {
            out.push(self.resolve(repo));
        }
        for name in ["OPENTIDE_TIDE_WORKSPACE", "OPENTIDE_REPO_ROOT"] {
            if let Some(value) = self.env.get(name).filter(|value| !value.is_empty()) {
                out.push(self.resolve(value));
            }
        }
        out.extend(self.host.cwd.clone());
        out
    }
}

/// The subcommand path `matches` ran.
fn command_path(matches: &clap::ArgMatches) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = matches;
    while let Some((name, sub)) = current.subcommand() {
        words.push(name.to_owned());
        current = sub;
    }
    words
}

thread_local! {
    static LAST_PANIC: RefCell<Option<Internal>> = const { RefCell::new(None) };
}

/// Records each panic's message, location and backtrace for the crash report,
/// instead of printing them: [`run`] reports the panic itself.
pub fn install_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        let message = crash::panic_message(info.payload());
        let location = info
            .location()
            .map(|location| {
                format!(
                    "at {}:{}:{}\n",
                    location.file(),
                    location.line(),
                    location.column()
                )
            })
            .unwrap_or_default();
        let backtrace = std::backtrace::Backtrace::force_capture();
        LAST_PANIC.with(|last| {
            *last.borrow_mut() = Some(Internal {
                kind: "panic".into(),
                message,
                trace: format!("{location}{backtrace}"),
            });
        });
    }));
}

/// The UTC time now: `2026-11-09T10:11:12Z`, the crash log's stamp
/// `20261109T101112123456Z`, and the log lines' `10:11:12`.
pub fn utc_now() -> (String, String, String) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = i64::try_from(now.as_secs()).unwrap_or(0);
    let (year, month, day) = civil(secs.div_euclid(86_400));
    let rest = secs.rem_euclid(86_400);
    let (hour, minute, second) = (rest / 3600, rest % 3600 / 60, rest % 60);
    (
        format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z"),
        format!(
            "{year:04}{month:02}{day:02}T{hour:02}{minute:02}{second:02}{:06}Z",
            now.subsec_micros()
        ),
        format!("{hour:02}:{minute:02}:{second:02}"),
    )
}

/// Days since 1970-01-01 as a proleptic Gregorian date (Howard Hinnant's algorithm).
fn civil(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

fn log_clock() -> String {
    utc_now().2
}

/// Runs `opentide` with `argv` (without the program name); the exit code.
pub fn run(
    argv: &[String],
    env: &Env,
    host: &Host,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> i32 {
    let started = Instant::now();
    let root = catalog::root();
    let hoisted = hoist::hoist(&root, argv);
    let globals = globals(&root, &hoisted, env);
    let leading = hoist::leading_words(&root, &hoisted);
    let mode = mode::resolve(
        Inputs {
            json_flag: globals.json,
            no_color: globals.no_color,
            command: &leading,
            stdout_tty: host.stdout_tty,
        },
        env,
    );
    let debug = globals.debug || env.debug_requested();
    let run = Run {
        indent: mode::json_indent(env, host.stdout_tty),
        args: hoisted,
        root,
        globals,
        mode,
        env,
        host,
        started,
    };
    let mut redactor = workspace_redactor(&run.workspaces(), env);
    if let Some(proxy) = &run.globals.proxy {
        redactor = redactor.with_secrets(url_secrets(proxy).0);
    }
    let layer = LogLayer::new(
        logging::Config {
            debug,
            quiet: run.globals.quiet,
            json_lines: env.boolean("OPENTIDE_LOG_JSON").unwrap_or(false),
        },
        host.log_sink.clone(),
        redactor.clone(),
        log_clock,
    );
    let result = tracing::subscriber::with_default(logging::subscriber(layer), || {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run.dispatch(out, err)))
    });
    match result {
        Ok(code) => code,
        Err(payload) => {
            let internal = LAST_PANIC
                .with(|last| last.borrow_mut().take())
                .unwrap_or_else(|| Internal {
                    kind: "panic".into(),
                    message: crash::panic_message(payload.as_ref()),
                    trace: String::new(),
                });
            report_internal(&run, &internal, &redactor, debug, out, err)
        }
    }
}

fn report_internal(
    run: &Run<'_>,
    internal: &Internal,
    redactor: &Redactor,
    debug: bool,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> i32 {
    let words = hoist::command_words(&run.root, &run.args).join(" ");
    let facts = Facts::current(&run.host.version);
    let now = utc_now();
    crash::report(
        internal,
        &crash::Report {
            argv: &run.args,
            command: &words,
            mode: run.mode,
            debug,
            env: run.env,
            redactor,
            facts: &facts,
            stderr_tty: run.host.stderr_tty,
            indent: run.indent,
            log_dir: crash::crash_log_dir(run.env),
            now: (now.0, now.1),
        },
        out,
        err,
    )
}

static INTERRUPTED: AtomicBool = AtomicBool::new(false);

/// Whether Ctrl-C was pressed: long jobs (tenant calls) poll this and stop.
pub fn interrupted() -> bool {
    INTERRUPTED.load(Ordering::SeqCst)
}

/// Ctrl-C: `error: interrupted` on stderr, exit 130, in every mode and with
/// no JSON document. Jobs see [`interrupted`] first.
pub fn install_interrupt_handler() {
    // A second install (an embedding host calling `main` twice) keeps the first.
    let _ = ctrlc::set_handler(|| {
        INTERRUPTED.store(true, Ordering::SeqCst);
        let mut err = std::io::stderr().lock();
        let _ = err.write_all(b"error: interrupted\n");
        let _ = err.flush();
        std::process::exit(INTERRUPTED_EXIT_CODE);
    });
}

/// `opentide` in this process: the process's environment and streams.
pub fn main(argv: &[String], version: &str) -> i32 {
    use std::io::IsTerminal;
    install_panic_hook();
    install_interrupt_handler();
    let env = Env::from_process();
    let stderr_sink: Sink = std::sync::Arc::new(std::sync::Mutex::new(std::io::stderr()));
    let host = Host {
        version: version.to_owned(),
        stdout_tty: std::io::stdout().is_terminal(),
        stderr_tty: std::io::stderr().is_terminal(),
        log_sink: stderr_sink,
        cwd: std::env::current_dir().ok(),
        width: terminal_size::terminal_size_of(std::io::stderr())
            .or_else(|| terminal_size::terminal_size_of(std::io::stdout()))
            .map(|(width, _)| usize::from(width.0)),
    };
    let mut out = std::io::stdout().lock();
    let mut err = std::io::stderr();
    run(argv, &env, &host, &mut out, &mut err)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn framework_civil_dates() {
        assert_eq!(civil(0), (1970, 1, 1));
        assert_eq!(civil(20_766), (2026, 11, 9));
        assert_eq!(civil(-1), (1969, 12, 31));
        assert_eq!(civil(11_016), (2000, 2, 29));
        let (iso, stamp, clock) = utc_now();
        assert_eq!(iso.len(), 20);
        assert_eq!(stamp.len(), 22);
        assert_eq!(clock.len(), 8);
    }

    #[test]
    fn framework_globals_read_root_options_only() {
        let root = catalog::root();
        let args: Vec<String> =
            "--repo r --proxy=http://p --debug -V --data d --help validate --quiet"
                .split_whitespace()
                .map(str::to_owned)
                .collect();
        let globals = globals(&root, &args, &Env::default());
        assert_eq!(globals.repo.as_deref(), Some("r"));
        assert_eq!(globals.proxy.as_deref(), Some("http://p"));
        assert!(globals.debug && globals.version && globals.help && !globals.quiet);
        let env = Env::from_pairs([("OPENTIDE_PROXY", "http://e")]);
        assert_eq!(
            globals_of(&root, "validate", &env).proxy.as_deref(),
            Some("http://e")
        );
    }

    fn globals_of(root: &clap::Command, text: &str, env: &Env) -> Globals {
        let args: Vec<String> = text.split_whitespace().map(str::to_owned).collect();
        globals(root, &args, env)
    }
}
