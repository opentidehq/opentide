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
use crate::render::outcome::{Console, OutcomeKind};
use crate::render::text::{Colour, Style, Text};
use crate::usage;
use clap::parser::ValueSource;
use std::cell::RefCell;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime};

/// Command paths with a Rust implementation; every other one is refused with
/// `engine_not_ported`, as `OPENTIDE_ENGINE=rust` refuses it.
/// `deploy` runs here with `--dry-run` only (UC-3.1c); a deploy that sends is
/// refused as unported, and `validate query` offline only (UC-3.5b): a
/// `--live` run is refused the same way.
pub const PORTED: &[&str] = &[
    "commands",
    "explain",
    "info",
    "lint",
    "validate",
    "validate query",
    "rules unreviewed",
    "generate exports",
    "generate exports navigator",
    "generate exports objects",
    "generate exports revisions",
    "generate docs",
    "generate docs rules",
    "generate docs objectives",
    "generate docs threats",
    "generate docs index",
    "deploy",
];

/// The file in which a run refused with `engine_not_ported` records its
/// message, when the variable names one. `OPENTIDE_ENGINE=compare`
/// (`src/opentide/cli/engines.py`) sets it for the Rust side: a command this
/// engine runs for some inputs only (`generate docs` without CVE details)
/// refuses the others, and the Python side's run is then the result.
pub const REFUSAL_ENV: &str = "OPENTIDE_ENGINE_REFUSAL";

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
    /// Ctrl-C for this run: set by the handler ([`install_interrupt_handler`]),
    /// polled by long jobs ([`Interrupt::requested`]).
    pub interrupt: Interrupt,
}

/// Ctrl-C, as one run sees it.
///
/// The first Ctrl-C sets it: long jobs (tenant calls) poll
/// [`Interrupt::requested`], stop and clean up, and the run then prints
/// `error: interrupted` on stderr and exits 130 with no JSON document. A
/// second Ctrl-C, or a run that has not stopped after [`INTERRUPT_GRACE`],
/// ends the process at once with the same line and code.
#[derive(Clone, Debug, Default)]
pub struct Interrupt {
    requested: Arc<AtomicBool>,
    reported: Arc<AtomicBool>,
}

impl Interrupt {
    /// Records a Ctrl-C; whether one was recorded before.
    pub fn request(&self) -> bool {
        self.requested.swap(true, Ordering::SeqCst)
    }

    /// Whether Ctrl-C was pressed: long jobs poll this and stop.
    pub fn requested(&self) -> bool {
        self.requested.load(Ordering::SeqCst)
    }

    /// Takes back a Ctrl-C a command handled as its way to stop
    /// (`validate --watch` exits 0): the run then reports no interruption.
    pub fn consume(&self) {
        self.requested.store(false, Ordering::SeqCst);
    }

    /// Prints `error: interrupted` once, whoever reports it first; 130.
    pub fn report(&self, err: &mut dyn Write) -> i32 {
        if !self.reported.swap(true, Ordering::SeqCst) {
            let _ignored = err.write_all(b"error: interrupted\n");
            let _ignored = err.flush();
        }
        INTERRUPTED_EXIT_CODE
    }
}

/// How long the run has to stop after the first Ctrl-C before the process
/// ends without it.
pub const INTERRUPT_GRACE: Duration = Duration::from_secs(5);

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
    /// `--data`, as typed on the command line (not from the environment).
    pub data: Option<String>,
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
            "--data" => globals.data = value(),
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

    /// Whether Ctrl-C was pressed: long jobs poll this and stop.
    pub fn interrupted(&self) -> bool {
        self.host.interrupt.requested()
    }

    /// Prints `outcome` in this run's mode; its exit code. A run Ctrl-C
    /// stopped prints nothing here: [`run`] reports it. A write that fails
    /// is the run's error ([`run`] reports it).
    fn emit(
        &self,
        outcome: &Outcome,
        notes: &[(String, String)],
        lines: &[String],
        out: &mut dyn Write,
        err: &mut dyn Write,
    ) -> std::io::Result<i32> {
        if self.interrupted() {
            return Ok(INTERRUPTED_EXIT_CODE);
        }
        self.record_refusal(outcome)?;
        match self.mode {
            Mode::Json => {
                let text = document_text(&outcome.document(self.duration_ms()), self.indent);
                out.write_all(text.as_bytes())?;
            }
            _ if outcome.failure.is_some() && outcome.exit_code != 0 => {
                let message = outcome
                    .failure
                    .as_ref()
                    .map_or(outcome.message.as_str(), |failure| failure.message.as_str());
                let console = self.console(self.host.stderr_tty);
                let mut text = console.error(message, notes, self.mode, false);
                text.push_str(&console.next_actions(&outcome.next_actions));
                text.push_str(&console.agent_tip(self.mode));
                err.write_all(text.as_bytes())?;
            }
            Mode::Mcp => {}
            _ => {
                let console = self.console(self.host.stdout_tty);
                let bold = Style::new("bold");
                for line in lines {
                    out.write_all(console.line(&Text::styled(line, &bold)).as_bytes())?;
                }
                out.write_all(
                    console
                        .outcome(OutcomeKind::Ok, &outcome.message)
                        .as_bytes(),
                )?;
                out.write_all(console.next_actions(&outcome.next_actions).as_bytes())?;
            }
        }
        out.flush()?;
        err.flush()?;
        Ok(outcome.exit_code)
    }

    /// Writes an `engine_not_ported` refusal's message to the file
    /// [`REFUSAL_ENV`] names, if it names one.
    fn record_refusal(&self, outcome: &Outcome) -> std::io::Result<()> {
        let Some(failure) = outcome
            .failure
            .as_ref()
            .filter(|failure| failure.code == code::ENGINE_NOT_PORTED)
        else {
            return Ok(());
        };
        match self.env.get(REFUSAL_ENV).filter(|path| !path.is_empty()) {
            Some(path) => std::fs::write(path, failure.message.as_bytes()),
            None => Ok(()),
        }
    }

    /// The stream the lines go to: colour in `human` mode, bold and dim only
    /// in `plain` mode, on a terminal that is not `TERM=dumb`; wrapped at its
    /// width there, whole on a pipe.
    fn console(&self, tty: bool) -> Console {
        let dumb = self
            .env
            .get("TERM")
            .unwrap_or_default()
            .trim()
            .eq_ignore_ascii_case("dumb");
        let colour = match self.mode {
            _ if !tty || dumb => Colour::None,
            Mode::Human => Colour::Full,
            Mode::Plain => Colour::Mono,
            _ => Colour::None,
        };
        Console {
            colour,
            width: self.host.width.filter(|_| colour != Colour::None),
        }
    }

    /// The help of the command at `path` on `out`; `code`.
    fn help(&self, path: &[String], code: i32, out: &mut dyn Write) -> std::io::Result<i32> {
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
        out.write_all(text.as_bytes())?;
        if !text.ends_with('\n') {
            out.write_all(b"\n")?;
        }
        out.flush()?;
        Ok(code)
    }

    fn dispatch(&self, out: &mut dyn Write, err: &mut dyn Write) -> std::io::Result<i32> {
        if self.globals.version {
            writeln!(out, "{} {}", catalog::PROGRAM, self.host.version)?;
            out.flush()?;
            return Ok(0);
        }
        if self.args.is_empty() && !self.mode.is_machine() {
            return self.help(&[], 0, out);
        }
        let argv = std::iter::once(catalog::PROGRAM.to_owned()).chain(self.args.iter().cloned());
        let matches = match self.root.clone().try_get_matches_from(argv) {
            Ok(matches) => matches,
            Err(error) => {
                let path = hoist::command_words(&self.root, &self.args);
                match error.kind() {
                    clap::error::ErrorKind::DisplayHelp => return self.help(&path, 0, out),
                    // `opentide mcp`: a person gets the group's help, exit 2;
                    // json and agent mode get the usage error below.
                    clap::error::ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
                        if matches!(self.mode, Mode::Human | Mode::Plain) =>
                    {
                        return self.help(&path, USAGE_EXIT_CODE, out);
                    }
                    _ => {}
                }
                let problem = usage::describe(&self.root, &self.args, &error);
                let outcome = Outcome::failed(&problem.command, USAGE_EXIT_CODE, problem.failure);
                return self.emit(&outcome, &problem.notes, &[], out, err);
            }
        };
        let mut words = command_path(&matches);
        // `generate schemas templates`: the words after `generate` that are
        // no subcommand of it are its phases.
        let mut generate_phases = Vec::new();
        if words.first().map(String::as_str) == Some("generate")
            && let Some(("generate", group)) = matches.subcommand()
            && let Some((first, external)) = group.subcommand()
            && self
                .root
                .find_subcommand("generate")
                .is_some_and(|generate| generate.find_subcommand(first).is_none())
        {
            generate_phases.push(first.to_owned());
            if let Ok(Some(rest)) = external.try_get_many::<String>("") {
                generate_phases.extend(rest.cloned());
            } else if let Ok(Some(rest)) = external.try_get_many::<std::ffi::OsString>("") {
                generate_phases.extend(rest.map(|word| word.to_string_lossy().into_owned()));
            }
            words.truncate(1);
            // The phases end at the first word that starts with `-`
            // (`GeneratePhaseGroup`): what follows is `generate`'s own
            // options, parsed as such, so `generate schemas --bogus` is an
            // unknown option and `generate schemas --help` the group's help.
            if let Some(end) = generate_phases
                .iter()
                .position(|word| word.starts_with('-'))
            {
                let options = generate_phases.split_off(end);
                let start = hoist::root_options_end(&self.root, &self.args);
                let mut reparsed = self.args[..=start].to_vec();
                reparsed.extend(options);
                let argv =
                    std::iter::once(catalog::PROGRAM.to_owned()).chain(reparsed.iter().cloned());
                if let Err(error) = self.root.clone().try_get_matches_from(argv) {
                    if error.kind() == clap::error::ErrorKind::DisplayHelp {
                        return self.help(&words, 0, out);
                    }
                    let problem = usage::describe(&self.root, &reparsed, &error);
                    let outcome =
                        Outcome::failed(&problem.command, USAGE_EXIT_CODE, problem.failure);
                    return self.emit(&outcome, &problem.notes, &[], out, err);
                }
            }
        }
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
            "info" => {
                let report = self.info(&matches);
                let code = self.emit_report(&report, out, err);
                // `info catalog`'s document is large (see `release`).
                release(report);
                code
            }
            "generate exports"
            | "generate exports navigator"
            | "generate exports objects"
            | "generate exports revisions" => {
                use opentide_compile::generate::exports::Target;
                let target = match words.get(2).map(String::as_str) {
                    Some("navigator") => Some(Target::Navigator),
                    Some("objects") => Some(Target::Objects),
                    Some("revisions") => Some(Target::Revisions),
                    _ => None,
                };
                let cwd = self.host.cwd.clone().unwrap_or_default();
                let report = crate::commands::generate::exports(
                    target,
                    &crate::commands::generate::Context {
                        repo: self.globals.repo.as_deref(),
                        env: self.env,
                        cwd: &cwd,
                    },
                );
                self.emit_report(&report, out, err)
            }
            "generate" => {
                let cwd = self.host.cwd.clone().unwrap_or_default();
                let report = crate::commands::generate::phases(
                    &generate_phases,
                    &crate::commands::generate::Context {
                        repo: self.globals.repo.as_deref(),
                        env: self.env,
                        cwd: &cwd,
                    },
                    &self.host.version,
                );
                self.emit_report(&report, out, err)
            }
            "new threat" | "new objective" | "new rule" => {
                let report = self.new_object(&matches, &words[1]);
                self.emit_report(&report, out, err)
            }
            "generate explorer" => {
                let parsed = leaf(&matches);
                let options = crate::commands::generate::ExplorerOptions {
                    include_visibility: parsed.get_flag("include_visibility"),
                    visibility_tlp: (parsed.value_source("visibility_tlp")
                        == Some(ValueSource::CommandLine))
                    .then(|| parsed.get_one::<String>("visibility_tlp").cloned())
                    .flatten(),
                };
                let cwd = self.host.cwd.clone().unwrap_or_default();
                let report = crate::commands::generate::explorer(
                    &options,
                    &crate::commands::generate::Context {
                        repo: self.globals.repo.as_deref(),
                        env: self.env,
                        cwd: &cwd,
                    },
                );
                self.emit_report(&report, out, err)
            }
            "validate" => {
                // A person at a terminal sees what runs until the result
                // replaces it.
                let status = self.mode == Mode::Human
                    && self.host.stderr_tty
                    && !self.globals.quiet
                    && self.console(true).colour != Colour::None;
                // Log lines follow under `--debug`: the line stays above them.
                let logging = self.globals.debug || self.env.debug_requested();
                // A report on stdout is whole: no status line then either.
                let status = status
                    && !leaf(&matches).get_flag("watch")
                    && leaf(&matches)
                        .get_one::<crate::tree::ReportFormat>("report_format")
                        .is_none_or(|format| *format == crate::tree::ReportFormat::Text);
                if status {
                    let mut line = Text::styled("⠋", &Style::new("bold cyan"));
                    line.push_str(" Validating objects");
                    err.write_all(b"\x1b[?25l")?;
                    err.write_all(line.render(Colour::Full, false).as_bytes())?;
                    if logging {
                        err.write_all(b"\n")?;
                    }
                    err.flush()?;
                }
                let (parsed, report) = self.validate(&matches);
                if status {
                    err.write_all(if logging {
                        b"\x1b[?25h".as_slice()
                    } else {
                        b"\r\x1b[2K\x1b[?25h".as_slice()
                    })?;
                    err.flush()?;
                }
                if let Some(report) = report {
                    return self.emit_report(&report, out, err);
                }
                let cwd = self.host.cwd.clone().unwrap_or_default();
                let terminal = self.terminal();
                let interrupt = self.host.interrupt.clone();
                let code = crate::commands::watch::run(
                    &parsed,
                    &crate::commands::validate::Context {
                        repo: self.globals.repo.as_deref(),
                        env: self.env,
                        cwd: &cwd,
                        version: &self.host.version,
                        terminal: &terminal,
                    },
                    out,
                    err,
                    &|| interrupt.requested(),
                )?;
                // Ctrl-C is how a watch stops.
                self.host.interrupt.consume();
                Ok(code)
            }
            "validate query" => {
                let report = self.validate_query(&matches);
                self.emit_report(&report, out, err)
            }
            "lint" => {
                let report = self.lint(&matches);
                self.emit_report(&report, out, err)
            }
            "explain" => {
                let code = leaf(&matches).get_one::<String>("code").cloned();
                let report = crate::commands::explain::run(code.as_deref(), &self.terminal());
                self.emit_report(&report, out, err)
            }
            "generate docs"
            | "generate docs rules"
            | "generate docs objectives"
            | "generate docs threats"
            | "generate docs index" => {
                use crate::commands::generate::{DocsArgs, DocsScope};
                use opentide_compile::generate::docs::catalog::Scope;
                let docs = leaf(&matches);
                let flag = |name: &str| {
                    docs.try_get_one::<bool>(name)
                        .ok()
                        .flatten()
                        .copied()
                        .unwrap_or(false)
                };
                let parsed = DocsArgs {
                    scope: match words.get(2).map(String::as_str) {
                        Some("rules") => Some(DocsScope::Objects(Scope::Rules)),
                        Some("objectives") => Some(DocsScope::Objects(Scope::Objectives)),
                        Some("threats") => Some(DocsScope::Objects(Scope::Threats)),
                        Some("index") => Some(DocsScope::Index),
                        _ => None,
                    },
                    output: docs.get_one::<String>("output").cloned(),
                    flavor: docs.get_one::<String>("flavor").cloned(),
                    rules: flag("rules"),
                    threats: flag("threats"),
                    objectives: flag("objectives"),
                    changed: flag("changed"),
                };
                let cwd = self.host.cwd.clone().unwrap_or_default();
                let report = crate::commands::generate::docs(
                    &parsed,
                    &crate::commands::generate::Context {
                        repo: self.globals.repo.as_deref(),
                        env: self.env,
                        cwd: &cwd,
                    },
                );
                self.emit_report(&report, out, err)
            }
            "doctor" => {
                let cwd = self.host.cwd.clone().unwrap_or_default();
                let report = crate::commands::doctor::run(
                    leaf(&matches).get_flag("offline"),
                    &crate::commands::doctor::Context {
                        repo: self.globals.repo.as_deref(),
                        env: self.env,
                        cwd: &cwd,
                        version: &self.host.version,
                        text: self.mode != Mode::Json && !self.globals.quiet,
                    },
                );
                self.emit_report(&report, out, err)
            }
            "migrate vocab-scope" => {
                let options = leaf(&matches);
                let parsed = crate::commands::migrate::Args {
                    apply: options.get_flag("apply"),
                    fields: options
                        .get_many::<String>("field")
                        .map(|values| values.cloned().collect())
                        .unwrap_or_default(),
                    force: options.get_flag("force"),
                };
                let cwd = self.host.cwd.clone().unwrap_or_default();
                let report = crate::commands::migrate::run(
                    &parsed,
                    self.globals.repo.as_deref(),
                    self.env,
                    &cwd,
                );
                self.emit_report(&report, out, err)
            }
            "generate inflight" | "generate inflight prune" => {
                let cwd = self.host.cwd.clone().unwrap_or_default();
                let cx = crate::commands::generate::Context {
                    repo: self.globals.repo.as_deref(),
                    env: self.env,
                    cwd: &cwd,
                };
                let report = if path == "generate inflight" {
                    crate::commands::generate::inflight_shards(&cx)
                } else {
                    crate::commands::generate::inflight_prune(&cx)
                };
                self.emit_report(&report, out, err)
            }
            "mcp start" => {
                // stdout is JSON-RPC's: nothing is emitted around the server.
                let resolved =
                    |path: Option<&str>| path.map(|path| self.resolve(path).display().to_string());
                let launch = crate::mcp::Launch {
                    cwd: self.host.cwd.clone(),
                    repo: resolved(self.globals.repo.as_deref()),
                    data: resolved(self.globals.data.as_deref()),
                    proxy: self.globals.proxy.clone(),
                    debug: self.globals.debug || self.env.debug_requested(),
                };
                crate::mcp::serve(&launch, &self.host.version)
            }
            "setup ci" => {
                let report = self.setup_ci(&matches);
                self.emit_report(&report, out, err)
            }
            "setup skills discover" | "setup skills show" => {
                let report = self.setup_skills_catalogue(&matches, &path);
                self.emit_report(&report, out, err)
            }
            "setup env" | "setup hooks" | "setup platforms" | "setup repo" | "setup mcp"
            | "setup vscode" => {
                let report = self.setup_step(&matches);
                self.emit_report(&report, out, err)
            }
            "setup" => {
                let report = self.setup_group(&matches);
                self.emit_report(&report, out, err)
            }
            "rules unreviewed" => {
                let older_than = leaf(&matches)
                    .get_one::<String>("older_than")
                    .cloned()
                    .unwrap_or_else(|| "90d".to_owned());
                let cwd = self.host.cwd.clone().unwrap_or_default();
                let report = crate::commands::rules::run(
                    &older_than,
                    self.globals.repo.as_deref(),
                    self.env,
                    &cwd,
                    jiff::Timestamp::now(),
                    self.mode != Mode::Json,
                );
                self.emit_report(&report, out, err)
            }
            "deploy" if leaf(&matches).get_flag("dry_run") => {
                let run = self.deploy(&matches);
                self.emit_deploy(&run, out, err)
            }
            "deploy" => {
                let message = "opentide deploy without --dry-run has no Rust implementation yet: \
                     unset OPENTIDE_ENGINE, or set it to python or compare."
                    .to_owned();
                let mut failure = Failure::new(code::ENGINE_NOT_PORTED, message);
                failure.argument = Some("OPENTIDE_ENGINE".into());
                let outcome = Outcome::failed(&path, USAGE_EXIT_CODE, failure);
                self.emit(&outcome, &[], &[], out, err)
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

    /// `opentide new <family>`, from its parsed arguments.
    fn new_object(&self, matches: &clap::ArgMatches, family: &str) -> crate::commands::Report {
        use crate::commands::new::{Context, NewArgs, run, stdin_is_terminal};
        let args = leaf(matches);
        let text = |id: &str| args.try_get_one::<String>(id).ok().flatten().cloned();
        let many = |id: &str| -> Vec<String> {
            args.try_get_many::<String>(id)
                .ok()
                .flatten()
                .map(|values| values.cloned().collect())
                .unwrap_or_default()
        };
        let platforms: Vec<String> = args
            .try_get_many::<crate::tree::Platform>("platform")
            .ok()
            .flatten()
            .map(|values| {
                values
                    .filter_map(|platform| {
                        clap::ValueEnum::to_possible_value(platform)
                            .map(|value| value.get_name().to_owned())
                    })
                    .collect()
            })
            .unwrap_or_default();
        let parsed = NewArgs {
            family: family.to_owned(),
            name: text("name"),
            path: text("path"),
            platforms,
            objective: text("objective"),
            threats: many("threat"),
        };
        let cwd = self.host.cwd.clone().unwrap_or_default();
        run(
            &parsed,
            &Context {
                repo: self.globals.repo.as_deref(),
                env: self.env,
                cwd: &cwd,
                version: &self.host.version,
                can_prompt: self.mode == Mode::Human && stdin_is_terminal(),
            },
        )
    }

    /// `opentide setup ci`, from its parsed arguments and the `setup`
    /// group's.
    fn setup_ci(&self, matches: &clap::ArgMatches) -> crate::commands::Report {
        use crate::commands::setup::{CiArgs, ci};
        let Some((_, group)) = matches.subcommand() else {
            return crate::commands::Report::error("setup ci", "no setup command");
        };
        let args = leaf(matches);
        let given = |matches: &clap::ArgMatches, id: &str| {
            matches.value_source(id) == Some(ValueSource::CommandLine)
        };
        let flag = |id: &str| args.get_flag(id);
        let text = |id: &str| args.get_one::<String>(id).cloned();
        let provider = args
            .get_one::<crate::tree::CiPlatform>("ci_platform")
            .map_or(
                opentide_compile::ci::Provider::GitHub,
                |platform| match platform {
                    crate::tree::CiPlatform::Github => opentide_compile::ci::Provider::GitHub,
                    crate::tree::CiPlatform::Gitlab => opentide_compile::ci::Provider::GitLab,
                    crate::tree::CiPlatform::Azure => opentide_compile::ci::Provider::Azure,
                },
            );
        let group_only = self.setup_group_only(group);
        let parsed = CiArgs {
            provider,
            path: given(args, "path").then(|| text("path")).flatten(),
            group_path: given(group, "path")
                .then(|| group.get_one::<String>("path").cloned())
                .flatten(),
            staging: !flag("no_staging"),
            inflight: !flag("no_inflight"),
            sharing: flag("sharing"),
            lint_changed: flag("lint_changed"),
            promotion: if flag("promotion") {
                Some(true)
            } else if flag("no_promotion") {
                Some(false)
            } else {
                None
            },
            promotion_target: text("promotion_target"),
            python_version: text("python_version").unwrap_or_else(|| "3.12".to_owned()),
            explorer_pages: flag("explorer_pages"),
            default_branch: text("default_branch"),
            plan: flag("plan") || group.get_flag("plan"),
            yes: flag("yes") || group.get_flag("yes"),
            group_only,
        };
        let cwd = self.host.cwd.clone().unwrap_or_default();
        ci(&parsed, &self.setup_context(&cwd))
    }

    /// The `setup` group's own options given on the command line before a
    /// subcommand, which it would ignore, named as the group's help names
    /// them (`--staging/--no-staging`).
    fn setup_group_only(&self, group: &clap::ArgMatches) -> Vec<String> {
        let given = |matches: &clap::ArgMatches, id: &str| {
            matches.value_source(id) == Some(ValueSource::CommandLine)
        };
        let setup = self.root.find_subcommand("setup");
        let mut group_only: Vec<String> = Vec::new();
        for arg in setup.into_iter().flat_map(clap::Command::get_arguments) {
            let id = arg.get_id().as_str();
            if matches!(id, "path" | "yes" | "plan") || !given(group, id) {
                continue;
            }
            let long = |arg: &clap::Arg| arg.get_long().map(|long| format!("--{long}"));
            let partner = setup
                .into_iter()
                .flat_map(clap::Command::get_arguments)
                .find(|other| {
                    other.get_id() != arg.get_id()
                        && (other.get_id().as_str() == format!("no_{id}")
                            || id == format!("no_{}", other.get_id().as_str())
                            || (id, other.get_id().as_str()) == ("lint_all", "lint_changed")
                            || (id, other.get_id().as_str()) == ("lint_changed", "lint_all"))
                });
            let name = match (long(arg), partner.and_then(long)) {
                (Some(own), Some(other)) if id.starts_with("no_") || id == "lint_all" => {
                    format!("{other}/{own}")
                }
                (Some(own), Some(other)) => format!("{own}/{other}"),
                (Some(own), None) => own,
                _ => id.to_owned(),
            };
            if !group_only.contains(&name) {
                group_only.push(name);
            }
        }
        group_only
    }

    /// The setup commands' context.
    fn setup_context<'a>(
        &'a self,
        cwd: &'a std::path::Path,
    ) -> crate::commands::setup::Context<'a> {
        crate::commands::setup::Context {
            repo: self.globals.repo.as_deref(),
            env: self.env,
            cwd,
            mode: self.mode,
            version: &self.host.version,
            quiet: self.globals.quiet,
            terminal: self.terminal(),
            interrupt: self.host.interrupt.clone(),
            stderr: self.host.log_sink.clone(),
        }
    }

    /// `opentide setup env|hooks|platforms|repo|mcp|vscode`.
    fn setup_step(&self, matches: &clap::ArgMatches) -> crate::commands::Report {
        use crate::commands::setup::files::RepoOptions;
        use crate::commands::setup::run::{Paths, Step, subcommand};
        use clap::ValueEnum;
        let Some((_, group)) = matches.subcommand() else {
            return crate::commands::Report::error("setup", "no setup command");
        };
        let Some((name, args)) = group.subcommand() else {
            return crate::commands::Report::error("setup", "no setup command");
        };
        let given = |matches: &clap::ArgMatches, id: &str| {
            matches.value_source(id) == Some(ValueSource::CommandLine)
        };
        let text = |id: &str| args.get_one::<String>(id).cloned();
        let flag_given = given(args, "path_flag");
        let positional_given = given(args, "path");
        let paths = Paths {
            own: if flag_given {
                text("path_flag")
            } else if positional_given {
                text("path")
            } else {
                None
            },
            group: given(group, "path")
                .then(|| group.get_one::<String>("path").cloned())
                .flatten(),
            both: flag_given && positional_given,
            group_only: self.setup_group_only(group),
        };
        let flag = |id: &str| {
            args.try_get_one::<bool>(id)
                .ok()
                .flatten()
                .copied()
                .unwrap_or(false)
        };
        let step = match name {
            "env" => Step::Env,
            "hooks" => Step::Hooks {
                install: !flag("no_install"),
            },
            "platforms" => Step::Platforms(
                [
                    ("sentinel", "sentinel"),
                    ("splunk", "splunk"),
                    ("crowdstrike", "crowdstrike"),
                    ("defender_for_endpoint", "defender_for_endpoint"),
                    ("sentinel_one", "sentinel_one"),
                    ("carbon_black_cloud", "carbon_black_cloud"),
                    ("harfanglab", "harfanglab"),
                    ("elastic", "elastic"),
                    ("sysdig", "sysdig"),
                ]
                .into_iter()
                .filter(|(id, _)| flag(id))
                .map(|(_, value)| value.to_owned())
                .collect(),
            ),
            "repo" => Step::Repo(RepoOptions {
                name: text("name"),
                org: text("org"),
                description: text("description"),
                platforms: args
                    .get_many::<crate::tree::Platform>("platform")
                    .into_iter()
                    .flatten()
                    .filter_map(|platform| platform.to_possible_value())
                    .map(|value| value.get_name().to_owned())
                    .collect(),
            }),
            "vscode" => Step::Vscode(crate::commands::setup::vscode::Options {
                generate: !flag("no_generate"),
                merge: !flag("no_merge"),
                mcp: flag("mcp"),
                ..crate::commands::setup::vscode::Options::from_flags(
                    flag("settings"),
                    flag("snippets"),
                )
            }),
            _ => Step::Mcp(
                [
                    ("vscode", "vscode"),
                    ("cursor", "cursor"),
                    ("claude_code", "claude-code"),
                    ("generic", "generic"),
                ]
                .into_iter()
                .filter(|(id, _)| flag(id))
                .map(|(_, value)| value.to_owned())
                .collect(),
            ),
        };
        let cwd = self.host.cwd.clone().unwrap_or_default();
        subcommand(
            &step,
            &paths,
            flag("yes") || group.get_flag("yes"),
            flag("plan") || group.get_flag("plan"),
            &self.setup_context(&cwd),
        )
    }

    /// `opentide setup` without a subcommand.
    fn setup_group(&self, matches: &clap::ArgMatches) -> crate::commands::Report {
        use crate::commands::setup::files::RepoOptions;
        use crate::commands::setup::run::{GroupArgs, group};
        use clap::ValueEnum;
        let args = leaf(matches);
        let flag = |id: &str| args.get_flag(id);
        let text = |id: &str| args.get_one::<String>(id).cloned();
        let names = |values: Vec<Option<clap::builder::PossibleValue>>| -> Vec<String> {
            let mut out: Vec<String> = Vec::new();
            for value in values.into_iter().flatten() {
                let name = value.get_name().to_owned();
                if !out.contains(&name) {
                    out.push(name);
                }
            }
            out
        };
        let parsed = GroupArgs {
            path: text("path").unwrap_or_else(|| ".".to_owned()),
            repo: RepoOptions {
                name: text("name"),
                org: text("org"),
                description: text("description"),
                platforms: args
                    .get_many::<crate::tree::Platform>("platform")
                    .into_iter()
                    .flatten()
                    .filter_map(|platform| platform.to_possible_value())
                    .map(|value| value.get_name().to_owned())
                    .collect(),
            },
            ci: args
                .get_one::<crate::tree::Ci>("ci")
                .and_then(|ci| ci.to_possible_value())
                .map(|value| value.get_name().to_owned()),
            pipeline: None,
            staging: !flag("no_staging"),
            inflight: !flag("no_inflight"),
            sharing: flag("sharing"),
            lint_changed: flag("lint_changed"),
            explorer_pages: flag("explorer_pages"),
            promotion: if flag("promotion") {
                Some(true)
            } else if flag("no_promotion") {
                Some(false)
            } else {
                None
            },
            promotion_target: text("promotion_target"),
            python_version: text("python_version").unwrap_or_else(|| "3.12".to_owned()),
            default_branch: text("default_branch"),
            vscode_setup: flag("vscode_setup"),
            mcp: names(
                args.get_many::<crate::tree::Mcp>("mcp")
                    .into_iter()
                    .flatten()
                    .map(ValueEnum::to_possible_value)
                    .collect(),
            ),
            skills: names(
                args.get_many::<crate::tree::Skills>("skills")
                    .into_iter()
                    .flatten()
                    .map(ValueEnum::to_possible_value)
                    .collect(),
            ),
            plugin: flag("plugin"),
            hooks: flag("hooks"),
            env: flag("env"),
            plan: flag("plan"),
            yes: flag("yes"),
        };
        let cwd = self.host.cwd.clone().unwrap_or_default();
        group(&parsed, &self.setup_context(&cwd))
    }

    /// `opentide info`, from its parsed arguments.
    fn info(&self, matches: &clap::ArgMatches) -> crate::commands::Report {
        use clap::ValueEnum;
        let args = leaf(matches);
        let cwd = self.host.cwd.clone().unwrap_or_default();
        let parsed = crate::commands::info::Args {
            platform: args
                .get_one::<crate::tree::Platform>("platform")
                .and_then(|platform| platform.to_possible_value())
                .map(|value| value.get_name().to_owned()),
            section: args.get_one::<String>("section").cloned(),
            name: args.get_one::<String>("name").cloned(),
            technique: args.get_one::<String>("technique").cloned(),
            strict: args.get_flag("strict"),
        };
        crate::commands::info::run(
            &parsed,
            &crate::commands::info::Context {
                repo: self.globals.repo.as_deref(),
                env: self.env,
                cwd: &cwd,
                version: &self.host.version,
                text: self.mode != Mode::Json,
            },
        )
    }

    /// `opentide validate`, from its parsed arguments: its report, or `None`
    /// for a `--watch` the options allow, which runs until Ctrl-C.
    fn validate(
        &self,
        matches: &clap::ArgMatches,
    ) -> (
        crate::commands::validate::Args,
        Option<crate::commands::Report>,
    ) {
        use crate::commands::validate::{Args, Context, run};
        use clap::ValueEnum;
        let args = leaf(matches);
        let strings = |id: &str| -> Vec<String> {
            args.get_many::<String>(id)
                .map(|values| values.cloned().collect())
                .unwrap_or_default()
        };
        let parsed = Args {
            check: args
                .get_one::<crate::tree::Check>("check")
                .and_then(|check| check.to_possible_value())
                .and_then(|value| opentide_workspace::validate::Check::parse(value.get_name())),
            selection: opentide_workspace::validate::Selection {
                files: strings("file"),
                uuids: strings("uuid"),
                types: strings("object_type"),
            },
            strict: args.get_flag("strict"),
            queries: args
                .get_one::<crate::tree::Queries>("queries")
                .map(|queries| match queries {
                    crate::tree::Queries::Error => opentide_workspace::validate::QueriesMode::Error,
                    crate::tree::Queries::Warn => opentide_workspace::validate::QueriesMode::Warn,
                    crate::tree::Queries::Off => opentide_workspace::validate::QueriesMode::Off,
                }),
            fix: args.get_flag("fix"),
            dry_run: args.get_flag("dry_run"),
            watch: args.get_flag("watch"),
            format: args
                .get_one::<crate::tree::ReportFormat>("report_format")
                .map(|format| match format {
                    crate::tree::ReportFormat::Text => crate::render::report::ReportFormat::Text,
                    crate::tree::ReportFormat::Sarif => crate::render::report::ReportFormat::Sarif,
                    crate::tree::ReportFormat::Codequality => {
                        crate::render::report::ReportFormat::Codequality
                    }
                }),
            output: args.get_one::<PathBuf>("output").cloned(),
        };
        if parsed.watch && crate::commands::validate::refuse(&parsed, self.mode).is_none() {
            return (parsed, None);
        }
        let cwd = self.host.cwd.clone().unwrap_or_default();
        let terminal = self.terminal();
        let report = run(
            &parsed,
            &Context {
                repo: self.globals.repo.as_deref(),
                env: self.env,
                cwd: &cwd,
                version: &self.host.version,
                terminal: &terminal,
            },
        );
        (parsed, Some(report))
    }

    /// `opentide validate query`, from its parsed arguments. The options of
    /// `validate` it also takes, typed before `query`, are its own
    /// (`hand_down`); the others are refused, as is one typed on both.
    fn validate_query(&self, matches: &clap::ArgMatches) -> crate::commands::Report {
        use crate::commands::validate_query::{Args, COMMAND, Context, run};
        use clap::ValueEnum;
        let args = leaf(matches);
        let group = matches.subcommand_matches("validate");
        let typed =
            |on: &clap::ArgMatches, id: &str| on.value_source(id) == Some(ValueSource::CommandLine);
        if let Some(group) = group {
            // `validate`'s options in its order, with their flags.
            const GROUP: [(&str, &str, bool); 11] = [
                ("check", "--check", false),
                ("file", "--file", true),
                ("uuid", "--uuid", true),
                ("object_type", "--type", false),
                ("strict", "--strict", true),
                ("queries", "--queries", true),
                ("fix", "--fix", false),
                ("dry_run", "--dry-run", false),
                ("watch", "--watch", false),
                ("report_format", "--format", false),
                ("output", "--output", false),
            ];
            let refused: Vec<&str> = GROUP
                .iter()
                .filter(|(id, _, shared)| !shared && typed(group, id))
                .map(|(_, flag, _)| *flag)
                .collect();
            let problem = if refused.is_empty() {
                // `validate query`'s own options, in its order.
                let twice: Vec<&str> = [
                    ("file", "--file"),
                    ("uuid", "--uuid"),
                    ("strict", "--strict"),
                    ("queries", "--queries"),
                ]
                .iter()
                .filter(|(id, _)| typed(group, id) && typed(args, id))
                .map(|(_, flag)| *flag)
                .collect();
                (!twice.is_empty()).then(|| {
                    format!(
                        "Pass {} once, before or after `query`, not both: `opentide validate \
                         query` would use only the second.",
                        twice.join(", ")
                    )
                })
            } else {
                let verb = if refused.len() == 1 {
                    "configures"
                } else {
                    "configure"
                };
                Some(format!(
                    "{} {verb} `opentide validate` itself and would be ignored by `opentide \
                     validate query`.",
                    refused.join(", ")
                ))
            };
            if let Some(problem) = problem {
                let failure = Failure::new(
                    code::USAGE_INVALID_VALUE,
                    format!("Invalid value: {problem}"),
                );
                return crate::commands::Report::failed(COMMAND, USAGE_EXIT_CODE, failure);
            }
        }
        // An option typed on `validate` alone is the subcommand's.
        let pick = |id: &str| -> &clap::ArgMatches {
            let shared = ["file", "uuid", "strict", "queries"].contains(&id);
            match group {
                Some(group) if shared && typed(group, id) && !typed(args, id) => group,
                _ => args,
            }
        };
        let strings = |id: &str| -> Vec<String> {
            pick(id)
                .get_many::<String>(id)
                .map(|values| values.cloned().collect())
                .unwrap_or_default()
        };
        let parsed = Args {
            platform: args
                .get_one::<crate::tree::Platform>("platform")
                .and_then(|platform| platform.to_possible_value())
                .map(|value| value.get_name().to_owned()),
            strategies: strings("strategy"),
            plan: args.get_one::<String>("plan").cloned(),
            wide: args.get_flag("wide"),
            live: args.get_flag("live"),
            changed: args.get_flag("changed"),
            files: strings("file"),
            uuids: strings("uuid"),
            strict: pick("strict").get_flag("strict"),
            queries: pick("queries")
                .get_one::<crate::tree::Queries>("queries")
                .map(|queries| match queries {
                    crate::tree::Queries::Error => opentide_workspace::validate::QueriesMode::Error,
                    crate::tree::Queries::Warn => opentide_workspace::validate::QueriesMode::Warn,
                    crate::tree::Queries::Off => opentide_workspace::validate::QueriesMode::Off,
                }),
            check_timeout: args.get_one::<String>("check_timeout").cloned(),
        };
        let cwd = self.host.cwd.clone().unwrap_or_default();
        let terminal = self.terminal();
        run(
            &parsed,
            &Context {
                repo: self.globals.repo.as_deref(),
                env: self.env,
                cwd: &cwd,
                terminal: &terminal,
            },
        )
    }

    /// `opentide lint`, from its parsed arguments.
    fn lint(&self, matches: &clap::ArgMatches) -> crate::commands::Report {
        use clap::ValueEnum;
        let args = leaf(matches);
        let parsed = crate::commands::lint::Args {
            fix: args.get_flag("fix"),
            strict: args.get_flag("strict"),
            checks: args
                .get_many::<crate::tree::Check2>("check")
                .into_iter()
                .flatten()
                .filter_map(|check| check.to_possible_value())
                .filter_map(|value| opentide_workspace::lint::LintCheck::parse(value.get_name()))
                .collect(),
            changed: args.get_flag("changed"),
            files: args
                .get_many::<String>("file")
                .map(|values| values.cloned().collect())
                .unwrap_or_default(),
            format: args
                .get_one::<crate::tree::ReportFormat>("report_format")
                .map(|format| report_format(*format)),
            output: args.get_one::<PathBuf>("output").cloned(),
        };
        let cwd = self.host.cwd.clone().unwrap_or_default();
        let terminal = self.terminal();
        crate::commands::lint::run(
            &parsed,
            &crate::commands::lint::Context {
                repo: self.globals.repo.as_deref(),
                env: self.env,
                cwd: &cwd,
                version: &self.host.version,
                terminal: &terminal,
            },
        )
    }

    /// The streams, as a command lays its text out for them.
    fn terminal(&self) -> crate::commands::Terminal {
        crate::commands::Terminal {
            mode: self.mode,
            stdout: self.console(self.host.stdout_tty),
            stderr: self.console(self.host.stderr_tty),
            quiet: self.globals.quiet,
            stdout_tty: self.host.stdout_tty,
            width: self.host.width,
        }
    }

    /// `opentide deploy --dry-run`, from its parsed arguments.
    fn deploy(&self, matches: &clap::ArgMatches) -> crate::commands::deploy::DryRun {
        use clap::ValueEnum;
        let args = leaf(matches);
        let strings = |id: &str| -> Vec<String> {
            args.get_many::<String>(id)
                .map(|values| values.cloned().collect())
                .unwrap_or_default()
        };
        let keep_deprecated = if args.get_flag("keep_deprecated") {
            Some(true)
        } else if args.get_flag("drop_deprecated") {
            Some(false)
        } else {
            None
        };
        let parsed = crate::commands::deploy::Args {
            strategies: strings("strategy"),
            all: args.get_flag("all_files"),
            uuids: strings("uuids"),
            files: strings("files"),
            platform: args
                .get_one::<crate::tree::Platform>("platform")
                .and_then(|platform| platform.to_possible_value())
                .map(|value| value.get_name().to_owned()),
            plan: args.get_one::<String>("plan").cloned(),
            wide: args.get_flag("wide"),
            keep_deprecated,
        };
        let cwd = self.host.cwd.clone().unwrap_or_default();
        crate::commands::deploy::run(
            &parsed,
            &crate::commands::deploy::Context {
                repo: self.globals.repo.as_deref(),
                env: self.env,
                cwd: &cwd,
            },
        )
    }

    /// Prints a dry run in this run's mode, in the oracle's order: the
    /// progress events, then the plan (stdout), the rules that would fail
    /// (stderr), the CI job summary, the result, and the closing note.
    fn emit_deploy(
        &self,
        run: &crate::commands::deploy::DryRun,
        out: &mut dyn Write,
        err: &mut dyn Write,
    ) -> std::io::Result<i32> {
        use crate::render::outcome::{ResultView, render_result};
        use crate::render::{ci, progress, summary};
        if self.interrupted() {
            return Ok(INTERRUPTED_EXIT_CODE);
        }
        let outcome = &run.outcome;
        if progress::Progress::from_env(self.env).enabled() {
            let total = run.compiled.len();
            for (index, platform) in run.compiled.iter().enumerate() {
                let event = progress::progress_event(platform, index + 1, Some(total));
                err.write_all(progress::event_line(&event).as_bytes())?;
            }
            err.flush()?;
        }
        if self.mode == Mode::Json {
            let document = run.document(self.duration_ms());
            out.write_all(document_text(&document, self.indent).as_bytes())?;
            out.flush()?;
            return Ok(outcome.exit_code);
        }
        let stdout = self.console(self.host.stdout_tty);
        let stderr = self.console(self.host.stderr_tty);
        let text_out = self.mode != Mode::Mcp;
        if !run.refused && !self.globals.quiet && text_out {
            for (line, hang) in run.plan_lines() {
                let text = match hang {
                    Some(hang) => stdout.print_line(&line, hang),
                    None => stdout.line(&line),
                };
                out.write_all(text.as_bytes())?;
            }
            out.flush()?;
        }
        if !run.diagnostics.is_empty() {
            // Errors print under --quiet too: the tally that follows counts them.
            let frames = crate::render::codeframe::Frames {
                colour: stderr.colour,
                links: self.mode == Mode::Human && self.host.stderr_tty,
                columns: stderr.width,
                highlight: self.mode == Mode::Human,
                cwd: self.host.cwd.clone().unwrap_or_default(),
                env: self.env.clone(),
            };
            let mut sources = crate::render::diagnostic::SourceFiles::default();
            err.write_all(
                frames
                    .render(&run.diagnostics, &mut sources, false)
                    .as_bytes(),
            )?;
            err.flush()?;
        }
        if !run.refused && outcome.exit_code != USAGE_EXIT_CODE {
            let markdown = summary::fit(
                &summary::deploy_summary(&run.result, None, Some(true)),
                summary::MAX_SUMMARY_BYTES,
            );
            let cwd = self.host.cwd.clone().unwrap_or_default();
            let written = ci::append_summary(&markdown, "deploy", self.mode, self.env, &cwd);
            for line in &written.stdout {
                out.write_all(format!("{line}\n").as_bytes())?;
            }
        }
        let view = ResultView {
            message: outcome.message.clone(),
            outcome: run.outcome_line.clone(),
            status: outcome.status.clone(),
            ok: outcome.ok(),
            outcome_kind: run.plan_kind.then_some(OutcomeKind::Plan),
            failure: outcome
                .failure
                .as_ref()
                .map(|failure| (failure.code.clone(), failure.suggestion.clone())),
            detail: run.detail(),
            advice: run.advice(),
            warnings: run.warnings.clone(),
            next_actions: outcome.next_actions.clone(),
            numbered_next: false,
        };
        let (result_out, result_err) =
            render_result(&view, stdout, stderr, self.mode, self.globals.quiet);
        if text_out {
            out.write_all(result_out.as_bytes())?;
        }
        err.write_all(result_err.as_bytes())?;
        if !run.refused && !self.globals.quiet && text_out {
            let note = Text::styled(crate::commands::deploy::DRY_RUN_NOTE, &Style::new("dim"));
            out.write_all(stdout.line(&note).as_bytes())?;
        }
        out.flush()?;
        err.flush()?;
        Ok(outcome.exit_code)
    }

    /// The width a table or a long line is laid out at on stdout: `COLUMNS`,
    /// else the terminal's, else 80.
    fn stdout_width(&self) -> usize {
        if let Some(columns) = self
            .env
            .get("COLUMNS")
            .filter(|value| !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|value| value.parse::<usize>().ok())
        {
            return columns;
        }
        if self.host.stdout_tty {
            self.host.width.unwrap_or(80)
        } else {
            80
        }
    }

    /// Prints `report` in this run's mode; its exit code.
    fn emit_report(
        &self,
        report: &crate::commands::Report,
        out: &mut dyn Write,
        err: &mut dyn Write,
    ) -> std::io::Result<i32> {
        use crate::commands::Block;
        use crate::render::outcome::{ResultView, render_result};
        if self.interrupted() {
            return Ok(INTERRUPTED_EXIT_CODE);
        }
        let outcome = &report.outcome;
        self.record_refusal(outcome)?;
        if !report.stderr_first.is_empty() {
            err.write_all(report.stderr_first.as_bytes())?;
            err.flush()?;
        }
        if self.mode == Mode::Json {
            let mut document = outcome.document(self.duration_ms());
            if !report.warnings.is_empty()
                && let crate::json::Json::Object(members) = &mut document
            {
                let at = members
                    .iter()
                    .position(|(key, _)| key == "message")
                    .map_or(members.len(), |at| at + 1);
                members.insert(
                    at,
                    (
                        "warnings".into(),
                        crate::json::Json::Array(
                            report.warnings.iter().map(crate::json::Json::str).collect(),
                        ),
                    ),
                );
            }
            out.write_all(document_text(&document, self.indent).as_bytes())?;
            out.flush()?;
            return Ok(outcome.exit_code);
        }
        if !report.steps.is_empty() && self.mode != Mode::Mcp && !self.globals.quiet {
            let console = self.console(self.host.stderr_tty);
            if self.mode == Mode::Human && self.host.stderr_tty {
                err.write_all(
                    crate::render::progress::checklist(
                        &report.steps,
                        self.host.width.unwrap_or(80),
                        console.colour,
                    )
                    .as_bytes(),
                )?;
            } else {
                for step in &report.steps {
                    err.write_all(
                        console
                            .line(&crate::render::progress::step_line(step))
                            .as_bytes(),
                    )?;
                }
            }
        }
        let stdout = self.console(self.host.stdout_tty);
        let width = self.stdout_width();
        if let Some(whole) = &report.whole_stdout {
            if self.mode != Mode::Mcp {
                out.write_all(whole.as_bytes())?;
            }
            out.flush()?;
            return Ok(outcome.exit_code);
        }
        if self.mode != Mode::Mcp {
            for block in &report.body {
                match block {
                    Block::Lines(lines) => {
                        for line in lines {
                            for row in crate::render::table::wrap_text(line, width) {
                                out.write_all(stdout.line(&row).as_bytes())?;
                            }
                        }
                    }
                    Block::Table(table) => {
                        for line in table.render(width) {
                            out.write_all(stdout.line(&line).as_bytes())?;
                        }
                    }
                    Block::Hanging(lines) => {
                        for (line, hang) in lines {
                            out.write_all(stdout.print_line(line, *hang).as_bytes())?;
                        }
                    }
                    Block::Raw(text) => out.write_all(text.as_bytes())?,
                    Block::Stderr(text) => {
                        out.flush()?;
                        err.write_all(text.as_bytes())?;
                        err.flush()?;
                    }
                }
            }
        }
        if report.body_only && outcome.exit_code == 0 {
            out.flush()?;
            err.flush()?;
            return Ok(outcome.exit_code);
        }
        let view = ResultView {
            message: outcome.message.clone(),
            outcome: report.outcome_line.clone(),
            status: outcome.status.clone(),
            ok: outcome.ok(),
            outcome_kind: report.outcome_kind,
            failure: outcome
                .failure
                .as_ref()
                .map(|failure| (failure.code.clone(), failure.suggestion.clone())),
            // A result's `detail` is a `note:` and its `advice` a `help:`
            // under the outcome (`REMEDIATION_FIELDS`).
            detail: data_text(&outcome.data, "detail"),
            advice: data_text(&outcome.data, "advice"),
            warnings: report.warnings.clone(),
            next_actions: outcome.next_actions.clone(),
            numbered_next: report.numbered_next,
        };
        let (text_out, text_err) = render_result(
            &view,
            stdout,
            self.console(self.host.stderr_tty),
            self.mode,
            self.globals.quiet,
        );
        if self.mode != Mode::Mcp {
            out.write_all(text_out.as_bytes())?;
        }
        err.write_all(text_err.as_bytes())?;
        out.flush()?;
        err.flush()?;
        Ok(outcome.exit_code)
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

impl Run<'_> {
    /// `setup skills discover` and `setup skills show` (UC-4.1, #831): the
    /// target the command and its groups name, then the catalogue.
    fn setup_skills_catalogue(
        &self,
        matches: &clap::ArgMatches,
        path: &str,
    ) -> crate::commands::Report {
        use crate::commands::skills;
        let cwd = self.host.cwd.clone().unwrap_or_default();
        let given = |matches: &clap::ArgMatches, id: &str| {
            matches.value_source(id) == Some(ValueSource::CommandLine)
        };
        // The groups' own options, which the subcommand would ignore, and
        // their paths, which it takes (`_hand_down`, `_group_path`).
        let mut group_paths: Vec<String> = Vec::new();
        let mut refusal: Option<String> = None;
        let mut current = matches;
        let mut command = self.root.clone();
        let mut words = vec![crate::catalog::PROGRAM.to_owned()];
        while let Some((name, sub)) = current.subcommand() {
            let Some(group) = command.find_subcommand(name).cloned() else {
                break;
            };
            words.push(name.to_owned());
            if sub.subcommand().is_none() {
                break;
            }
            let invoked = sub.subcommand_name().unwrap_or_default().to_owned();
            let ignored: Vec<String> = group
                .get_arguments()
                .filter(|arg| {
                    let id = arg.get_id().as_str();
                    !matches!(id, "path" | "yes" | "plan") && given(sub, id)
                })
                .map(|arg| {
                    let mut names: Vec<String> = Vec::new();
                    if let Some(long) = arg.get_long() {
                        names.push(format!("--{long}"));
                    }
                    if let Some(short) = arg.get_short() {
                        names.push(format!("-{short}"));
                    }
                    names.join("/")
                })
                .collect();
            if !ignored.is_empty() && refusal.is_none() {
                let verb = if ignored.len() == 1 {
                    "configures"
                } else {
                    "configure"
                };
                refusal = Some(format!(
                    "{} {verb} `{}` itself and would be ignored by `{} {invoked}`.",
                    ignored.join(", "),
                    words.join(" "),
                    words.join(" ")
                ));
            }
            if given(sub, "path")
                && let Some(value) = sub.get_one::<String>("path")
            {
                group_paths.push(value.clone());
            }
            current = sub;
            command = group;
        }
        let leaf = leaf(matches);
        let usage = |message: String| {
            let mut failure = crate::envelope::Failure::new(
                code::USAGE_INVALID_VALUE,
                format!("Invalid value: {message}"),
            );
            failure.argument = None;
            crate::commands::Report::failed(path, USAGE_EXIT_CODE, failure)
        };
        if let Some(refusal) = refusal {
            return usage(refusal);
        }
        let mut warnings = Vec::new();
        let own = if path == "setup skills discover" {
            let flag = given(leaf, "path_flag");
            let positional = given(leaf, "path");
            if flag && positional {
                return usage(
                    "Pass the repository path once: use --path/-C or the positional PATH, not both."
                        .to_owned(),
                );
            }
            if positional {
                let value = leaf.get_one::<String>("path").cloned().unwrap_or_default();
                let legacy = format!("positional PATH (opentide setup skills discover {value})");
                if self.mode == Mode::Json {
                    tracing::warn!(
                        legacy = legacy.as_str(),
                        use_instead = "--path/-C",
                        "cli_command_deprecated"
                    );
                } else {
                    warnings.push(format!("{legacy} is deprecated; use --path/-C"));
                }
                Some(value)
            } else if flag {
                leaf.get_one::<String>("path_flag").cloned()
            } else {
                None
            }
        } else {
            given(leaf, "path")
                .then(|| leaf.get_one::<String>("path").cloned())
                .flatten()
        };
        let setup_path = |given: &str| -> std::path::PathBuf {
            let candidate = std::path::Path::new(given);
            match self.globals.repo.as_deref() {
                Some(repo)
                    if candidate == std::path::Path::new(".")
                        && crate::commands::setup::resolved(&cwd, std::path::Path::new(repo))
                            != crate::commands::setup::resolved(&cwd, &cwd) =>
                {
                    cwd.join(repo)
                }
                _ => cwd.join(candidate),
            }
        };
        let named: Vec<String> = group_paths.into_iter().chain(own).collect();
        let mut targets: Vec<std::path::PathBuf> = named
            .iter()
            .map(|given| crate::commands::setup::resolved(&cwd, &setup_path(given)))
            .collect();
        targets.dedup();
        if targets.len() > 1 {
            return usage(format!(
                "Pass the repository path once: {} name different targets.",
                named.join(" and ")
            ));
        }
        let repo = setup_path(named.last().map_or(".", String::as_str));
        let interrupt = &self.host.interrupt;
        let interrupted = || interrupt.requested();
        let network = skills::Network {
            env: self.env,
            proxy: self.globals.proxy.as_deref(),
            interrupted: &interrupted,
        };
        let mut report = if path == "setup skills discover" {
            skills::discover(
                &skills::DiscoverArgs {
                    repo,
                    query: leaf.get_one::<String>("query").cloned(),
                    installed_only: leaf.get_flag("installed"),
                    refresh: leaf.get_flag("refresh"),
                },
                network,
                self.stdout_width(),
            )
        } else {
            skills::show(
                &leaf.get_one::<String>("name").cloned().unwrap_or_default(),
                &repo,
                leaf.get_flag("refresh"),
                network,
                self.mode == Mode::Json,
            )
        };
        report.warnings.splice(0..0, warnings);
        report
    }
}

/// `--format`'s value as the renderers name it.
fn report_format(format: crate::tree::ReportFormat) -> crate::render::report::ReportFormat {
    match format {
        crate::tree::ReportFormat::Text => crate::render::report::ReportFormat::Text,
        crate::tree::ReportFormat::Sarif => crate::render::report::ReportFormat::Sarif,
        crate::tree::ReportFormat::Codequality => crate::render::report::ReportFormat::Codequality,
    }
}

/// The matches of the subcommand `matches` ran.
fn leaf(matches: &clap::ArgMatches) -> &clap::ArgMatches {
    let mut current = matches;
    while let Some((_, sub)) = current.subcommand() {
        current = sub;
    }
    current
}

/// The subcommand path `matches` ran.
/// The string a result holds at `key`, if any.
fn data_text(data: &[(String, crate::json::Json)], key: &str) -> Option<String> {
    data.iter()
        .find(|(name, _)| name == key)
        .and_then(|(_, value)| match value {
            crate::json::Json::Str(text) => Some(text.clone()),
            _ => None,
        })
}

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
    utc_at(SystemTime::now())
}

/// [`utc_now`] at `time`, formatted by humantime's RFC 3339.
pub fn utc_at(time: SystemTime) -> (String, String, String) {
    let iso = humantime::format_rfc3339_seconds(time).to_string();
    // `2026-11-09T10:11:12.123456Z` -> `20261109T101112123456Z`.
    let stamp: String = humantime::format_rfc3339_micros(time)
        .to_string()
        .chars()
        .filter(|c| !matches!(c, '-' | ':' | '.'))
        .collect();
    let clock = iso.get(11..19).unwrap_or_default().to_owned();
    (iso, stamp, clock)
}

/// A log line's time: `2026-11-09 10:11:12` (UTC), the date-time a JSON line
/// carries; a text line under `--debug` shows the time part.
fn log_clock() -> String {
    utc_now()
        .0
        .replace('T', " ")
        .trim_end_matches('Z')
        .to_owned()
}

/// Runs `opentide` with `argv` (without the program name); the exit code.
pub fn run(
    argv: &[String],
    env: &Env,
    host: &Host,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> i32 {
    run_with(argv, env, host, out, err, |run, out, err| {
        Ok(run.dispatch(out, err)?)
    })
}

/// What a command returns: its exit code, or an error it did not expect,
/// which is reported as a crash, as a panic is.
pub type CommandResult = Result<i32, Box<dyn std::error::Error + Send + Sync>>;

/// [`run`], with the command step given: everything around it (modes,
/// logging, the crash handler) is the run's.
fn run_with(
    argv: &[String],
    env: &Env,
    host: &Host,
    out: &mut dyn Write,
    err: &mut dyn Write,
    command: impl FnOnce(&Run<'_>, &mut dyn Write, &mut dyn Write) -> CommandResult,
) -> i32 {
    let started = Instant::now();
    let root = catalog::root();
    let hoisted = hoist::drop_group_separators(&root, &hoist::hoist(&root, argv));
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
            // `--json` writes its log lines as JSON too, as OPENTIDE_LOG_JSON=1 does.
            json_lines: mode == Mode::Json || env.boolean("OPENTIDE_LOG_JSON").unwrap_or(false),
        },
        host.log_sink.clone(),
        redactor.clone(),
        log_clock,
    );
    let result = tracing::subscriber::with_default(logging::subscriber(layer), || {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| command(&run, out, err)))
    });
    if run.interrupted() {
        // The jobs stopped: one line, no document, whatever they returned.
        return host.interrupt.report(err);
    }
    match result {
        Ok(Ok(code)) => code,
        // The reader went away (`opentide --json commands | head -c1`):
        // nobody reads a report either. Exit 1, quietly, as the CLI always has.
        Ok(Err(error)) if is_broken_pipe(error.as_ref()) => 1,
        Ok(Err(error)) => {
            let internal = Internal::from_error(error.as_ref());
            report_internal(&run, &internal, &redactor, debug, out, err)
        }
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

/// Whether `error` is, or wraps, a write to a closed pipe.
fn is_broken_pipe(error: &(dyn std::error::Error + 'static)) -> bool {
    let mut current = Some(error);
    while let Some(error) = current {
        if error
            .downcast_ref::<std::io::Error>()
            .is_some_and(|error| error.kind() == std::io::ErrorKind::BrokenPipe)
        {
            return true;
        }
        current = error.source();
    }
    false
}

/// Ctrl-C: `interrupt` is set, and the run stops ([`Interrupt`]). The
/// process ends with `error: interrupted` and 130 on a second Ctrl-C, or when
/// the run has not stopped after [`INTERRUPT_GRACE`].
pub fn install_interrupt_handler(interrupt: Interrupt) {
    // A second install (an embedding host calling `main` twice) keeps the first.
    let _ignored = ctrlc::set_handler(move || {
        if let Some(code) = on_interrupt(&interrupt, &mut std::io::stderr().lock()) {
            std::process::exit(code);
        }
        let interrupt = interrupt.clone();
        std::thread::spawn(move || {
            std::thread::sleep(INTERRUPT_GRACE);
            std::process::exit(interrupt.report(&mut std::io::stderr().lock()));
        });
    });
}

/// One Ctrl-C: the first tells the jobs and returns `None` (the run stops
/// and reports it); a second reports it now and returns the exit code, 130.
pub fn on_interrupt(interrupt: &Interrupt, err: &mut dyn Write) -> Option<i32> {
    if interrupt.request() {
        Some(interrupt.report(err))
    } else {
        None
    }
}

/// Set by [`exit`]: the process ends when the run returns.
static PROCESS_ENDS: AtomicBool = AtomicBool::new(false);

/// `opentide` as the whole process: [`main`], then exit with its status.
/// The `opentide` binary calls it; a host that runs commands in its own
/// process (the Python package's `cli_main`) calls [`main`] instead.
pub fn exit(argv: &[String], version: &str) -> ! {
    PROCESS_ENDS.store(true, Ordering::Relaxed);
    std::process::exit(main(argv, version))
}

/// Frees `value`, unless the process ends when this run returns ([`exit`]):
/// freeing a large document tree (a workspace's index, `info catalog`'s
/// document) takes longer than building it, and the exit reclaims it at no
/// cost. In any other process it is dropped here, so nothing leaks.
pub(crate) fn release<T>(value: T) {
    release_when(value, PROCESS_ENDS.load(Ordering::Relaxed));
}

fn release_when<T>(value: T, process_ends: bool) {
    if process_ends {
        std::mem::forget(value);
    } else {
        drop(value);
    }
}

/// `opentide` in this process: the process's environment and streams.
pub fn main(argv: &[String], version: &str) -> i32 {
    use std::io::IsTerminal;
    install_panic_hook();
    let interrupt = Interrupt::default();
    install_interrupt_handler(interrupt.clone());
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
        interrupt,
    };
    let mut out = std::io::stdout().lock();
    let mut err = std::io::stderr();
    run(argv, &env, &host, &mut out, &mut err)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Counts its drops, to tell a freed value from a leaked one.
    struct Counted(std::rc::Rc<std::cell::Cell<u32>>);
    impl Drop for Counted {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }

    #[test]
    fn release_frees_unless_the_process_ends() {
        let drops = std::rc::Rc::new(std::cell::Cell::new(0));
        release_when(Counted(drops.clone()), false);
        assert_eq!(
            drops.get(),
            1,
            "a run inside a host process frees what it built"
        );
        release_when(Counted(drops.clone()), true);
        assert_eq!(drops.get(), 1, "the binary leaves it to the exit");
    }

    #[test]
    fn a_run_in_process_frees_what_it_releases() {
        // Only `exit` (the binary) sets the switch: `main` and `run`, which
        // the Python package calls in its own process, never leak.
        assert!(!PROCESS_ENDS.load(Ordering::Relaxed));
        let drops = std::rc::Rc::new(std::cell::Cell::new(0));
        release(Counted(drops.clone()));
        assert_eq!(drops.get(), 1);
    }

    #[test]
    fn framework_utc_dates() {
        let at = |secs: u64, micros: u64| {
            utc_at(
                std::time::UNIX_EPOCH + Duration::from_secs(secs) + Duration::from_micros(micros),
            )
        };
        assert_eq!(
            at(0, 0),
            (
                "1970-01-01T00:00:00Z".into(),
                "19700101T000000000000Z".into(),
                "00:00:00".into()
            )
        );
        assert_eq!(
            at(1_794_219_072, 123_456),
            (
                "2026-11-09T10:11:12Z".into(),
                "20261109T101112123456Z".into(),
                "10:11:12".into()
            )
        );
        assert_eq!(at(951_782_400, 0).0, "2000-02-29T00:00:00Z");
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

    #[derive(Clone, Default)]
    struct Buffer(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl Write for Buffer {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    struct Ran {
        code: i32,
        stdout: String,
        stderr: String,
    }

    fn host(tty: bool, sink: &Buffer) -> Host {
        Host {
            version: "9.9.9".into(),
            stdout_tty: tty,
            stderr_tty: tty,
            log_sink: std::sync::Arc::new(std::sync::Mutex::new(sink.clone())),
            cwd: None,
            width: None,
            interrupt: Interrupt::default(),
        }
    }

    fn ran(
        line: &str,
        pairs: &[(&str, &str)],
        tty: bool,
        command: impl FnOnce(&Run<'_>, &mut dyn Write, &mut dyn Write) -> CommandResult,
    ) -> Ran {
        let argv: Vec<String> = line.split_whitespace().map(str::to_owned).collect();
        let env = Env::from_pairs(pairs.iter().copied());
        let err = Buffer::default();
        let mut out = Vec::new();
        let code = run_with(
            &argv,
            &env,
            &host(tty, &err),
            &mut out,
            &mut err.clone(),
            command,
        );
        let stderr = String::from_utf8(err.0.lock().unwrap().clone()).unwrap();
        Ran {
            code,
            stdout: String::from_utf8(out).unwrap(),
            stderr,
        }
    }

    fn dispatched(line: &str, pairs: &[(&str, &str)], tty: bool) -> Ran {
        ran(
            line,
            pairs,
            tty,
            |run, out, err| Ok(run.dispatch(out, err)?),
        )
    }

    /// `line` dispatched at a terminal of `width` columns.
    fn dispatched_at(line: &str, pairs: &[(&str, &str)], width: usize) -> Ran {
        let argv: Vec<String> = line.split_whitespace().map(str::to_owned).collect();
        let env = Env::from_pairs(pairs.iter().copied());
        let err = Buffer::default();
        let mut out = Vec::new();
        let mut host = host(true, &err);
        host.width = Some(width);
        let code = run_with(
            &argv,
            &env,
            &host,
            &mut out,
            &mut err.clone(),
            |run, out, err| Ok(run.dispatch(out, err)?),
        );
        let stderr = String::from_utf8(err.0.lock().unwrap().clone()).unwrap();
        Ran {
            code,
            stdout: String::from_utf8(out).unwrap(),
            stderr,
        }
    }

    #[test]
    fn framework_usage_error_at_a_narrow_terminal_is_the_outcome_renderer() {
        let word = "--an-option-whose-name-is-wider-than-the-terminal";
        let line = format!("validate {word}");
        for (mode, colour) in [("plain", Colour::Mono), ("human", Colour::Full)] {
            let result = dispatched_at(&line, &[("OPENTIDE_OUTPUT", mode)], 30);
            assert_eq!(result.code, USAGE_EXIT_CODE, "{mode}");
            // A word is never split: the option stays whole on its row.
            assert!(result.stderr.contains(word), "{mode}: {}", result.stderr);
            let message = format!("No such option: {word}");
            let console = Console {
                colour,
                width: Some(30),
            };
            let notes = [
                (
                    "usage".to_owned(),
                    "opentide validate [OPTIONS] COMMAND [ARGS]...".to_owned(),
                ),
                (
                    "help".to_owned(),
                    "run 'opentide validate --help'".to_owned(),
                ),
            ];
            assert_eq!(
                result.stderr,
                console.error(&message, &notes, Mode::Plain, false),
                "{mode}"
            );
        }
        // The agent tip, as the outcome renderer writes it.
        let result = dispatched_at(&line, &[("AI_AGENT", "a")], 30);
        assert!(
            result
                .stderr
                .ends_with("tip: add --json for machine-readable output\n"),
            "{}",
            result.stderr
        );
    }

    const MODES: &[(&str, &[(&str, &str)])] = &[
        ("x", &[("OPENTIDE_OUTPUT", "human")]),
        ("x", &[]),
        ("--json x", &[]),
        ("x", &[("AI_AGENT", "a")]),
        ("mcp start", &[]),
    ];

    #[test]
    fn framework_logging_never_writes_stdout_and_follows_the_mode() {
        for (line, pairs) in MODES {
            for debug in [false, true] {
                let line = if debug {
                    format!("--debug {line}")
                } else {
                    (*line).to_owned()
                };
                let result = ran(&line, pairs, true, |_, _, _| {
                    tracing::debug!(path = "x", "registry_loaded");
                    tracing::warn!("tenant_targets_failed");
                    Ok(0)
                });
                assert_eq!(result.stdout, "", "{line}");
                // `--json` writes its log lines as JSON, as the oracle does.
                let (warned, loaded) = if line.contains("--json") {
                    (
                        "\"event\":\"tenant_targets_failed\",\"level\":\"warning\"",
                        "{\"path\":\"x\",\"event\":\"registry_loaded\",\"level\":\"debug\"",
                    )
                } else {
                    (
                        "warning: Tenant targets failed",
                        "Registry loaded · path: x",
                    )
                };
                assert!(result.stderr.contains(warned), "{line}: {}", result.stderr);
                assert_eq!(result.stderr.contains(loaded), debug, "{line}");
            }
        }
        let quiet = ran("--quiet x", &[], false, |_, _, _| {
            tracing::warn!("hidden");
            tracing::error!("shown");
            Ok(0)
        });
        assert_eq!(quiet.stderr, "error: Shown\n");
        // OPENTIDE_DEBUG and a boolean DEBUG turn debug on; DEBUG='*' does not.
        for (pairs, shown) in [
            (&[("OPENTIDE_DEBUG", "1")][..], true),
            (&[("DEBUG", "true")][..], true),
            (&[("DEBUG", "*")][..], false),
        ] {
            let result = ran("x", pairs, false, |_, _, _| {
                tracing::debug!("seen");
                Ok(0)
            });
            assert_eq!(result.stderr.contains("debug: Seen"), shown, "{pairs:?}");
        }
    }

    #[test]
    fn framework_crash_from_a_panic_and_from_an_error_report_the_same() {
        let state =
            std::env::temp_dir().join(format!("opentide-cli-app-crash-{}", std::process::id()));
        let state_text = state.display().to_string();
        // The state directory on every platform: XDG on Linux, under HOME on
        // macOS, LOCALAPPDATA on Windows.
        let pairs = [
            ("XDG_STATE_HOME", state_text.as_str()),
            ("HOME", state_text.as_str()),
            ("USERPROFILE", state_text.as_str()),
            ("LOCALAPPDATA", state_text.as_str()),
            ("API_TOKEN", "s3cr3t-value"),
        ];
        let panicked = ran(
            "--json validate --token s3cr3t-value",
            &pairs,
            false,
            |_, _, _| panic!("boom with s3cr3t-value inside"),
        );
        assert_eq!(panicked.code, 1);
        let stderr_first = panicked.stderr.lines().next().unwrap();
        assert_eq!(stderr_first, "error[internal]: panic: boom with *** inside");
        assert!(
            panicked
                .stderr
                .contains("  note: crash log, with credentials and tenant names redacted: ")
        );
        assert!(panicked.stderr.contains("  help: this is a bug in opentide; report it: https://github.com/opentidehq/opentide/issues/new?title=Crash+in+opentide+validate&body="));
        assert!(
            panicked
                .stderr
                .ends_with("  help: add --debug to see the traceback\n")
        );
        let document = crate::json::Json::parse(&panicked.stdout).unwrap();
        assert_eq!(
            document.get("command"),
            Some(&crate::json::Json::str("validate"))
        );
        let failure = document.get("failure").unwrap();
        assert_eq!(
            failure.get("code"),
            Some(&crate::json::Json::str("internal"))
        );
        let crate::json::Json::Str(log) = failure.get("crash_log").unwrap() else {
            panic!("no crash log")
        };
        let text = std::fs::read_to_string(log).unwrap();
        assert!(text.starts_with("opentide crash log\n\ntime: "));
        assert!(
            text.contains("arguments: --json validate --token '***'")
                || text.contains("arguments: --json validate --token ***")
        );
        assert!(!text.contains("s3cr3t-value"), "{text}");
        assert!(text.contains("output mode: json"));

        let failed = ran("--json validate", &pairs, false, |_, _, _| {
            Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "gone",
            )))
        });
        assert_eq!(failed.code, 1);
        assert_eq!(
            failed.stderr.lines().next().unwrap(),
            "error[internal]: Error: gone"
        );
        assert!(failed.stdout.contains("\"code\":\"internal\""));

        // --debug prints the trace first; mcp mode never writes stdout; no
        // home means no log, said so.
        let debug = ran(
            "--debug mcp start",
            &[("XDG_STATE_HOME", "relative")],
            false,
            |_, _, _| Err("plain".into()),
        );
        assert_eq!(debug.stdout, "");
        assert!(
            debug.stderr.starts_with("Error: plain\n"),
            "{}",
            debug.stderr
        );
        assert!(
            debug
                .stderr
                .contains("  note: no crash log written: no home directory to keep crash logs in")
        );
        assert!(!debug.stderr.contains("add --debug"));
        // A person at a terminal clicks a short link.
        let human = ran(
            "x",
            &[("OPENTIDE_OUTPUT", "human"), ("HOME", "/nonexistent/x")],
            true,
            |_, _, _| Err("e".into()),
        );
        assert!(
            human
                .stderr
                .contains("\u{1b}]8;;https://github.com/opentidehq/opentide/issues/new?")
        );
        let _ = std::fs::remove_dir_all(&state);
    }

    #[test]
    fn framework_interrupt_first_tells_the_jobs_second_exits_130() {
        let interrupt = Interrupt::default();
        let mut err = Vec::new();
        // The first Ctrl-C only tells the jobs: the run reports it.
        assert_eq!(on_interrupt(&interrupt, &mut err), None);
        assert!(interrupt.requested());
        assert!(err.is_empty());
        // The second ends the process now, with the one line.
        assert_eq!(on_interrupt(&interrupt, &mut err), Some(130));
        assert_eq!(err, b"error: interrupted\n");
        // Reported once, whoever reports it first.
        assert_eq!(interrupt.report(&mut err), 130);
        assert_eq!(err, b"error: interrupted\n");
    }

    #[test]
    fn framework_interrupt_lets_a_polling_job_clean_up_and_prints_no_document() {
        for line in ["--json commands", "commands", "mcp start"] {
            let cleaned = std::cell::Cell::new(false);
            let result = ran(line, &[], false, |run, out, err| {
                // Ctrl-C while the job runs: it polls, stops and cleans up.
                assert_eq!(on_interrupt(&run.host.interrupt, &mut Vec::new()), None);
                for _ in 0..3 {
                    if run.interrupted() {
                        cleaned.set(true);
                        break;
                    }
                }
                Ok(run.dispatch(out, err)?)
            });
            assert!(cleaned.get(), "{line}");
            assert_eq!(result.code, 130, "{line}");
            assert_eq!(result.stdout, "", "{line}");
            assert_eq!(result.stderr, "error: interrupted\n", "{line}");
        }
        // A job that fails on its way out is still an interrupt, not a crash.
        let failed = ran("--json validate", &[], false, |run, _, _| {
            run.host.interrupt.request();
            Err("cancelled".into())
        });
        assert_eq!(
            (failed.code, failed.stdout.as_str(), failed.stderr.as_str()),
            (130, "", "error: interrupted\n")
        );
    }

    /// A stream whose every write fails with `kind`.
    struct Failing(std::io::ErrorKind);

    impl Write for Failing {
        fn write(&mut self, _bytes: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::from(self.0))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Err(std::io::Error::from(self.0))
        }
    }

    fn into_failing(line: &str, kind: std::io::ErrorKind) -> (i32, String) {
        let argv: Vec<String> = line.split_whitespace().map(str::to_owned).collect();
        let sink = Buffer::default();
        let state = std::env::temp_dir().join(format!(
            "opentide-cli-write-{}-{}",
            std::process::id(),
            line.len()
        ));
        let state_text = state.display().to_string();
        let env = Env::from_pairs([
            ("XDG_STATE_HOME", state_text.as_str()),
            ("HOME", state_text.as_str()),
            ("USERPROFILE", state_text.as_str()),
            ("LOCALAPPDATA", state_text.as_str()),
        ]);
        let code = run(
            &argv,
            &env,
            &host(false, &sink),
            &mut Failing(kind),
            &mut sink.clone(),
        );
        let _ = std::fs::remove_dir_all(&state);
        let stderr = String::from_utf8(sink.0.lock().unwrap().clone()).unwrap();
        (code, stderr)
    }

    #[test]
    fn framework_a_lost_document_is_a_failure_not_success() {
        // `opentide --json commands > /dev/full`: the document is lost, so
        // the run fails as an internal error (exit 1), as the CLI always has.
        for line in [
            "--json commands",
            "commands",
            "--version",
            "--json validate",
        ] {
            let (code, stderr) = into_failing(line, std::io::ErrorKind::StorageFull);
            assert_eq!(code, 1, "{line}");
            assert!(stderr.starts_with("error[internal]: "), "{line}: {stderr}");
        }
        // Help on a full disk too.
        let (code, _) = into_failing("validate --help", std::io::ErrorKind::StorageFull);
        assert_eq!(code, 1);
        // The reader went away: exit 1, quietly.
        let (code, stderr) = into_failing("--json commands", std::io::ErrorKind::BrokenPipe);
        assert_eq!((code, stderr.as_str()), (1, ""));
    }

    /// A refusal is recorded in the file `OPENTIDE_ENGINE_REFUSAL` names, in
    /// every mode, for `compare` to run Python alone; nothing else is.
    #[test]
    fn a_refusal_is_recorded_where_the_dispatcher_asks() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("refusal");
        let path = file.to_string_lossy().into_owned();
        for line in ["--json share push", "share push"] {
            let refused = dispatched(line, &[(REFUSAL_ENV, &path)], false);
            assert_eq!(refused.code, 2, "{line}");
            let recorded = std::fs::read_to_string(&file).unwrap();
            assert!(
                recorded.starts_with("opentide share push has no Rust implementation yet"),
                "{line}: {recorded}"
            );
            std::fs::remove_file(&file).unwrap();
        }
        // doctor runs here with --offline only: without it, the network
        // checks are Python's, and compare runs Python alone on the refusal.
        for line in ["--json doctor", "doctor"] {
            let refused = dispatched(line, &[(REFUSAL_ENV, &path)], false);
            assert_eq!(refused.code, 2, "{line}");
            let recorded = std::fs::read_to_string(&file).unwrap();
            assert!(
                recorded.starts_with(
                    "opentide doctor without --offline has no Rust implementation yet"
                ),
                "{line}: {recorded}"
            );
            std::fs::remove_file(&file).unwrap();
        }
        let ran = dispatched("--json commands", &[(REFUSAL_ENV, &path)], false);
        assert_eq!(ran.code, 0);
        assert!(!file.exists());
        // Without the variable, nothing is written.
        assert_eq!(dispatched("share push", &[], false).code, 2);
        assert_eq!(dispatched("doctor", &[], false).code, 2);
        assert!(!file.exists());
    }

    #[test]
    fn framework_root_version_help_and_refusals() {
        let version = dispatched("--version", &[], false);
        assert_eq!(
            (version.code, version.stdout.as_str()),
            (0, "opentide 9.9.9\n")
        );
        assert_eq!(
            dispatched("-V commands", &[], false).stdout,
            "opentide 9.9.9\n"
        );
        let bare = dispatched("", &[], false);
        assert_eq!(bare.code, 0);
        assert!(bare.stdout.contains("Usage: opentide"), "{}", bare.stdout);
        let help = dispatched("validate query --help", &[], true);
        assert_eq!(help.code, 0);
        assert!(
            help.stdout.contains("opentide validate query"),
            "{}",
            help.stdout
        );
        let refused = dispatched("--json share push", &[], false);
        assert_eq!(refused.code, 2);
        assert!(refused.stdout.contains("\"code\":\"engine_not_ported\""));
        assert!(refused.stdout.contains("\"argument\":\"OPENTIDE_ENGINE\""));
        let plain = dispatched("share push", &[], false);
        assert_eq!(
            plain.stderr,
            "error: opentide share push has no Rust implementation yet: unset OPENTIDE_ENGINE, or set it to python or compare.\n"
        );
        let file =
            std::env::temp_dir().join(format!("opentide-cli-not-a-dir-{}", std::process::id()));
        std::fs::write(&file, "x").unwrap();
        let line = format!("--repo {} validate", file.display());
        let not_dir = dispatched(&line, &[], false);
        assert!(
            not_dir.stderr.starts_with("error: --repo "),
            "{}",
            not_dir.stderr
        );
        assert!(not_dir.stderr.contains(" is not a directory\n"));
        // `setup` creates the repository: a missing --repo is no error there.
        assert!(
            !dispatched("--repo nowhere-at-all setup", &[], false)
                .stderr
                .contains("does not exist")
        );
        std::fs::remove_file(&file).unwrap();
    }

    #[test]
    fn framework_json_indentation_and_one_trailing_newline() {
        let compact = dispatched("--json commands", &[], false);
        assert!(compact.stdout.starts_with("{\"program\""));
        let indented = dispatched("--json commands", &[], true);
        assert!(indented.stdout.starts_with("{\n  \"program\""));
        let forced = dispatched("--json commands", &[("OPENTIDE_JSON_INDENT", "0")], true);
        assert!(forced.stdout.starts_with("{\"program\""));
        for result in [compact, indented, forced] {
            assert!(result.stdout.ends_with("}\n") && !result.stdout.ends_with("\n\n"));
        }
    }

    #[test]
    fn framework_redaction_fuzzed_secrets_never_reach_output_logs_or_crash_logs() {
        let root =
            std::env::temp_dir().join(format!("opentide-cli-redact-fuzz-{}", std::process::id()));
        let mut state: u64 = 0xD1B5_4A32_D192_ED03;
        let mut next = move || {
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            state.wrapping_mul(0x2545_F491_4F6C_DD1D)
        };
        // Quotes, backslashes and non-ASCII too: a secret must be redacted
        // as written, before JSON or Debug escapes it.
        let alphabet: Vec<char> =
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.~!$%^*+\"\\éü日"
                .chars()
                .collect();
        for round in 0..60 {
            let (secret_length, password_length) = (next() % 24, next() % 16);
            let mut word = |length: u64| -> String {
                (0..8 + length)
                    .map(|_| alphabet[usize::try_from(next()).unwrap() % alphabet.len()])
                    .collect()
            };
            let secret = format!("S{}", word(secret_length));
            let password = format!("P{}", word(password_length)).replace(['@', '/', '?', '#'], "x");
            let tenant = format!("tenant-{}", word(4)).replace(['"', '\\', 'é', 'ü', '日'], "t");
            let host = format!(
                "{}.example",
                word(3).to_lowercase().replace(
                    [
                        '.', '~', '!', '$', '%', '^', '*', '+', '_', '"', '\\', 'é', 'ü', '日'
                    ],
                    "a",
                )
            );
            let workspace = root.join(round.to_string());
            let platforms = workspace.join(".opentide/configurations/platforms");
            std::fs::create_dir_all(&platforms).unwrap();
            std::fs::write(
                platforms.join("splunk.toml"),
                format!("[[tenants]]\nname = \"{tenant}\"\nurl = \"https://{host}:8089\"\ntoken = \"$SPLUNK_TOKEN\"\n"),
            )
            .unwrap();
            let state_home = workspace.join("state").display().to_string();
            let repo = workspace.display().to_string();
            let proxy = format!("http://user:{password}@proxy.local:3128");
            // Every other round logs JSON lines (OPENTIDE_LOG_JSON=1).
            let log_json = if round % 2 == 0 { "1" } else { "0" };
            let pairs = [
                ("OPENTIDE_LOG_JSON", log_json),
                ("SPLUNK_TOKEN", secret.as_str()),
                ("HTTPS_PROXY", proxy.as_str()),
                ("XDG_STATE_HOME", state_home.as_str()),
                ("HOME", state_home.as_str()),
                ("USERPROFILE", state_home.as_str()),
                ("LOCALAPPDATA", state_home.as_str()),
            ];
            let line = format!("--debug --json --repo {repo} validate --api-key {secret}");
            let leak = format!(
                "token={secret} proxy {proxy} on {tenant} at {host} Authorization: Bearer {secret}"
            );
            let result = ran(&line, &pairs, false, |_, _, _| {
                tracing::warn!(detail = leak.as_str(), "request_failed");
                tracing::warn!(detail = ?leak, "debug_field");
                // Alone, with no key or scheme a pattern would catch.
                tracing::warn!(detail = secret.as_str(), "secret_alone");
                tracing::warn!(detail = ?secret, "secret_debug");
                tracing::debug!("{}", leak);
                panic!("{leak}")
            });
            let crate::json::Json::Str(log) = crate::json::Json::parse(&result.stdout)
                .unwrap()
                .get("failure")
                .and_then(|failure| failure.get("crash_log"))
                .cloned()
                .unwrap()
            else {
                panic!("no crash log")
            };
            let crash_log = std::fs::read_to_string(log).unwrap();
            for (name, text) in [
                ("stdout", &result.stdout),
                ("stderr", &result.stderr),
                ("crash log", &crash_log),
            ] {
                for value in [&secret, &password, &tenant, &host] {
                    // As written, and as JSON or `{:?}` escapes it.
                    let escaped = value.escape_debug().to_string();
                    assert!(
                        !text.contains(value.as_str()) && !text.contains(escaped.as_str()),
                        "round {round}: {value} in the {name}:\n{text}"
                    );
                }
            }
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn framework_repeated_flags_run_as_once_and_the_last_value_wins() {
        let once = dispatched("--json commands", &[], false);
        assert_eq!(once.code, 0);
        for line in [
            "--json commands --json",
            "commands --json --json",
            "--debug --debug --json commands",
            "--quiet --json commands --quiet",
        ] {
            let twice = dispatched(line, &[], false);
            assert_eq!(twice.code, 0, "{line}: {}", twice.stdout);
            assert_eq!(
                normalised(&twice.stdout),
                normalised(&once.stdout),
                "{line}"
            );
        }
        let plain = dispatched("--quiet commands --quiet", &[], false);
        assert_eq!(plain.code, 0);
        assert!(plain.stdout.contains("commands"), "{}", plain.stdout);
        // Parsed, then refused as not ported: no usage error.
        let strict = dispatched("--json share push --dry-run --dry-run", &[], false);
        assert!(
            strict.stdout.contains("\"code\":\"engine_not_ported\""),
            "{}",
            strict.stdout
        );
        // `--repo` twice: the last one is the repository.
        let dir = std::env::temp_dir().display().to_string();
        let last = dispatched(
            &format!("--repo /nowhere-at-all --repo {dir} --json commands"),
            &[],
            false,
        );
        assert_eq!(last.code, 0, "{}", last.stdout);
        let first = dispatched(
            &format!("--repo {dir} --repo /nowhere-at-all --json commands"),
            &[],
            false,
        );
        assert_eq!(first.code, 2);
        assert!(
            first
                .stdout
                .contains("--repo /nowhere-at-all does not exist")
        );
        let root = catalog::root();
        assert_eq!(
            globals_of(
                &root,
                "--repo a --repo=b --proxy p --proxy q x",
                &Env::default()
            ),
            Globals {
                repo: Some("b".into()),
                proxy: Some("q".into()),
                ..Globals::default()
            }
        );
    }

    fn normalised(stdout: &str) -> String {
        regex::Regex::new(r#""duration_ms":\d+"#)
            .unwrap()
            .replace_all(stdout, "")
            .into_owned()
    }

    #[test]
    fn framework_a_separator_before_a_command_name_runs_it() {
        let run = dispatched("--json -- commands", &[], false);
        assert_eq!(run.code, 0, "{}", run.stdout);
        assert!(run.stdout.starts_with("{\"program\""));
        let plain = dispatched("-- commands", &[], false);
        assert_eq!((plain.code, plain.stderr.as_str()), (0, ""));
        // `validate query` runs on this CLI (UC-3.5b): the separator is dropped
        // and the subcommand runs, not a usage error.
        let nested = dispatched("--json validate -- query", &[], false);
        assert!(
            nested.stdout.contains("\"command\":\"validate query\""),
            "{}",
            nested.stdout
        );
        assert!(
            !nested.stdout.contains("\"code\":\"usage_"),
            "{}",
            nested.stdout
        );
        // An unported subcommand after a separator is refused by its path.
        let unported = dispatched("--json share -- status", &[], false);
        assert!(
            unported.stdout.contains("\"command\":\"share status\""),
            "{}",
            unported.stdout
        );
        assert!(unported.stdout.contains("engine_not_ported"));
        // `validate -- --json`: an unknown option of validate, not a command.
        let option = dispatched("--json validate -- --json", &[], false);
        assert_eq!(option.code, 2);
        assert!(
            option.stdout.contains("\"command\":\"validate\""),
            "{}",
            option.stdout
        );
        assert!(option.stdout.contains("\"code\":\"usage_unknown_option\""));
        assert!(
            option
                .stdout
                .contains("\"message\":\"No such option: --json\"")
        );
    }

    #[test]
    fn framework_a_bare_help_group_prints_its_help_to_a_person() {
        for (line, pairs, tty) in [
            ("mcp", &[][..], false),
            ("lsp", &[("OPENTIDE_OUTPUT", "human")][..], true),
        ] {
            let bare = dispatched(line, pairs, tty);
            assert_eq!(bare.code, 2, "{line}");
            assert_eq!(bare.stderr, "", "{line}");
            assert!(
                bare.stdout.contains(&format!("opentide {line}")),
                "{line}: {}",
                bare.stdout
            );
            assert!(bare.stdout.contains("start"), "{line}");
        }
        let new = dispatched("--json new", &[], false);
        assert!(
            new.stdout
                .contains("\"error\":\"Missing command: choose from threat, objective, rule.\"")
        );
        let agent = dispatched("mcp", &[("AI_AGENT", "a")], false);
        assert!(agent.stdout.is_empty());
        assert!(
            agent
                .stderr
                .starts_with("error: Missing command: choose from start.\n")
        );
    }

    fn write_platform(workspace: &std::path::Path, tenant: &str) {
        let platforms = workspace.join(".opentide/configurations/platforms");
        std::fs::create_dir_all(&platforms).unwrap();
        std::fs::write(
            platforms.join("splunk.toml"),
            format!("[[tenants]]\nname = \"{tenant}\"\nurl = \"https://splunk.example:8089\"\n"),
        )
        .unwrap();
    }

    #[test]
    fn framework_redaction_is_wired_to_every_source() {
        // The --proxy password, from the command line only.
        let proxy = ran(
            "--proxy http://user:pr0xy-pass@proxy.local:3128 x",
            &[],
            false,
            |_, _, _| {
                tracing::warn!(detail = "auth pr0xy-pass failed", "proxy_failed");
                Ok(0)
            },
        );
        assert!(
            proxy.stderr.contains("warning: Proxy failed"),
            "{}",
            proxy.stderr
        );
        assert!(!proxy.stderr.contains("pr0xy-pass"), "{}", proxy.stderr);
        // The tenants of OPENTIDE_REPO_ROOT's workspace.
        let workspace =
            std::env::temp_dir().join(format!("opentide-cli-repo-root-{}", std::process::id()));
        write_platform(&workspace, "tenant-acme-prod");
        let repo_root = workspace.display().to_string();
        let tenant = ran(
            "x",
            &[("OPENTIDE_REPO_ROOT", repo_root.as_str())],
            false,
            |_, _, _| {
                tracing::warn!(tenant = "tenant-acme-prod", "deploy_failed");
                Ok(0)
            },
        );
        assert!(tenant.stderr.contains("tenant: ***"), "{}", tenant.stderr);
        assert!(!tenant.stderr.contains("acme"), "{}", tenant.stderr);
        let _ = std::fs::remove_dir_all(&workspace);
    }

    #[test]
    fn framework_log_json_is_wired_and_redacted_before_escaping() {
        let secret = "s3cr\"et\\v4lué日";
        let pairs = [("OPENTIDE_LOG_JSON", "1"), ("API_TOKEN", secret)];
        let result = ran("x", &pairs, false, |_, _, _| {
            tracing::warn!(detail = secret, "request_failed");
            tracing::warn!(detail = ?secret, "debug_field");
            tracing::warn!("{}", secret);
            Ok(0)
        });
        let lines: Vec<&str> = result.stderr.lines().collect();
        assert_eq!(lines.len(), 3, "{}", result.stderr);
        for line in &lines {
            let document = crate::json::Json::parse(line).unwrap();
            assert!(document.get("event").is_some(), "{line}");
            assert!(!line.contains("s3cr"), "{line}");
            assert!(line.contains("***"), "{line}");
        }
        // Without OPENTIDE_LOG_JSON, the readable line, redacted the same.
        let text = ran("x", &[("API_TOKEN", secret)], false, |_, _, _| {
            tracing::warn!(detail = ?secret, "debug_field");
            Ok(0)
        });
        assert_eq!(text.stderr, "warning: Debug field · detail: \"***\"\n");
    }

    #[test]
    fn framework_a_failing_tenant_request_leaves_no_credential_in_logs_or_crash_logs() {
        // A tenant request that fails (refused), with credentials in the
        // URL's user info and query: the connector's error, logged at every
        // level and ending the run, reaches neither the output, the log nor
        // the crash log. The values are in no variable, so the run's own
        // redaction cannot be what hides them.
        let state = std::env::temp_dir().join(format!(
            "opentide-cli-tenant-failure-{}",
            std::process::id()
        ));
        let state_text = state.display().to_string();
        let pairs = [
            ("XDG_STATE_HOME", state_text.as_str()),
            ("HOME", state_text.as_str()),
            ("USERPROFILE", state_text.as_str()),
            ("LOCALAPPDATA", state_text.as_str()),
        ];
        let (secret, password) = ("q7Zk-tenant-credential-41", "pw-x9Lm3-proxy");
        let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = closed.local_addr().unwrap().port();
        drop(closed);
        let url = format!("http://user:{password}@127.0.0.1:{port}/api?token={secret}");
        for line in ["--debug --json x", "--debug x"] {
            let result = ran(line, &pairs, false, |_, _, _| {
                let label = opentide_connectors::TenantLabel::new("splunk", "prod");
                let client = opentide_connectors::HttpClient::new(
                    &label,
                    &opentide_connectors::HttpSettings::default(),
                    &opentide_connectors::Environment::default(),
                    None,
                )?;
                let error = opentide_connectors::runtime::block_on(async {
                    let request = client.request(reqwest::Method::GET, &url).build()?;
                    let cancel = tokio_util::sync::CancellationToken::new();
                    Ok::<_, reqwest::Error>(client.send(request, &cancel).await)
                })??
                .unwrap_err();
                tracing::error!(detail = %error, "tenant_request_failed");
                tracing::debug!(error = ?error, "tenant_request_debug");
                Err(error.into())
            });
            let mut texts = vec![
                ("stdout", result.stdout.clone()),
                ("stderr", result.stderr.clone()),
            ];
            if let Some(crate::json::Json::Str(log)) = crate::json::Json::parse(&result.stdout)
                .ok()
                .and_then(|document| document.get("failure").cloned())
                .and_then(|failure| failure.get("crash_log").cloned())
            {
                texts.push(("crash log", std::fs::read_to_string(log).unwrap()));
            }
            let all: String = texts.iter().map(|(_, text)| text.as_str()).collect();
            // The failure was reported, by its origin.
            assert!(
                all.contains(&format!("http://127.0.0.1:{port}")),
                "{line}: {all}"
            );
            for (name, text) in &texts {
                for value in [secret, password] {
                    assert!(
                        !text.contains(value),
                        "{line}: {value} in the {name}:\n{text}"
                    );
                }
            }
        }
        let _ = std::fs::remove_dir_all(&state);
    }

    #[test]
    fn framework_crash_log_masks_short_secret_named_variables() {
        let state =
            std::env::temp_dir().join(format!("opentide-cli-short-secret-{}", std::process::id()));
        let state_text = state.display().to_string();
        let pairs = [
            ("XDG_STATE_HOME", state_text.as_str()),
            ("HOME", state_text.as_str()),
            ("USERPROFILE", state_text.as_str()),
            ("LOCALAPPDATA", state_text.as_str()),
            // Too short to be redacted as text, but its name says secret.
            ("OPENTIDE_API_TOKEN", "abc"),
            ("OPENTIDE_LINKS", "none"),
        ];
        let crashed = ran("--json x", &pairs, false, |_, _, _| Err("boom".into()));
        let document = crate::json::Json::parse(&crashed.stdout).unwrap();
        let crate::json::Json::Str(log) = document
            .get("failure")
            .and_then(|failure| failure.get("crash_log"))
            .unwrap()
        else {
            panic!("no crash log")
        };
        let text = std::fs::read_to_string(log).unwrap();
        assert!(text.contains("  OPENTIDE_API_TOKEN=***\n"), "{text}");
        assert!(text.contains("  OPENTIDE_LINKS=none\n"), "{text}");
        let _ = std::fs::remove_dir_all(&state);
    }

    #[test]
    fn framework_mcp_mode_never_writes_stdout_and_error_comes_first() {
        let success = ran("mcp start", &[], false, |run, out, err| {
            let outcome = Outcome {
                command: "mcp start".into(),
                status: "completed".into(),
                message: "done".into(),
                data: Vec::new(),
                exit_code: 0,
                summary: Vec::new(),
                next_actions: Vec::new(),
                failure: None,
            };
            Ok(run.emit(&outcome, &[], &["a line".into()], out, err)?)
        });
        assert_eq!((success.code, success.stdout.as_str()), (0, ""));
        let failed = dispatched("--json deploy", &[], false);
        assert!(
            failed.stdout.starts_with("{\"error\":"),
            "{}",
            failed.stdout
        );
    }

    #[test]
    fn framework_small_behaviours() {
        // TERM=DUMB in any case: no SGR, even in human mode on a terminal.
        let dumb = dispatched(
            "deploy",
            &[("OPENTIDE_OUTPUT", "human"), ("TERM", "DUMB")],
            true,
        );
        assert!(!dumb.stderr.contains('\u{1b}'), "{}", dumb.stderr);
        let coloured = dispatched(
            "deploy",
            &[("OPENTIDE_OUTPUT", "human"), ("TERM", "xterm")],
            true,
        );
        assert!(coloured.stderr.contains('\u{1b}'), "{}", coloured.stderr);
        // A bare argv in machine mode is the usage error, not help.
        let bare = dispatched("--json", &[], false);
        assert_eq!(bare.code, 2);
        assert!(bare.stdout.contains("\"error\":\"Missing command.\""));
        // `-Vh`: clap's `-h` shows the help (an intended difference: the
        // Python CLI had no `-h` and exited 2).
        let short = dispatched("-Vh", &[], false);
        assert_eq!(short.code, 0);
        assert!(short.stdout.contains("Usage: opentide"));
    }

    fn globals_of(root: &clap::Command, text: &str, env: &Env) -> Globals {
        let args: Vec<String> = text.split_whitespace().map(str::to_owned).collect();
        globals(root, &args, env)
    }

    /// `generate <phase>...`: the words after `generate` that are no
    /// subcommand are its phases. An unknown phase is a usage error; the full
    /// pipeline is refused for the Python engine; the subcommands still run
    /// as subcommands.
    #[test]
    fn generate_takes_its_phases_as_words() {
        let unknown = dispatched("--json generate schemas explrer", &[], false);
        assert_eq!(unknown.code, 2, "{}", unknown.stdout);
        assert!(
            unknown.stdout.contains(
                "Unknown generation phase explrer. Pass one or more of: schemas, snippets, templates, vocabs."
            ),
            "{}",
            unknown.stdout
        );
        assert!(unknown.stdout.contains("\"code\":\"usage_invalid_choice\""));
        assert!(unknown.stdout.contains("\"argument\":\"phase\""));
        let refused = dispatched("--json generate", &[], false);
        assert_eq!(refused.code, 2);
        assert!(refused.stdout.contains("\"code\":\"engine_not_ported\""));
        // The phases end at the first `-` word: what follows is
        // `generate`'s own options (`GeneratePhaseGroup`).
        for (argv, option) in [
            ("--json generate schemas --bogus", "--bogus"),
            ("--json generate schemas templates --repo .", "--repo"),
        ] {
            let flag = dispatched(argv, &[], false);
            assert_eq!(flag.code, 2, "{}", flag.stdout);
            assert!(
                flag.stdout.contains("\"code\":\"usage_unknown_option\""),
                "{}",
                flag.stdout
            );
            assert!(flag.stdout.contains(option), "{}", flag.stdout);
            assert!(!flag.stdout.contains("generation phase"), "{}", flag.stdout);
        }
        let help = dispatched("generate schemas --help", &[], false);
        assert_eq!(help.code, 0, "{}", help.stdout);
        assert!(
            help.stdout.contains("Usage: opentide generate"),
            "{}",
            help.stdout
        );
        let subcommand = dispatched("--json generate inflight prune --bogus", &[], false);
        assert!(
            subcommand.stdout.contains("usage_unknown_option"),
            "{}",
            subcommand.stdout
        );
    }
}
